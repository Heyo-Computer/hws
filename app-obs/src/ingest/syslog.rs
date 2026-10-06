//! A minimal syslog listener, UDP and TCP.
//!
//! This exists for senders that cannot be taught to POST JSON — an off-the-shelf
//! daemon inside a guest, or a static upstream already configured to log to a
//! network target. It is deliberately not a full RFC 5424 implementation: it
//! extracts the priority (which gives a level), finds where the message starts,
//! and treats the rest as text. Everything beyond that would be parsing effort
//! spent on fields the dashboard does not surface.
//!
//! Syslog carries no notion of a deployment. The tag / APP-NAME is used when it
//! is a usable deployment id, and otherwise records fall back to a configured
//! default rather than being discarded — an unattributed log still beats a lost
//! one when someone is debugging.

use super::Sink;
use crate::store::schema::{LogRecord, Record};
use chrono::Utc;
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};

/// Longest datagram accepted. RFC 5424 requires receivers to support 2048
/// bytes; this is generous beyond that without letting one sender allocate
/// unboundedly.
const MAX_DATAGRAM: usize = 8192;

pub struct SyslogConfig {
    pub addr: String,
    /// Used when a message's tag isn't a usable deployment id.
    pub default_deployment: String,
}

/// Serve UDP and TCP on the same address until the process ends.
pub async fn serve(config: SyslogConfig, sink: Sink) -> std::io::Result<()> {
    let udp = UdpSocket::bind(&config.addr).await?;
    let tcp = TcpListener::bind(&config.addr).await?;
    tracing::info!(addr = %config.addr, "syslog listening (udp + tcp)");

    let default_udp = config.default_deployment.clone();
    let sink_udp = sink.clone();
    let udp_task = async move {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            match udp.recv_from(&mut buf).await {
                Ok((len, peer)) => {
                    let text = String::from_utf8_lossy(&buf[..len]);
                    ingest_line(&sink_udp, &default_udp, text.trim(), Some(peer));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "syslog udp receive failed");
                }
            }
        }
    };

    let tcp_task = async move {
        loop {
            match tcp.accept().await {
                Ok((stream, peer)) => {
                    // One task per connection: a sender that opens a stream and
                    // trickles must not stall the accept loop.
                    let sink = sink.clone();
                    let default = config.default_deployment.clone();
                    tokio::spawn(async move {
                        let mut lines = BufReader::new(stream).lines();
                        // `next_line` bounds each line by the reader's buffer
                        // growth, so a sender with no newlines can't make us
                        // allocate without limit.
                        while let Ok(Some(line)) = lines.next_line().await {
                            ingest_line(&sink, &default, line.trim(), Some(peer));
                        }
                    });
                }
                Err(e) => tracing::warn!(error = %e, "syslog tcp accept failed"),
            }
        }
    };

    tokio::join!(udp_task, tcp_task);
    Ok(())
}

fn ingest_line(sink: &Sink, default_deployment: &str, line: &str, peer: Option<SocketAddr>) {
    if line.is_empty() {
        return;
    }
    let parsed = parse(line);
    let record = Record::Log(LogRecord {
        ts_millis: Utc::now().timestamp_millis(),
        deployment: parsed
            .tag
            .filter(|t| usable_deployment(t))
            .map(str::to_string)
            .unwrap_or_else(|| default_deployment.to_string()),
        backend: None,
        source: "syslog".into(),
        level: parsed.level.map(str::to_string),
        message: parsed.message.to_string(),
        fields: None,
        host: peer.map(|p| p.ip().to_string()),
        namespace: None,
    });
    sink.send(record);
}

/// Cheap pre-check mirroring the partition rules, so an unusable tag falls back
/// to the default instead of being rejected later by the writer and lost.
fn usable_deployment(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 128
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && tag.bytes().any(|b| b != b'.')
}

#[derive(Debug, PartialEq)]
struct Parsed<'a> {
    level: Option<&'a str>,
    tag: Option<&'a str>,
    message: &'a str,
}

/// Pull the priority, tag, and message text out of a syslog line.
///
/// Handles the `<PRI>` prefix common to RFC 3164 and 5424 and both of their
/// header shapes well enough to find the message. Anything unrecognised is kept
/// whole as the message rather than dropped.
fn parse(line: &str) -> Parsed<'_> {
    let (priority, rest) = split_priority(line);
    let level = priority.map(severity_to_level);

    // RFC 5424 is `<PRI>VERSION TIMESTAMP HOST APP PROCID MSGID [SD] MSG`.
    // The leading version digit is what distinguishes it from RFC 3164.
    if let Some(parsed) = parse_5424(rest, level) {
        return parsed;
    }

    // RFC 3164: `<PRI>MMM DD HH:MM:SS HOST TAG[pid]: MSG`. The tag is the token
    // before the first colon, which is the only part worth recovering.
    if let Some((head, message)) = rest.split_once(": ") {
        let tag = head
            .rsplit(' ')
            .next()
            .map(|t| t.split('[').next().unwrap_or(t))
            .filter(|t| !t.is_empty());
        return Parsed {
            level,
            tag,
            message: message.trim(),
        };
    }

    Parsed {
        level,
        tag: None,
        message: rest.trim(),
    }
}

fn split_priority(line: &str) -> (Option<u8>, &str) {
    let Some(rest) = line.strip_prefix('<') else {
        return (None, line);
    };
    let Some(end) = rest.find('>') else {
        return (None, line);
    };
    match rest[..end].parse::<u16>() {
        // PRI = facility * 8 + severity; only the low three bits are severity.
        Ok(pri) => (Some((pri % 8) as u8), &rest[end + 1..]),
        Err(_) => (None, line),
    }
}

fn parse_5424<'a>(rest: &'a str, level: Option<&'a str>) -> Option<Parsed<'a>> {
    let mut parts = rest.splitn(7, ' ');
    let version = parts.next()?;
    if version != "1" {
        return None;
    }
    let _timestamp = parts.next()?;
    let _hostname = parts.next()?;
    let app_name = parts.next()?;
    let _procid = parts.next()?;
    let _msgid = parts.next()?;
    let remainder = parts.next().unwrap_or("");

    // Structured data is either `-` or one or more `[...]` blocks; skip past it
    // to the human-readable message.
    let message = if let Some(stripped) = remainder.strip_prefix("- ") {
        stripped
    } else if remainder.starts_with('[') {
        remainder
            .rfind("] ")
            .map(|i| &remainder[i + 2..])
            .unwrap_or(remainder)
    } else {
        remainder
    };

    Some(Parsed {
        level,
        tag: (app_name != "-").then_some(app_name),
        message: message.trim(),
    })
}

/// Syslog severities collapsed onto the level vocabulary the dashboard filters
/// by. Emergency through error all read as "error" — the distinction has never
/// driven a different action in practice.
fn severity_to_level(severity: u8) -> &'static str {
    match severity {
        0..=3 => "error",
        4 => "warning",
        5 | 6 => "info",
        _ => "debug",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3164_lines_yield_tag_level_and_message() {
        // <134> = facility 16, severity 6 (info)
        let parsed = parse("<134>Jul 28 17:34:56 us2 myapp[1234]: something happened");
        assert_eq!(
            parsed,
            Parsed {
                level: Some("info"),
                tag: Some("myapp"),
                message: "something happened",
            },
        );
    }

    #[test]
    fn rfc5424_lines_yield_app_name_and_message() {
        let parsed = parse("<134>1 2026-07-28T17:34:56Z us2 myapp 1234 ID47 - something happened");
        assert_eq!(
            parsed,
            Parsed {
                level: Some("info"),
                tag: Some("myapp"),
                message: "something happened",
            },
        );
    }

    #[test]
    fn rfc5424_structured_data_is_skipped() {
        let parsed = parse(
            r#"<134>1 2026-07-28T17:34:56Z us2 myapp 1234 ID47 [ex@1 k="v"] the real message"#,
        );
        assert_eq!(parsed.message, "the real message");
        assert_eq!(parsed.tag, Some("myapp"));
    }

    #[test]
    fn severities_map_onto_the_dashboard_vocabulary() {
        // 0-3 emerg/alert/crit/err all read as error.
        assert_eq!(parse("<0>x").level, Some("error"));
        assert_eq!(parse("<11>x").level, Some("error"));
        assert_eq!(parse("<12>x").level, Some("warning"));
        assert_eq!(parse("<13>x").level, Some("info"));
        assert_eq!(parse("<14>x").level, Some("info"));
        assert_eq!(parse("<15>x").level, Some("debug"));
    }

    #[test]
    fn unparseable_lines_keep_their_text_rather_than_being_dropped() {
        // A line we can't classify is still a line somebody may need.
        let parsed = parse("just some text with no syslog framing at all");
        assert_eq!(parsed.level, None);
        assert_eq!(parsed.tag, None);
        assert_eq!(parsed.message, "just some text with no syslog framing at all");

        let malformed = parse("<notanumber>still here");
        assert_eq!(malformed.message, "<notanumber>still here");
    }

    #[test]
    fn tags_that_are_not_usable_deployment_ids_are_rejected() {
        // Falls back to the default rather than reaching the writer and being
        // dropped there.
        assert!(usable_deployment("myapp"));
        assert!(usable_deployment("vault-86a37f"));
        assert!(!usable_deployment("../escape"));
        assert!(!usable_deployment("has space"));
        assert!(!usable_deployment(""));
        assert!(!usable_deployment(".."));
    }

    #[tokio::test]
    async fn an_unusable_tag_falls_back_to_the_default_deployment() {
        let (sink, mut rx) = Sink::new(10);
        ingest_line(&sink, "syslog", "<134>Jul 28 17:34:56 us2 ../evil: hi", None);

        let Record::Log(record) = rx.recv().await.unwrap() else {
            panic!("expected a log record");
        };
        assert_eq!(record.deployment, "syslog");
        assert_eq!(record.message, "hi");
        assert_eq!(record.source, "syslog");
    }

    #[tokio::test]
    async fn the_sender_address_is_recorded_as_the_host() {
        let (sink, mut rx) = Sink::new(10);
        let peer: SocketAddr = "172.16.0.2:5140".parse().unwrap();
        ingest_line(&sink, "syslog", "<134>x myapp: hello", Some(peer));

        let Record::Log(record) = rx.recv().await.unwrap() else {
            panic!("expected a log record");
        };
        // Address without the port: the port is ephemeral, the address
        // identifies the guest.
        assert_eq!(record.host.as_deref(), Some("172.16.0.2"));
    }

    #[tokio::test]
    async fn empty_lines_are_ignored() {
        let (sink, _rx) = Sink::new(10);
        ingest_line(&sink, "syslog", "", None);
        assert_eq!(sink.accepted(), 0);
    }
}
