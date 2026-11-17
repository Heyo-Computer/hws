//! `heyctl alerts` — a namespace's alerts, through app-lb's `alerting`
//! plugin.
//!
//! Rules, receivers and checks are the plugin's install configuration
//! (`heyctl plugins install alerting -n <ns> -f alerting.json`); these
//! commands read what the rules found and acknowledge, silence and test.
//! Reads need view in the namespace; everything that changes something needs
//! admin.

use anyhow::{Result, bail};
use clap::{Args, Subcommand};

use super::Ctx;
use crate::output::{self, Table};
use crate::{AlertingRead, NewSilence};

#[derive(Args, Debug)]
pub struct AlertsArgs {
    /// Defaults to the namespace this credential is confined to.
    #[arg(long, short = 'n', value_name = "NAMESPACE", global = true)]
    pub namespace: Option<String>,
    #[command(subcommand)]
    pub cmd: AlertsCmd,
}

#[derive(Subcommand, Debug)]
pub enum AlertsCmd {
    /// Pending and firing alerts, and (with --resolved) the recently resolved.
    #[command(alias = "ls")]
    List {
        /// Also list the recently resolved.
        #[arg(long)]
        resolved: bool,
    },
    /// Acknowledge an alert: no repeat notifications until it resolves.
    Ack {
        /// The alert's fingerprint, from `heyctl alerts list`.
        fingerprint: String,
        #[arg(long, short = 'm', value_name = "TEXT")]
        comment: Option<String>,
    },
    /// Hold notifications for matching alerts. With no matcher, every alert
    /// in the namespace.
    Silence(SilenceArgs),
    /// Remove a silence.
    Unsilence {
        /// The silence's id, from `heyctl alerts silences`.
        id: String,
    },
    /// The silences in force.
    Silences,
    /// Each check and its last result.
    Checks,
    /// The last webhooks sent, newest first.
    Deliveries,
    /// Send an `alert.test` webhook to a receiver.
    TestReceiver {
        /// The receiver's id from the install configuration.
        receiver: String,
    },
}

#[derive(Args, Debug)]
pub struct SilenceArgs {
    /// Only alerts from this rule.
    #[arg(long)]
    pub rule: Option<String>,
    /// Only alerts on this deployment.
    #[arg(long)]
    pub deployment: Option<String>,
    /// Only alerts of this severity: info, warning or critical.
    #[arg(long)]
    pub severity: Option<String>,
    /// How long: 30m, 4h, 2d, … (at most 90 days).
    #[arg(long = "for", value_name = "DURATION", default_value = "1h")]
    pub duration: String,
    #[arg(long, short = 'm', value_name = "TEXT", default_value = "")]
    pub comment: String,
}

/// `30m`, `4h`, `2d`, `90s` or bare seconds.
fn parse_duration(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = num.parse().map_err(|_| anyhow::anyhow!("{s:?} is not a duration like 30m, 4h or 2d"))?;
    let mul = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => bail!("{s:?} is not a duration like 30m, 4h or 2d"),
    };
    Ok(n.saturating_mul(mul))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn opt(v: &Option<impl ToString>) -> String {
    v.as_ref().map(ToString::to_string).unwrap_or_else(|| "-".into())
}

pub fn run(ctx: &Ctx, args: &AlertsArgs) -> Result<()> {
    let ns = ctx.namespace(args.namespace.as_deref())?;
    let a = ctx.client.alerting(ns.as_str());
    let raw = |what| -> Result<bool> {
        if ctx.out.is_machine() {
            let v = ctx.client.raw().alerting(&ns, what)?;
            output::emit(&v, ctx.out, &[])?;
            return Ok(true);
        }
        Ok(false)
    };
    match &args.cmd {
        AlertsCmd::List { resolved } => {
            if raw(AlertingRead::Alerts)? {
                return Ok(());
            }
            let list = a.alerts()?;
            let mut rows: Vec<_> = list.active.iter().collect();
            if *resolved {
                rows.extend(list.resolved.iter());
            }
            if rows.is_empty() {
                println!("No alerts in namespace {ns:?}.");
                return Ok(());
            }
            let mut t = Table::new(["FINGERPRINT", "STATUS", "SEVERITY", "RULE", "DEPLOYMENT", "SINCE", "ACK", "SUMMARY"]);
            for x in rows {
                let mut status = x.status.clone();
                if x.silenced {
                    status.push_str(" (silenced)");
                }
                t.row([
                    x.fingerprint.clone(),
                    status,
                    x.severity.clone(),
                    x.rule.clone(),
                    x.deployment.clone(),
                    output::timestamp(x.started_at.unwrap_or(x.pending_since)),
                    opt(&x.acked_by),
                    x.summary.clone(),
                ]);
            }
            t.print();
        }
        AlertsCmd::Ack { fingerprint, comment } => {
            let x = a.ack(fingerprint, comment.as_deref())?;
            eprintln!("Acknowledged {} ({} on {}).", x.fingerprint, x.rule, x.deployment);
        }
        AlertsCmd::Silence(s) => {
            let secs = parse_duration(&s.duration)?;
            if secs == 0 {
                bail!("--for must be longer than zero");
            }
            let mut new = NewSilence::until(now() + secs).comment(&s.comment);
            new.rule = s.rule.clone();
            new.deployment = s.deployment.clone();
            new.severity = s.severity.clone();
            let x = a.silence(&new)?;
            eprintln!("Silence {} in force until {}.", x.id, output::timestamp(x.until));
        }
        AlertsCmd::Unsilence { id } => {
            a.unsilence(id)?;
            eprintln!("Silence {id} removed.");
        }
        AlertsCmd::Silences => {
            if raw(AlertingRead::Silences)? {
                return Ok(());
            }
            let list = a.silences()?.silences;
            if list.is_empty() {
                println!("No silences in namespace {ns:?}.");
                return Ok(());
            }
            let mut t = Table::new(["ID", "RULE", "DEPLOYMENT", "SEVERITY", "UNTIL", "BY", "COMMENT"]);
            for x in &list {
                t.row([
                    x.id.clone(),
                    opt(&x.matchers.rule),
                    opt(&x.matchers.deployment),
                    opt(&x.matchers.severity),
                    output::timestamp(x.until),
                    opt(&x.created_by),
                    x.comment.clone(),
                ]);
            }
            t.print();
        }
        AlertsCmd::Checks => {
            if raw(AlertingRead::Checks)? {
                return Ok(());
            }
            let list = a.checks()?.checks;
            if list.is_empty() {
                println!("No checks configured in namespace {ns:?}.");
                return Ok(());
            }
            let mut t = Table::new(["CHECK", "DEPLOYMENT", "PATH", "RESULT", "PASSING", "CHECKED", "ERROR"]);
            for c in &list {
                let (result, passing, checked, error) = match &c.result {
                    None => ("not run".into(), "-".into(), "-".into(), "-".into()),
                    Some(r) => (
                        if r.ok { "passing" } else { "failing" }.to_string(),
                        format!("{}/{} (need {})", r.passing, r.total, c.min_passing),
                        output::timestamp(r.checked_at),
                        opt(&r.last_error),
                    ),
                };
                t.row([c.id.clone(), c.deployment.clone(), c.path.clone(), result, passing, checked, error]);
            }
            t.print();
        }
        AlertsCmd::Deliveries => {
            if raw(AlertingRead::Deliveries)? {
                return Ok(());
            }
            let list = a.deliveries()?.deliveries;
            if list.is_empty() {
                println!("No webhooks sent in namespace {ns:?}.");
                return Ok(());
            }
            let mut t = Table::new(["ID", "WHEN", "EVENT", "RECEIVER", "STATUS", "ATTEMPTS", "HTTP", "ERROR"]);
            for d in &list {
                t.row([
                    d.delivery_id.clone(),
                    output::timestamp(d.created_at),
                    d.event.clone(),
                    d.receiver.clone(),
                    d.status.clone(),
                    d.attempts.to_string(),
                    opt(&d.response_status),
                    opt(&d.last_error),
                ]);
            }
            t.print();
        }
        AlertsCmd::TestReceiver { receiver } => {
            let x = a.test_receiver(receiver)?;
            eprintln!(
                "Test webhook {} queued for {}; follow it with `heyctl alerts deliveries -n {ns}`.",
                x.delivery_id, x.receiver
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_parse() {
        assert_eq!(parse_duration("90").unwrap(), 90);
        assert_eq!(parse_duration("30m").unwrap(), 1800);
        assert_eq!(parse_duration("4h").unwrap(), 14_400);
        assert_eq!(parse_duration("2d").unwrap(), 172_800);
        assert!(parse_duration("soon").is_err());
        assert!(parse_duration("3w").is_err());
    }
}
