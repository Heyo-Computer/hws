//! Route 53, for the DNS-01 challenge.
//!
//! Shells out to the `aws` CLI rather than linking an SDK, the same way image
//! builds shell out to `heyvm` and artifact pulls to `art`. Three API calls are
//! needed — publish a TXT record, wait for the change to reach every Route 53
//! nameserver, and confirm they answer with it — and `aws-sdk-route53` brings
//! about forty crates and its own credential machinery to make them. The CLI already has credentials sorted
//! out (profile, instance role, `AWS_*`), which is the part nobody wants to
//! reimplement.
//!
//! The cost is a binary on the host. `APP_LB_AWS_BIN` points at it, and a
//! missing one surfaces as a failed issuance with the reason in the log rather
//! than a mystery.

use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// How long one `aws` invocation may take before it is killed. Generous, since
/// `test-dns-answer` occasionally waits on a slow resolver, but bounded: a
/// wedged CLI must not hold the ACME sweep open forever.
const CALL_TIMEOUT: Duration = Duration::from_secs(60);

/// How long to wait for a change to reach every Route 53 nameserver, and then
/// for them to answer with the record.
///
/// This wait is the difference between a working DNS-01 setup and one that
/// throttles the whole account. Let's Encrypt gets exactly one look, from
/// several vantage points at once, and a failed validation puts *every*
/// hostname on this account into a backoff measured in hours.
///
/// `ChangeResourceRecordSets` returns `PENDING`; the change has reached every
/// Route 53 location only once `GetChange` says `INSYNC`, typically 30–60
/// seconds later. `TestDNSAnswer` alone does not prove that: the nameserver
/// addresses are anycast, so it sees the nearby sites, which have the record
/// within seconds, while the CA validates from several regions at once and can
/// reach a site that does not yet. Checking only `TestDNSAnswer`, a wildcard
/// order went `Invalid` nine seconds after publishing; waiting for `INSYNC`
/// first is also what lego's Route 53 provider does.
const VISIBLE_TIMEOUT: Duration = Duration::from_secs(180);
const VISIBLE_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum DnsError {
    /// The `aws` binary could not be run at all.
    Spawn(std::io::Error),
    /// It ran and failed; carries the command and its stderr.
    Failed { what: String, detail: String },
    Timeout(String),
    /// The record was published but the nameservers never served it.
    NotVisible { name: String, waited_secs: u64 },
    /// The change never reached every Route 53 nameserver.
    NotInSync { name: String, waited_secs: u64 },
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(e) => write!(
                f,
                "could not run the aws CLI ({e}); DNS-01 needs it on the app-lb host \
                 (set APP_LB_AWS_BIN if it is not on PATH)"
            ),
            Self::Failed { what, detail } => write!(f, "{what} failed: {detail}"),
            Self::Timeout(what) => write!(f, "{what} did not finish in time"),
            Self::NotVisible { name, waited_secs } => write!(
                f,
                "published {name} but Route 53's nameservers still did not answer with it \
                 after {waited_secs}s; not asking the CA to validate against a record it \
                 would not find"
            ),
            Self::NotInSync { name, waited_secs } => write!(
                f,
                "published {name} but Route 53 had not reported the change INSYNC after \
                 {waited_secs}s; not asking the CA to validate while some nameservers may \
                 not have it"
            ),
        }
    }
}

impl std::error::Error for DnsError {}

/// A hosted zone, addressed through the `aws` CLI.
#[derive(Debug, Clone)]
pub struct Route53 {
    aws_bin: String,
    zone_id: String,
}

impl Route53 {
    pub fn new(aws_bin: impl Into<String>, zone_id: impl Into<String>) -> Self {
        Self {
            aws_bin: aws_bin.into(),
            zone_id: zone_id.into(),
        }
    }

    /// Publish the DNS-01 response for `domain` and wait until Route 53's own
    /// nameservers answer with it.
    ///
    /// `values` are the raw challenge digests; they are quoted here because a
    /// TXT record's value is a quoted character-string on the wire, and Route 53
    /// takes it in that form.
    ///
    /// Several values for one name is not an edge case: ordering `example.com`
    /// and `*.example.com` together produces two authorizations that share the
    /// single name `_acme-challenge.example.com`, and both digests have to be
    /// present at once or one of the two fails.
    pub async fn publish_challenge(&self, domain: &str, values: &[String]) -> Result<(), DnsError> {
        let name = challenge_name(domain);
        let deadline = tokio::time::Instant::now() + VISIBLE_TIMEOUT;
        let change_id = self.change("UPSERT", &name, values).await?;
        self.wait_until_insync(&name, &change_id, deadline).await?;
        self.wait_until_visible(&name, values, deadline).await
    }

    /// Remove the challenge record. Best-effort by design: a leftover
    /// `_acme-challenge` TXT is harmless, and failing an issuance that already
    /// succeeded because the cleanup did not would be worse.
    pub async fn retract_challenge(&self, domain: &str, values: &[String]) {
        if values.is_empty() {
            return;
        }
        let name = challenge_name(domain);
        if let Err(e) = self.change("DELETE", &name, values).await.map(drop) {
            tracing::warn!(%name, error = %e, "could not remove the ACME challenge record");
        }
    }

    /// One `ChangeResourceRecordSets` call. Returns the change id, for
    /// [`Self::wait_until_insync`].
    ///
    /// `values` are raw digests. A TXT record's value is a quoted
    /// character-string on the wire, and Route 53 wants it written that way, so
    /// the quotes are added here — once, in the one place that talks to the API.
    async fn change(
        &self,
        action: &str,
        name: &str,
        values: &[String],
    ) -> Result<String, DnsError> {
        let batch = serde_json::json!({
            "Changes": [{
                "Action": action,
                "ResourceRecordSet": {
                    "Name": name,
                    "Type": "TXT",
                    // Short, because the record only has to outlive one
                    // validation — and because a long TTL on a stale challenge
                    // is what makes the *next* issuance fail.
                    "TTL": 60,
                    "ResourceRecords": values
                        .iter()
                        .map(|v| serde_json::json!({ "Value": format!("\"{v}\"") }))
                        .collect::<Vec<_>>(),
                }
            }]
        });

        self.run(
            &[
                "route53",
                "change-resource-record-sets",
                "--hosted-zone-id",
                &self.zone_id,
                "--change-batch",
                &batch.to_string(),
                "--output",
                "json",
            ],
            &format!("{action} {name}"),
        )
        .await
        .and_then(|stdout| {
            change_info(&stdout)
                .map(|(id, _)| id)
                .ok_or_else(|| DnsError::Failed {
                    what: format!("{action} {name}"),
                    detail: format!("no ChangeInfo.Id in the response: {}", stdout.trim()),
                })
        })
    }

    /// Poll `GetChange` until Route 53 reports the change `INSYNC`, meaning
    /// every one of its authoritative nameservers has it.
    async fn wait_until_insync(
        &self,
        name: &str,
        change_id: &str,
        deadline: tokio::time::Instant,
    ) -> Result<(), DnsError> {
        loop {
            let status = self
                .run(
                    &[
                        "route53",
                        "get-change",
                        "--id",
                        change_id,
                        "--output",
                        "json",
                    ],
                    &format!("get-change {change_id}"),
                )
                .await;
            match status {
                Ok(stdout) => match change_info(&stdout) {
                    Some((_, status)) if status == "INSYNC" => {
                        tracing::debug!(%name, change_id, "challenge record is in sync");
                        return Ok(());
                    }
                    Some((_, status)) => {
                        tracing::debug!(%name, change_id, %status, "waiting for INSYNC")
                    }
                    None => tracing::debug!(%name, change_id, "unparseable get-change output"),
                },
                // Missing route53:GetChange is a configuration error that no
                // amount of waiting fixes; say so rather than timing out.
                Err(e @ DnsError::Failed { .. }) if is_access_denied(&e) => return Err(e),
                Err(e) => tracing::debug!(%name, error = %e, "get-change failed; retrying"),
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(DnsError::NotInSync {
                    name: name.to_string(),
                    waited_secs: VISIBLE_TIMEOUT.as_secs(),
                });
            }
            tokio::time::sleep(VISIBLE_INTERVAL).await;
        }
    }

    /// Ask Route 53's authoritative nameservers what they would answer for
    /// `name`, until they answer with every value.
    ///
    /// `test-dns-answer` is the right question rather than a local resolver
    /// lookup: it queries the zone's own nameservers, which is exactly who the
    /// CA will ask, and it needs no extra binary or DNS client in the tree.
    async fn wait_until_visible(
        &self,
        name: &str,
        values: &[String],
        deadline: tokio::time::Instant,
    ) -> Result<(), DnsError> {
        loop {
            let answer = self
                .run(
                    &[
                        "route53",
                        "test-dns-answer",
                        "--hosted-zone-id",
                        &self.zone_id,
                        "--record-name",
                        name,
                        "--record-type",
                        "TXT",
                        "--output",
                        "json",
                    ],
                    &format!("test-dns-answer {name}"),
                )
                .await;

            match answer {
                Ok(stdout) => {
                    // A transient failure here is not fatal — it is one poll of
                    // a loop that will ask again — so the parse is forgiving.
                    let seen = serde_json::from_str::<serde_json::Value>(&stdout)
                        .ok()
                        .and_then(|v| v.get("RecordData")?.as_array().cloned())
                        .unwrap_or_default();
                    let seen: Vec<String> = seen
                        .iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| s.trim_matches('"').to_string())
                        .collect();
                    if values.iter().all(|v| seen.contains(v)) {
                        tracing::debug!(%name, "challenge record is answerable");
                        return Ok(());
                    }
                    tracing::debug!(%name, want = values.len(), have = seen.len(), "waiting for DNS");
                }
                Err(e) => tracing::debug!(%name, error = %e, "DNS check failed; retrying"),
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(DnsError::NotVisible {
                    name: name.to_string(),
                    waited_secs: VISIBLE_TIMEOUT.as_secs(),
                });
            }
            tokio::time::sleep(VISIBLE_INTERVAL).await;
        }
    }

    /// Run `aws` with the given arguments and return stdout.
    async fn run(&self, args: &[&str], what: &str) -> Result<String, DnsError> {
        let mut command = Command::new(&self.aws_bin);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Without this a timed-out `aws` outlives the future that gave up
            // on it and keeps its pipes open.
            .kill_on_drop(true);

        let output = match tokio::time::timeout(CALL_TIMEOUT, command.output()).await {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => return Err(DnsError::Spawn(e)),
            Err(_) => return Err(DnsError::Timeout(what.to_string())),
        };

        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(DnsError::Failed {
                what: what.to_string(),
                detail: if detail.is_empty() {
                    format!("exit status {}", output.status)
                } else {
                    detail
                },
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

/// `(Id, Status)` from a `ChangeResourceRecordSets` or `GetChange` response.
fn change_info(stdout: &str) -> Option<(String, String)> {
    let v: serde_json::Value = serde_json::from_str(stdout).ok()?;
    let info = v.get("ChangeInfo")?;
    Some((
        info.get("Id")?.as_str()?.to_string(),
        info.get("Status")?.as_str()?.to_string(),
    ))
}

fn is_access_denied(e: &DnsError) -> bool {
    matches!(e, DnsError::Failed { detail, .. }
        if detail.contains("AccessDenied") || detail.contains("not authorized"))
}

/// The record name a DNS-01 challenge for `domain` is published at.
///
/// Always the bare domain's `_acme-challenge`, never the wildcard's: an
/// authorization for `*.example.com` is an authorization for `example.com`, and
/// the CA looks up `_acme-challenge.example.com` for both. Publishing under a
/// literal `*` would create a record nothing ever reads.
pub fn challenge_name(domain: &str) -> String {
    format!(
        "_acme-challenge.{}.",
        domain.trim().trim_start_matches("*.").trim_end_matches('.')
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_info_reads_id_and_status() {
        let out = r#"{"ChangeInfo": {"Id": "/change/C123", "Status": "PENDING",
            "SubmittedAt": "2026-11-20T18:25:28Z"}}"#;
        assert_eq!(
            change_info(out),
            Some(("/change/C123".to_string(), "PENDING".to_string()))
        );
        assert_eq!(change_info("{}"), None);
        assert_eq!(change_info("not json"), None);
    }

    #[test]
    fn access_denied_is_recognised() {
        let denied = DnsError::Failed {
            what: "get-change".into(),
            detail: "An error occurred (AccessDenied) when calling the GetChange operation".into(),
        };
        assert!(is_access_denied(&denied));
        assert!(!is_access_denied(&DnsError::Timeout("x".into())));
    }

    /// The wildcard and its apex share one challenge name. Getting this wrong
    /// publishes a record with a `*` in it that the CA never looks up, and the
    /// order fails with nothing obviously wrong in the zone.
    #[test]
    fn the_wildcard_and_its_apex_share_a_challenge_name() {
        assert_eq!(
            challenge_name("*.sb.example.com"),
            "_acme-challenge.sb.example.com."
        );
        assert_eq!(
            challenge_name("sb.example.com"),
            "_acme-challenge.sb.example.com."
        );
        // Trailing dots and stray whitespace are normalised away rather than
        // producing `_acme-challenge.sb.example.com..`.
        assert_eq!(
            challenge_name("  sb.example.com.  "),
            "_acme-challenge.sb.example.com."
        );
    }
}
