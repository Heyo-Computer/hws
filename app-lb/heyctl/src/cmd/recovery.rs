use crate::cmd::Ctx;
use crate::output::{self, Table};
use crate::recovery::{RecoveryRequest, validate_uuid};
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::Value;

#[derive(Debug, Subcommand)]
pub enum RecoveryCmd {
    /// List Cloud checkpoints, including their commit time.
    Checkpoints { cloud_id: String },
    /// Show destination eligibility and rejection reasons.
    Destinations { id: String },
    /// List durable recovery operations.
    List { id: String },
    /// Recover only after independently fencing the source. Never moves a running VM.
    Start(StartArgs),
    /// Inspect an operation, including after an ambiguous POST timeout.
    Status { id: String, operation_id: String },
}

#[derive(Debug, Args)]
pub struct StartArgs {
    id: String,
    #[arg(long, value_parser = validate_uuid)]
    checkpoint: String,
    #[arg(long)]
    destination: String,
    #[arg(long, required = true)]
    source_fenced: bool,
    #[arg(long, value_parser = nonempty)]
    fencing_evidence: String,
    #[arg(long, value_parser = validate_uuid)]
    operation_id: String,
}

fn nonempty(s: &str) -> std::result::Result<String, String> {
    if s.trim().is_empty() {
        Err("provide evidence of external source fencing".into())
    } else {
        Ok(s.into())
    }
}

fn text(v: &Value, key: &str) -> String {
    match &v[key] {
        Value::Null => "-".into(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

pub fn run(ctx: &Ctx, cmd: &RecoveryCmd) -> Result<()> {
    let (value, fields): (Value, &[&str]) = match cmd {
        RecoveryCmd::Checkpoints { cloud_id } => (
            serde_json::to_value(ctx.client.recovery_checkpoints(cloud_id)?)?,
            &[
                "checkpoint_id",
                "state",
                "committed_at",
                "created_at",
                "backend_id",
                "runtime_id",
            ],
        ),
        RecoveryCmd::Destinations { id } => (
            serde_json::to_value(ctx.client.recovery_destinations(id)?)?,
            &["id", "region", "eligible", "reason"],
        ),
        RecoveryCmd::List { id } => (
            serde_json::to_value(ctx.client.recoveries(id)?)?,
            operation_fields(),
        ),
        RecoveryCmd::Status { id, operation_id } => (
            serde_json::to_value(ctx.client.recovery_status(id, operation_id)?)?,
            operation_fields(),
        ),
        RecoveryCmd::Start(a) => {
            let request = RecoveryRequest {
                operation_id: a.operation_id.clone(),
                checkpoint_id: a.checkpoint.clone(),
                destination_backend_id: a.destination.clone(),
                source_fenced: a.source_fenced,
                fencing_evidence: a.fencing_evidence.clone(),
            };
            let result = ctx.client.start_recovery(&a.id, &request).with_context(|| format!("Recovery outcome may be unknown. Inspect `heyctl recovery status {} {}` before retrying; reuse the same operation ID and identical request, never generate another ID after timeout", a.id, a.operation_id))?;
            (serde_json::to_value(result)?, operation_fields())
        }
    };
    if ctx.out.is_machine() {
        return output::emit(&value, ctx.out, &[]);
    }
    let rows: Vec<&Value> = if let Some(rows) = value.as_array() {
        rows.iter().collect()
    } else if let Some(rows) = value.get("destinations").and_then(Value::as_array) {
        eprintln!(
            "Sandbox: {}  Source backend: {}",
            text(&value, "sandbox_id"),
            text(&value, "source_backend_id")
        );
        rows.iter().collect()
    } else {
        vec![&value]
    };
    let mut table = Table::new(fields.iter().map(|s| s.to_uppercase()));
    for row in rows {
        table.row(fields.iter().map(|key| {
            if key.ends_with("_at") {
                if let Some(secs) = row[*key].as_u64() {
                    return output::timestamp(secs);
                }
            }
            text(row, key)
        }));
    }
    table.print();
    Ok(())
}

fn operation_fields() -> &'static [&'static str] {
    &[
        "operation_id",
        "sandbox_id",
        "source_backend_id",
        "destination_backend_id",
        "recovery_checkpoint_id",
        "phase",
        "source_fenced",
        "fencing_evidence",
        "error",
        "created_at",
        "updated_at",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: RecoveryCmd,
    }
    #[test]
    fn parser_requires_explicit_safe_intent() {
        let uuid = "12345678-1234-1234-1234-123456789abc";
        let args = [
            "recovery",
            "start",
            "vm",
            "--checkpoint",
            uuid,
            "--destination",
            "eu1",
            "--source-fenced",
            "--fencing-evidence",
            "power disabled",
            "--operation-id",
            uuid,
        ];
        assert!(Cli::try_parse_from(args).is_ok());
        for flag in [
            "--checkpoint",
            "--destination",
            "--source-fenced",
            "--fencing-evidence",
            "--operation-id",
        ] {
            let i = args.iter().position(|s| *s == flag).unwrap();
            let mut missing = args.to_vec();
            missing.drain(i..i + if flag == "--source-fenced" { 1 } else { 2 });
            assert!(Cli::try_parse_from(missing).is_err(), "{flag}");
        }
        let mut invalid = args;
        invalid[11] = "not-a-uuid";
        assert!(Cli::try_parse_from(invalid).is_err());
        invalid = args;
        invalid[9] = " ";
        assert!(Cli::try_parse_from(invalid).is_err());
        for verb in ["checkpoints", "destinations", "list"] {
            assert!(Cli::try_parse_from(["recovery", verb, "vm"]).is_ok());
        }
        assert!(Cli::try_parse_from(["recovery", "status", "vm", uuid]).is_ok());
    }
}
