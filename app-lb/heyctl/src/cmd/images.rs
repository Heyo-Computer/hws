//! `heyctl images` — heyvm's image catalog, as app-lb manages it.
//!
//! Images are named by content, so one is shared by every deployment that
//! pulls the same bytes. `list` shows what holds each one and what the offload
//! pacer would do with it; the rest act on one image. The server refuses to
//! offload or delete anything referenced or pinned, whatever is asked here.

use anyhow::Result;
use clap::Subcommand;

use crate::cmd::Ctx;
use crate::output::{self, Table};

#[derive(Subcommand, Debug)]
pub enum ImagesCmd {
    /// Every image: where it is, its size, what holds it, and whether the
    /// pacer would offload it.
    #[command(alias = "ls")]
    List,
    /// Offload one image now: prove the store it came from still has it (or
    /// push a built one to APP_LB_IMAGE_OFFLOAD_STORE), then delete it from
    /// heyvm. It is pulled back when a deployment needs it again.
    Offload { name: String },
    /// Run the offload pass now.
    Sweep,
    /// Delete an unreferenced image from heyvm outright.
    #[command(alias = "rm")]
    Delete { name: String },
    /// Keep an image on the host: a pinned image is never offloaded.
    Pin { name: String },
    /// Undo `pin`.
    Unpin { name: String },
}

pub fn run(ctx: &Ctx, cmd: &ImagesCmd) -> Result<()> {
    match cmd {
        ImagesCmd::List => list(ctx),
        ImagesCmd::Offload { name } => {
            let e = ctx.client.offload_image(name)?;
            eprintln!(
                "{name} offloaded{}.",
                e.offloaded_to
                    .map(|t| format!(" to {t}"))
                    .unwrap_or_default()
            );
            Ok(())
        }
        ImagesCmd::Sweep => {
            let s = ctx.client.sweep_images()?;
            if let Some(why) = s.skipped {
                eprintln!("Nothing was offloaded: {why}");
                return Ok(());
            }
            for name in &s.offloaded {
                println!("offloaded {name}");
            }
            for (name, why) in &s.failed {
                println!("kept {name}: {why}");
            }
            if s.offloaded.is_empty() && s.failed.is_empty() {
                eprintln!("Nothing to offload.");
            }
            Ok(())
        }
        ImagesCmd::Delete { name } => {
            ctx.client.delete_image(name)?;
            eprintln!("{name} deleted.");
            Ok(())
        }
        ImagesCmd::Pin { name } => {
            ctx.client.pin_image(name, true)?;
            eprintln!("{name} pinned.");
            Ok(())
        }
        ImagesCmd::Unpin { name } => {
            ctx.client.pin_image(name, false)?;
            eprintln!("{name} unpinned.");
            Ok(())
        }
    }
}

fn list(ctx: &Ctx) -> Result<()> {
    let inv = ctx.client.images()?;
    if ctx.out.is_machine() {
        let raw = serde_json::json!({
            "complete": inv.complete,
            "delete_supported": inv.delete_supported,
            "local_bytes": inv.local_bytes,
            "images": inv.images.iter().map(|i| serde_json::json!({
                "name": i.name, "source": i.source, "tier": i.tier, "present": i.present,
                "bytes": i.bytes, "digest": i.digest, "pinned": i.pinned,
                "references": i.references.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "kept_because": i.kept_because,
            })).collect::<Vec<_>>(),
        });
        let names: Vec<String> = inv
            .images
            .iter()
            .map(|i| format!("image/{}", i.name))
            .collect();
        return output::emit(&raw, ctx.out, &names);
    }
    let mut table = Table::new(["NAME", "SOURCE", "WHERE", "SIZE", "HELD BY", "OFFLOAD"]);
    for i in &inv.images {
        let place = if i.present {
            "local"
        } else if i.tier == "offloaded" {
            "offloaded"
        } else {
            "absent"
        };
        let held: Vec<String> = i.references.iter().map(ToString::to_string).collect();
        table.row([
            i.name.clone(),
            i.source.clone(),
            place.to_string(),
            output::bytes(i.bytes),
            if held.is_empty() {
                "-".into()
            } else {
                held.join(", ")
            },
            i.kept_because
                .clone()
                .unwrap_or_else(|| "would offload".into()),
        ]);
    }
    table.print();
    let mut notes = vec![format!("{} on this host", output::bytes(inv.local_bytes))];
    if let Some(d) = inv.disk_used_pct {
        notes.push(format!(
            "disk {d}% used, offload pressure at {}%",
            inv.pressure_pct
        ));
    }
    if !inv.complete {
        notes.push(format!(
            "references unknown, nothing will be removed: {}",
            inv.error.unwrap_or_default()
        ));
    }
    if inv.delete_supported == Some(false) {
        notes.push("this heyvm cannot delete images; upgrade it to offload".into());
    }
    eprintln!("{}", notes.join(" · "));
    Ok(())
}
