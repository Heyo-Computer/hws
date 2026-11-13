use anyhow::{Context, Result, bail};
use std::path::PathBuf;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Install this published version instead of the latest release.
    #[arg(long, value_name = "VERSION")]
    pub to: Option<String>,
    /// Install into PATH/bin instead of replacing this installation.
    #[arg(long, value_name = "PATH")]
    pub prefix: Option<PathBuf>,
}

pub fn run(args: &Args) -> Result<()> {
    if !cfg!(unix) {
        bail!("self-upgrade currently supports Linux and macOS; reinstall heyctl on this platform");
    }
    let prefix = match &args.prefix {
        Some(prefix) => prefix.clone(),
        None => {
            let exe = std::env::current_exe().context("locating the running heyctl")?;
            let bin = exe.parent().context("heyctl has no installation directory")?;
            if bin.file_name() != Some(std::ffi::OsStr::new("bin")) {
                bail!("heyctl is not installed in a bin directory; use upgrade --prefix PATH to install into PATH/bin");
            }
            bin.parent().context("heyctl has no installation prefix")?.to_path_buf()
        }
    };
    // Reuse the published installer's platform selection, checksums and atomic
    // replacement. Embed it rather than downloading and executing remote code.
    let mut command = std::process::Command::new("sh");
    command.args(["-s", "--", "--prefix"]).arg(&prefix);
    if let Some(version) = &args.to {
        command.args(["--version", version]);
    }
    let mut child = command.stdin(std::process::Stdio::piped()).spawn()
        .context("starting the heyctl installer (requires sh)")?;
    use std::io::Write;
    let written = child.stdin.take().context("opening installer input")?
        .write_all(include_bytes!("../install.sh"));
    let status = child.wait().context("waiting for the heyctl installer")?;
    if !status.success() {
        bail!("heyctl installer failed ({status}); see its output above");
    }
    written.context("sending the heyctl installer")?;
    Ok(())
}
