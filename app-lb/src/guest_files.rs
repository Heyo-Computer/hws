//! Reading and writing files in a running guest, over its console.
//!
//! heyvmd's own file routes act on host directories that a running Firecracker
//! guest never sees, so the only way to a file inside one is a command. These
//! are those commands: a read is a byte range of the file, base64-encoded; a
//! write is the bytes base64-encoded into the command and decoded in the guest,
//! one console-sized chunk at a time. The console moves tens of KB/s, which
//! suits configuration files, logs and small artifacts; anything larger goes
//! through a transfer, which the guest fetches over the network.

use base64::Engine as _;

/// Most bytes one read returns.
pub const MAX_READ_BYTES: u64 = 256 * 1024;
pub const DEFAULT_READ_BYTES: u64 = 96 * 1024;
/// Most bytes one write accepts; larger goes through a transfer.
pub const MAX_WRITE_BYTES: usize = 1024 * 1024;
/// Bytes per console command when writing. heyvmd runs a command as one
/// argument to `env … sh -lc`, and Linux caps a single argument at 128 KiB
/// (`MAX_ARG_STRLEN`); 96 KiB base64-encodes to exactly that and failed with
/// "Argument list too long" on us5. 48 KiB encodes to 64 KiB.
pub const WRITE_CHUNK: usize = 48 * 1024;

/// Whether `path` can be named in a guest command: absolute, and free of what
/// single quotes cannot carry over the serial console.
pub fn valid_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err(format!("path must be absolute: {path:?}"));
    }
    if path.contains('\'') || path.contains('\n') || path.contains('\r') || path.contains('\\') {
        return Err(format!(
            "path cannot contain a quote, backslash or newline: {path:?}"
        ));
    }
    Ok(())
}

/// The file's size, then `len` bytes from `offset`, base64.
pub fn read_script(path: &str, offset: u64, len: u64) -> String {
    format!(
        "f='{path}'; [ -f \"$f\" ] || {{ echo 'error=no such file'; exit 2; }}; \
         s=$(wc -c < \"$f\" | tr -d ' '); echo \"size=$s\"; printf 'data='; \
         tail -c +{start} \"$f\" | head -c {len} | base64 | tr -d '[:space:]'; echo",
        start = offset + 1,
    )
}

/// The file's size and the bytes [`read_script`] printed.
pub fn parse_read(stdout: &str) -> Result<(u64, Vec<u8>), String> {
    let mut size = None;
    let mut data = None;
    for line in stdout.lines().map(str::trim) {
        if let Some(e) = line.strip_prefix("error=") {
            return Err(e.to_string());
        } else if let Some(s) = line.strip_prefix("size=") {
            size = s.parse().ok();
        } else if let Some(d) = line.strip_prefix("data=") {
            data = Some(d.to_string());
        }
    }
    let size =
        size.ok_or_else(|| format!("the guest did not report the file size: {}", stdout.trim()))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data.unwrap_or_default())
        .map_err(|e| format!("the guest's read was not valid base64: {e}"))?;
    Ok((size, bytes))
}

/// The commands that write `bytes` to `path`: the first replaces the file (or
/// appends, with `append`) and creates its directory, the rest append. The last
/// prints the file's size. An empty write still creates or truncates the file.
pub fn write_scripts(path: &str, bytes: &[u8], append: bool) -> Vec<String> {
    let dir = match path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => path[..i].to_string(),
    };
    let chunks: Vec<&[u8]> = if bytes.is_empty() {
        vec![&[][..]]
    } else {
        bytes.chunks(WRITE_CHUNK).collect()
    };
    let last = chunks.len() - 1;
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let encoded = base64::engine::general_purpose::STANDARD.encode(chunk);
            let redirect = if i == 0 && !append { ">" } else { ">>" };
            let prefix = if i == 0 {
                format!("mkdir -p '{dir}' && ")
            } else {
                String::new()
            };
            let suffix = if i == last {
                format!(" && echo \"size=$(wc -c < '{path}' | tr -d ' ')\"")
            } else {
                String::new()
            };
            format!("{prefix}printf %s '{encoded}' | base64 -d {redirect} '{path}'{suffix}")
        })
        .collect()
}

/// The size the last write command reported.
pub fn parse_written(stdout: &str) -> Option<u64> {
    stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("size=").and_then(|s| s.parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_absolute_and_quotable() {
        assert!(valid_path("/workspace/a b.txt").is_ok());
        assert!(valid_path("rel").is_err());
        assert!(valid_path("/a'b").is_err());
        assert!(valid_path("/a\\b").is_err());
    }

    #[test]
    fn reads_parse_and_report_missing_files() {
        assert_eq!(
            parse_read("size=5\ndata=aGVsbG8=\n").unwrap(),
            (5, b"hello".to_vec())
        );
        assert_eq!(
            parse_read("error=no such file\n").unwrap_err(),
            "no such file"
        );
    }

    #[test]
    fn writes_chunk_and_only_the_first_replaces() {
        let bytes = vec![7u8; WRITE_CHUNK * 2 + 1];
        let scripts = write_scripts("/workspace/d/f", &bytes, false);
        assert_eq!(scripts.len(), 3);
        assert!(
            scripts[0].starts_with("mkdir -p '/workspace/d' && ")
                && scripts[0].contains("> '/workspace/d/f'")
        );
        assert!(scripts[1].contains(">> '/workspace/d/f'") && !scripts[1].contains("size="));
        assert!(scripts[2].contains("size="));
        assert!(write_scripts("/f", &[], false)[0].contains("> '/f'"));
        assert!(write_scripts("/f", b"x", true)[0].contains(">> '/f'"));
        for s in &scripts {
            assert!(!s.contains('\\'), "no backslash on the serial line");
            assert!(
                s.len() < 100_000,
                "a command is one argv entry, capped at 128 KiB: {}",
                s.len()
            );
        }
        assert_eq!(parse_written("size=42\n"), Some(42));
    }
}
