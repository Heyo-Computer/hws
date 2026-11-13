#![cfg(all(feature = "cli", unix))]

use std::{fs, process::Command};
use sha2::{Digest, Sha256};

#[test]
fn upgrade_replaces_current_install_and_preserves_it_on_corrupt_download() {
    let root = std::env::temp_dir().join(format!("heyctl upgrade {}", std::process::id()));
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("store/blobs")).unwrap();
    let installed = root.join("bin/heyctl");
    let original = fs::read(env!("CARGO_BIN_EXE_heyctl")).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_heyctl"), &installed).unwrap();
    let replacement = b"#!/bin/sh\necho 'heyctl fixture-release'\n";
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut archive = tar::Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_size(replacement.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    archive.append_data(&mut header, "heyctl", &replacement[..]).unwrap();
    let bytes = archive.into_inner().unwrap().finish().unwrap();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let blob = root.join("store/blobs").join(&digest);
    fs::write(&blob, &bytes).unwrap();
    let platform = format!("{}-{}", if cfg!(target_os = "macos") { "darwin" } else { "linux" },
        if cfg!(target_arch = "aarch64") { "aarch64" } else { "x86_64" });
    let manifest = root.join("versions.json");
    fs::write(&manifest, serde_json::json!({
        "latest": "unavailable", "store": reqwest::Url::from_directory_path(root.join("store")).unwrap().as_str().trim_end_matches('/'),
        "artifacts": [{"version":"fixture", "platform": platform, "digest":digest, "bin":"heyctl"}]
    }).to_string()).unwrap();
    let invoke = || {
        Command::new(&installed)
            .args(["--config", "/nonexistent/heyctl-config", "upgrade", "--to", "fixture"])
            .env_remove("HEYCTL_DIGEST").env_remove("HEYCTL_STORE_URL")
            .env_remove("HEYCTL_NO_VERIFY").env_remove("HEYCTL_VERSION")
            .env("HEYCTL_MANIFEST_URL", reqwest::Url::from_file_path(&manifest).unwrap().as_str())
            .output().unwrap()
    };
    let result = invoke();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert_eq!(fs::read(&installed).unwrap(), replacement);

    fs::copy(env!("CARGO_BIN_EXE_heyctl"), &installed).unwrap();
    fs::write(&blob, b"corrupted archive").unwrap();
    let result = invoke();
    assert!(!result.status.success());
    assert_eq!(fs::read(&installed).unwrap(), original);

    // The normal --upgrade path uses heyvm's S3 layout, without a server login
    // or a legacy manifest. Never fall back to another release on failure.
    let releases = root.join("releases");
    fs::create_dir_all(releases.join("v1.2.3")).unwrap();
    fs::write(releases.join("latest.txt"), "1.2.3\n").unwrap();
    let os = if cfg!(target_os = "macos") { "apple-darwin" } else { "unknown-linux-gnu" };
    let arch = if cfg!(target_arch = "aarch64") { "aarch64" } else { "x86_64" };
    let name = format!("heyctl-1.2.3-{os}-{arch}.tar.gz");
    let archive_path = releases.join("v1.2.3").join(&name);
    fs::write(&archive_path, &bytes).unwrap();
    fs::write(releases.join("v1.2.3").join(format!("{name}.sha256")), &digest).unwrap();
    let upgrade = |args: &[&str]| {
        Command::new(&installed).args(args)
            .env_remove("HEYCTL_DIGEST").env_remove("HEYCTL_STORE_URL")
            .env_remove("HEYCTL_MANIFEST_URL").env_remove("HEYCTL_BASE_URL")
            .env_remove("HEYCTL_NO_VERIFY").env_remove("HEYCTL_VERSION")
            .env("HEYCTL_INSTALL_BASE_URL", reqwest::Url::from_directory_path(&releases).unwrap().as_str())
            .output().unwrap()
    };
    let result = upgrade(&["--upgrade", "get", "deployments"]);
    assert!(!result.status.success());
    assert_eq!(fs::read(&installed).unwrap(), original);
    let result = upgrade(&["--config", "/nonexistent/heyctl-config", "--upgrade"]);
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert_eq!(fs::read(&installed).unwrap(), replacement);

    fs::copy(env!("CARGO_BIN_EXE_heyctl"), &installed).unwrap();
    fs::write(&archive_path, b"corrupted S3 archive").unwrap();
    assert!(!upgrade(&["--upgrade"]).status.success());
    assert_eq!(fs::read(&installed).unwrap(), original);
    fs::write(releases.join("latest.txt"), "9.9.9\n").unwrap();
    assert!(!upgrade(&["--upgrade"]).status.success());
    assert_eq!(fs::read(&installed).unwrap(), original);
    fs::remove_dir_all(root).unwrap();
}
