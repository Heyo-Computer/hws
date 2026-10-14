//! The sealed form of app-lb's secrets file, for a writer that is not the
//! [`SecretStore`](crate::secrets::SecretStore): the fleet importer, which
//! carries a server's plaintext secrets file into a fleet where secrets are
//! sealed with the fleet's `APP_LB_SECRET_KEY`.
//!
//! The envelope is the store's own, byte-compatible with what it reads:
//! `{"version": 1, "encryption": "aes-256-gcm", "nonce", "tag", "ciphertext"}`,
//! base64 throughout, the plaintext being the JSON array of secrets.

use base64::Engine;
use std::io;

/// Bound into the AEAD, so a payload cannot be replayed into another format.
pub const AAD: &[u8] = b"app-lb-secrets-v1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Turn whatever `APP_LB_SECRET_KEY` holds into 32 bytes.
///
/// 64 hex characters are taken literally, so a key generated with `openssl rand
/// -hex 32` is used as-is; anything else is hashed, so a passphrase works too
/// without a silently-truncated key.
#[allow(dead_code)]
pub fn derive_key(material: &str) -> Vec<u8> {
    let material = material.trim();
    if material.len() == 64
        && let Ok(bytes) = hex_decode(material)
    {
        return bytes;
    }
    openssl::hash::hash(openssl::hash::MessageDigest::sha256(), material.as_bytes())
        .expect("sha256 of a byte string cannot fail")
        .to_vec()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

/// Seal a plaintext secrets file (`"encryption": "none"`) with `key` (already
/// derived, 32 bytes). A file that is already sealed is returned unchanged:
/// re-sealing it would need the key it was sealed with.
#[allow(dead_code)]
pub fn seal_file(key: &[u8], file: &[u8]) -> io::Result<Vec<u8>> {
    let value: serde_json::Value = serde_json::from_slice(file)?;
    match value.get("encryption").and_then(|e| e.as_str()) {
        Some("none") => {}
        Some(_) => return Ok(file.to_vec()),
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a secrets file: no `encryption` field",
            ));
        }
    }
    let secrets = value
        .get("secrets")
        .cloned()
        .unwrap_or_else(|| serde_json::Value::Array(Vec::new()));
    let plaintext = serde_json::to_vec(&secrets)?;
    let mut nonce = [0u8; NONCE_LEN];
    openssl::rand::rand_bytes(&mut nonce).map_err(io::Error::other)?;
    let mut tag = [0u8; TAG_LEN];
    let ciphertext = openssl::symm::encrypt_aead(
        openssl::symm::Cipher::aes_256_gcm(),
        key,
        Some(&nonce),
        AAD,
        &plaintext,
        &mut tag,
    )
    .map_err(|e| io::Error::other(format!("seal failed: {e}")))?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let sealed = serde_json::json!({
        "version": 1,
        "encryption": "aes-256-gcm",
        "nonce": b64.encode(nonce),
        "tag": b64.encode(tag),
        "ciphertext": b64.encode(ciphertext),
    });
    Ok(serde_json::to_vec_pretty(&sealed)?)
}

/// The secrets inside a secrets file, as JSON: read straight from a plaintext
/// one, decrypted from a sealed one with `key`.
#[allow(dead_code)]
pub fn open_file(key: &[u8], file: &[u8]) -> io::Result<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_slice(file)?;
    let bad = |why: &str| io::Error::new(io::ErrorKind::InvalidData, why.to_string());
    match value.get("encryption").and_then(|e| e.as_str()) {
        Some("none") => Ok(value
            .get("secrets")
            .cloned()
            .unwrap_or_else(|| serde_json::Value::Array(Vec::new()))),
        Some("aes-256-gcm") => {
            let b64 = base64::engine::general_purpose::STANDARD;
            let field = |name: &str| -> io::Result<Vec<u8>> {
                let s = value
                    .get(name)
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| bad("a sealed secrets file is missing a field"))?;
                b64.decode(s)
                    .map_err(|_| bad("a sealed secrets field is not base64"))
            };
            let plaintext = openssl::symm::decrypt_aead(
                openssl::symm::Cipher::aes_256_gcm(),
                key,
                Some(&field("nonce")?),
                AAD,
                &field("ciphertext")?,
                &field("tag")?,
            )
            .map_err(|_| bad("the secrets file does not open with this APP_LB_SECRET_KEY"))?;
            Ok(serde_json::from_slice(&plaintext)?)
        }
        _ => Err(bad("not a secrets file")),
    }
}
