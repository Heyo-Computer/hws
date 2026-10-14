//! Sealing a fleet record with `APP_LB_SECRET_KEY` before it reaches the
//! shared store: AES-256-GCM, bound to the record's kind and key so a sealed
//! body cannot be moved to another record.
//!
//! Its own module because the `app-lb-fleet-import` binary seals too.

use std::io;

pub const MAGIC: &[u8] = b"applb-sealed-v1\0";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

pub fn seal(secret_key: &[u8], kind: &str, key: &str, plaintext: &[u8]) -> io::Result<Vec<u8>> {
    use openssl::symm::{Cipher, encrypt_aead};
    let mut nonce = [0u8; NONCE_LEN];
    openssl::rand::rand_bytes(&mut nonce).map_err(io::Error::other)?;
    let mut tag = [0u8; TAG_LEN];
    let aad = format!("{kind}/{key}");
    let ct = encrypt_aead(
        Cipher::aes_256_gcm(),
        secret_key,
        Some(&nonce),
        aad.as_bytes(),
        plaintext,
        &mut tag,
    )
    .map_err(|e| io::Error::other(format!("seal failed: {e}")))?;
    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + TAG_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn unseal(secret_key: &[u8], kind: &str, key: &str, sealed: &[u8]) -> io::Result<Vec<u8>> {
    use openssl::symm::{Cipher, decrypt_aead};
    let rest = sealed.strip_prefix(MAGIC).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{kind}/{key} is not sealed"),
        )
    })?;
    if rest.len() < NONCE_LEN + TAG_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{kind}/{key} is truncated"),
        ));
    }
    let (nonce, rest) = rest.split_at(NONCE_LEN);
    let (tag, ct) = rest.split_at(TAG_LEN);
    let aad = format!("{kind}/{key}");
    decrypt_aead(Cipher::aes_256_gcm(), secret_key, Some(nonce), aad.as_bytes(), ct, tag).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{kind}/{key} does not open with this APP_LB_SECRET_KEY; every fleet host needs the same one"
            ),
        )
    })
}
