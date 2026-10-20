//! Certificate storage and per-SNI selection for the HTTPS listener.
//!
//! The listener holds no certificate of its own. Pingora is configured with
//! [`TlsSettings::with_callbacks`], which builds an acceptor with *no* cert
//! attached, so [`CertStore`] is consulted during every handshake to supply one
//! based on the client's SNI. That is what lets a certificate issued seconds ago
//! for a brand-new deployment serve immediately, with no restart.
//!
//! The flip side: a bug here breaks *all* HTTPS rather than one hostname. Two
//! things guard against that — the store is populated from disk before the
//! listener binds, and an optional fallback certificate (`APP_LB_TLS_CERT`)
//! answers any SNI with no issued cert of its own.
//!
//! [`TlsSettings::with_callbacks`]: pingora_core::listeners::TlsSettings::with_callbacks

use crate::fleet_store::{Collection, Expect, FileCollection, FileOptions};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use openssl::asn1::Asn1Time;
use pingora_core::listeners::TlsAccept;
use pingora_core::protocols::tls::TlsRef;
use pingora_core::tls::ext;
use pingora_core::tls::pkey::{PKey, Private};
use pingora_core::tls::ssl::NameType;
use pingora_core::tls::x509::X509;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Renew once the certificate has this many days or fewer left. Let's Encrypt
/// issues for 90 days and starts sending expiry warnings at 20, so 30 leaves
/// room for several retries before anything is user-visible.
pub const RENEW_BEFORE_DAYS: u32 = 30;

/// A leaf certificate with the chain and private key needed to serve it.
pub struct CertifiedKey {
    leaf: X509,
    /// Intermediates, in order. Without these many clients reject the leaf, so
    /// they are installed on every handshake alongside it.
    chain: Vec<X509>,
    key: PKey<Private>,
}

impl CertifiedKey {
    /// Parse a PEM chain (leaf first, as ACME returns it) and a PEM private key.
    pub fn from_pem(chain_pem: &[u8], key_pem: &[u8]) -> Result<Self, CertError> {
        let mut certs = X509::stack_from_pem(chain_pem).map_err(CertError::Parse)?;
        if certs.is_empty() {
            return Err(CertError::NoCerts);
        }
        let leaf = certs.remove(0);
        let key = PKey::private_key_from_pem(key_pem).map_err(CertError::Parse)?;
        let public_key = leaf.public_key().map_err(CertError::Parse)?;
        if !public_key.public_eq(&key) {
            return Err(CertError::KeyMismatch);
        }
        Ok(Self {
            leaf,
            chain: certs,
            key,
        })
    }

    /// `true` once the certificate is inside the renewal window (or already
    /// expired). A cert whose expiry can't be compared is treated as due for
    /// renewal — reissuing a good cert is cheaper than serving an expired one.
    pub fn needs_renewal(&self) -> bool {
        let Ok(threshold) = Asn1Time::days_from_now(RENEW_BEFORE_DAYS) else {
            return true;
        };
        self.leaf.not_after() <= threshold
    }

    /// Expiry as an RFC-ish display string, for the admin API.
    pub fn not_after(&self) -> String {
        self.leaf.not_after().to_string()
    }

    /// The domain this certificate wildcards, if it has a `*.<domain>` SAN.
    ///
    /// Read from the certificate rather than from configuration, so what gets
    /// served follows what was actually issued — including a wildcard installed
    /// by hand through `APP_LB_TLS_CERT`. It is what lets
    /// [`lookup`](CertStore::lookup) answer a subdomain with its parent's
    /// certificate *without* ever doing so for a parent that is not a wildcard,
    /// which would be a name mismatch at the client.
    pub fn wildcard_of(&self) -> Option<String> {
        let names = self.leaf.subject_alt_names()?;
        names
            .iter()
            .filter_map(|n| n.dnsname())
            .find_map(|n| n.strip_prefix("*."))
            .map(|d| d.to_ascii_lowercase())
    }

    /// Issuer DN, for the admin API — distinguishes a real Let's Encrypt cert
    /// from a self-signed fallback at a glance. Rendered as `C=US, O=…, CN=…`.
    pub fn issuer(&self) -> String {
        self.leaf
            .issuer_name()
            .entries()
            .map(|e| {
                let field = e.object().nid().short_name().unwrap_or("?");
                // Lossy rather than `as_utf8`, which is deprecated for
                // truncating at an interior NUL.
                let value = String::from_utf8_lossy(e.data().as_slice());
                format!("{field}={value}")
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[derive(Debug)]
pub enum CertError {
    Parse(openssl::error::ErrorStack),
    NoCerts,
    Io(std::io::Error),
    BadHostname(String),
    KeyMismatch,
    ReadOnly,
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "could not parse PEM: {e}"),
            Self::NoCerts => write!(f, "PEM contained no certificates"),
            Self::Io(e) => write!(f, "{e}"),
            Self::BadHostname(h) => write!(f, "unusable hostname {h:?}"),
            Self::KeyMismatch => write!(f, "certificate and private key do not match"),
            Self::ReadOnly => write!(f, "certificate store is a read-only memory view"),
        }
    }
}

impl std::error::Error for CertError {}

/// One hostname's certificate state, as the admin API reports it.
#[derive(Serialize)]
pub struct CertStatus {
    pub host: String,
    pub not_after: String,
    pub issuer: String,
    pub needs_renewal: bool,
}

/// Serializable TLS state sent from the manager to forwarding workers.
///
/// Deliberately opaque and not `Debug`: it contains private key PEM.
#[derive(Serialize, Deserialize)]
pub struct CertSnapshot {
    certs: HashMap<String, SnapshotCert>,
    fallback: Option<SnapshotCert>,
}

#[derive(Serialize, Deserialize)]
struct SnapshotCert {
    #[serde(with = "pem_text")]
    chain_pem: Vec<u8>,
    #[serde(with = "pem_text")]
    key_pem: Vec<u8>,
}

/// PEM is ASCII, so it travels as a JSON string. As a `Vec<u8>` it became an
/// array of decimal numbers, ~3.5 bytes on the wire per PEM byte, and 63
/// certificates outgrew the worker frame limit. Arrays are still read.
mod pem_text {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(pem: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        let text = std::str::from_utf8(pem).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(text)
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Pem {
        Text(String),
        Bytes(Vec<u8>),
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        Ok(match Pem::deserialize(deserializer)? {
            Pem::Text(text) => text.into_bytes(),
            Pem::Bytes(bytes) => bytes,
        })
    }
}

struct CertView {
    certs: HashMap<String, Arc<CertifiedKey>>,
    fallback: Option<Arc<CertifiedKey>>,
}

enum StoreBacking {
    /// `<host>.crt.pem` and `<host>.key.pem`, both `0600` in a `0700`
    /// directory, on disk.
    Disk {
        chains: Arc<dyn Collection>,
        keys: Arc<dyn Collection>,
    },
    MemoryOnly,
}

/// Hostname -> certificate, swapped wholesale on update.
///
/// Same copy-on-write shape as [`Registry`](crate::registry::Registry): readers
/// (every TLS handshake) take a lock-free `ArcSwap` load, and the rare writer
/// clones the map. Cert issuance is far rarer than handshakes, so the clone
/// costs nothing that matters.
pub struct CertStore {
    view: ArcSwap<CertView>,
    backing: StoreBacking,
}

impl CertStore {
    pub fn new(dir: impl Into<PathBuf>, fallback: Option<Arc<CertifiedKey>>) -> Self {
        let dir = dir.into();
        let opts = FileOptions::PRIVATE.private_dir(0o700);
        Self::with_collections(
            Arc::new(FileCollection::new(&dir, ".crt.pem", opts)),
            Arc::new(FileCollection::new(&dir, ".key.pem", opts)),
            fallback,
        )
    }

    /// The same store over other backends: certificate chains and private keys
    /// under the hostname.
    pub fn with_collections(
        chains: Arc<dyn Collection>,
        keys: Arc<dyn Collection>,
        fallback: Option<Arc<CertifiedKey>>,
    ) -> Self {
        Self {
            view: ArcSwap::from_pointee(CertView {
                certs: HashMap::new(),
                fallback,
            }),
            backing: StoreBacking::Disk { chains, keys },
        }
    }

    /// Construct a worker-side store which can only be updated by snapshots.
    pub fn from_snapshot(snapshot: CertSnapshot) -> Result<Self, CertError> {
        let view = parse_snapshot(snapshot)?;
        Ok(Self {
            view: ArcSwap::from_pointee(view),
            backing: StoreBacking::MemoryOnly,
        })
    }

    /// Export the complete live view, including every intermediate and fallback.
    pub fn snapshot(&self) -> Result<CertSnapshot, CertError> {
        let view = self.view.load();
        let certs = view
            .certs
            .iter()
            .map(|(host, cert)| Ok((host.clone(), snapshot_cert(cert)?)))
            .collect::<Result<_, CertError>>()?;
        let fallback = view.fallback.as_deref().map(snapshot_cert).transpose()?;
        Ok(CertSnapshot { certs, fallback })
    }

    /// Validate the entire replacement before atomically publishing it.
    pub fn replace_snapshot(&self, snapshot: CertSnapshot) -> Result<(), CertError> {
        if !matches!(&self.backing, StoreBacking::MemoryOnly) {
            return Err(CertError::ReadOnly);
        }
        let view = parse_snapshot(snapshot)?;
        self.view.store(Arc::new(view));
        Ok(())
    }

    /// Load a cert/key PEM pair from disk, for the static fallback.
    pub fn load_pair(cert_path: &str, key_path: &str) -> Result<CertifiedKey, CertError> {
        let chain = std::fs::read(cert_path).map_err(CertError::Io)?;
        let key = std::fs::read(key_path).map_err(CertError::Io)?;
        CertifiedKey::from_pem(&chain, &key)
    }

    /// The certificate for `host`, if one has been issued.
    ///
    /// On an exact miss, the parent domain is tried once — and its certificate
    /// is served **only if it really is a wildcard for that parent**. This is
    /// what makes a fleet of sandboxes possible: thousands of hostnames under
    /// `sb.example.com` are served by the one `*.sb.example.com` certificate,
    /// where per-host issuance would exhaust Let's Encrypt's 50-certificates-
    /// per-domain-per-week limit on the first afternoon.
    ///
    /// A wildcard covers exactly one label, so the parent is tried once and not
    /// walked up the whole domain — matching what the certificate actually
    /// asserts rather than being generous with somebody else's name.
    pub fn lookup(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        // SNI arrives in whatever case the client sent; routing lowercases
        // hostnames too (see `proxy::request_host`), so match that.
        let host = host.to_ascii_lowercase();
        let view = self.view.load();
        let certs = &view.certs;
        if let Some(cert) = certs.get(&host) {
            return Some(cert.clone());
        }
        let parent = host.split_once('.')?.1;
        certs
            .get(parent)
            .filter(|c| c.wildcard_of().as_deref() == Some(parent))
            .cloned()
    }

    /// Resolve SNI and fallback from one immutable view, so snapshot swaps can
    /// never combine certificates from two generations.
    fn resolve(&self, host: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let view = self.view.load();
        if let Some(host) = host {
            let host = host.to_ascii_lowercase();
            if let Some(cert) = view.certs.get(&host) {
                return Some(cert.clone());
            }
            if let Some(parent) = host.split_once('.').map(|(_, parent)| parent) {
                if let Some(cert) = view
                    .certs
                    .get(parent)
                    .filter(|c| c.wildcard_of().as_deref() == Some(parent))
                {
                    return Some(cert.clone());
                }
            }
        }
        view.fallback.clone()
    }

    /// Hosts whose cert is missing or inside the renewal window.
    pub fn needing_renewal<'a>(&self, wanted: impl Iterator<Item = &'a str>) -> Vec<String> {
        let view = self.view.load();
        let certs = &view.certs;
        wanted
            .map(|h| h.to_ascii_lowercase())
            .filter(|h| certs.get(h).is_none_or(|c| c.needs_renewal()))
            .collect()
    }

    /// Install a certificate and persist it.
    ///
    /// The disk write happens first so a restart sees what is being served, but
    /// a write failure is logged rather than fatal: serving the cert until the
    /// next restart beats not serving it at all.
    pub fn insert(&self, host: &str, chain_pem: &[u8], key_pem: &[u8]) -> Result<(), CertError> {
        if !matches!(&self.backing, StoreBacking::Disk { .. }) {
            return Err(CertError::ReadOnly);
        }
        let host = normalize_host(host)?;
        let cert = Arc::new(CertifiedKey::from_pem(chain_pem, key_pem)?);

        if let Err(e) = self.persist(&host, chain_pem, key_pem) {
            tracing::error!(%host, error = %e, "could not persist certificate; it will be lost on restart");
        }

        self.view.rcu(|current| {
            let mut certs = current.certs.clone();
            certs.insert(host.clone(), cert.clone());
            CertView {
                certs,
                fallback: current.fallback.clone(),
            }
        });
        Ok(())
    }

    /// Write-then-rename, so a crash mid-write can't leave a truncated cert that
    /// would fail to parse on the next boot. Same approach as
    /// [`Registry::persist`](crate::registry::Registry::persist).
    fn persist(&self, host: &str, chain_pem: &[u8], key_pem: &[u8]) -> std::io::Result<()> {
        let StoreBacking::Disk { chains, keys } = &self.backing else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "certificate store is memory-only",
            ));
        };
        chains.put(host, chain_pem, Expect::Any)?;
        keys.put(host, key_pem, Expect::Any)?;
        Ok(())
    }

    /// Populate the store from `dir`. Must run before the listener binds, or a
    /// cold start serves the fallback for hostnames whose cert is already on
    /// disk. Returns how many loaded; a bad pair is skipped, not fatal, so one
    /// corrupt file can't keep the proxy from starting.
    pub fn load_from_disk(&self) -> usize {
        let StoreBacking::Disk { chains, keys } = &self.backing else {
            return 0;
        };
        // A directory that does not exist yet lists empty: a normal first run.
        let entries = match chains.list() {
            Ok(e) => e,
            Err(e) => {
                tracing::error!(dir = %chains.location(""), error = %e, "could not read cert directory");
                return 0;
            }
        };

        let mut loaded = HashMap::new();
        for entry in entries {
            let Ok(host) = normalize_host(&entry.key) else {
                tracing::warn!(file = %entry.location, "skipping cert with unusable hostname");
                continue;
            };

            let pair = entry.body.map_err(CertError::Io).and_then(|chain| {
                let key = keys.get(&host).map_err(CertError::Io)?.ok_or_else(|| {
                    CertError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("no private key at {}", keys.location(&host)),
                    ))
                })?;
                CertifiedKey::from_pem(&chain, &key.0)
            });
            match pair {
                Ok(cert) => {
                    loaded.insert(host, Arc::new(cert));
                }
                Err(e) => tracing::warn!(%host, error = %e, "skipping unreadable certificate"),
            }
        }

        let count = loaded.len();
        if count > 0 {
            self.view.rcu(|current| CertView {
                certs: loaded.clone(),
                fallback: current.fallback.clone(),
            });
        }
        count
    }

    pub fn status(&self) -> Vec<CertStatus> {
        let mut out: Vec<_> = self
            .view
            .load()
            .certs
            .iter()
            .map(|(host, c)| CertStatus {
                host: host.clone(),
                not_after: c.not_after(),
                issuer: c.issuer(),
                needs_renewal: c.needs_renewal(),
            })
            .collect();
        out.sort_by(|a, b| a.host.cmp(&b.host));
        out
    }
}

fn snapshot_cert(cert: &CertifiedKey) -> Result<SnapshotCert, CertError> {
    let mut chain_pem = cert.leaf.to_pem().map_err(CertError::Parse)?;
    for intermediate in &cert.chain {
        chain_pem.extend(intermediate.to_pem().map_err(CertError::Parse)?);
    }
    let key_pem = cert
        .key
        .private_key_to_pem_pkcs8()
        .map_err(CertError::Parse)?;
    Ok(SnapshotCert { chain_pem, key_pem })
}

fn parse_snapshot(snapshot: CertSnapshot) -> Result<CertView, CertError> {
    let mut certs = HashMap::with_capacity(snapshot.certs.len());
    for (host, pem) in snapshot.certs {
        let host = normalize_host(&host)?;
        let cert = Arc::new(CertifiedKey::from_pem(&pem.chain_pem, &pem.key_pem)?);
        certs.insert(host, cert);
    }
    let fallback = snapshot
        .fallback
        .map(|pem| CertifiedKey::from_pem(&pem.chain_pem, &pem.key_pem).map(Arc::new))
        .transpose()?;
    Ok(CertView { certs, fallback })
}

/// Lowercase a hostname and reject anything that could escape the cert
/// directory. Hostnames reach this from deployment specs, which are attacker-
/// adjacent input, and they are used to build filenames.
fn normalize_host(host: &str) -> Result<String, CertError> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let usable = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        && !host.contains("..");
    if usable {
        Ok(host)
    } else {
        Err(CertError::BadHostname(host))
    }
}

/// Private keys are written `0600`. The ACME directory itself should be `0700`;
/// this is the per-file backstop in case it isn't. Also used for the ACME
/// account key, which is every bit as sensitive.
#[cfg(unix)]
pub(crate) fn restrict(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
pub(crate) fn restrict(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Create a directory `0700`, since everything app-lb puts under the ACME
/// directory is either a private key or the account key. `create_dir_all` alone
/// would use the umask, which is typically world-readable.
pub(crate) fn create_dir_private(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Supplies the certificate mid-handshake, keyed on SNI.
///
/// A newtype rather than an impl on `Arc<CertStore>` directly, which the orphan
/// rule forbids (`Arc` is not a fundamental type).
pub struct SniResolver(Arc<CertStore>);

impl SniResolver {
    pub fn new(store: Arc<CertStore>) -> Self {
        Self(store)
    }
}

#[async_trait]
impl TlsAccept for SniResolver {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        // Owned, because `servername` borrows from `ssl` and everything below
        // needs it mutably.
        let sni = ssl.servername(NameType::HOST_NAME).map(str::to_string);
        let cert = self.0.resolve(sni.as_deref());

        let Some(cert) = cert else {
            // Nothing to offer. Returning without installing a cert fails the
            // handshake, which is the honest outcome — better than serving a
            // certificate for the wrong name.
            tracing::debug!(sni = ?sni, "no certificate for SNI; failing handshake");
            return;
        };

        if let Err(e) = ext::ssl_use_certificate(ssl, &cert.leaf) {
            tracing::error!(sni = ?sni, error = %e, "could not install leaf certificate");
            return;
        }
        if let Err(e) = ext::ssl_use_private_key(ssl, &cert.key) {
            tracing::error!(sni = ?sni, error = %e, "could not install private key");
            return;
        }
        for intermediate in &cert.chain {
            if let Err(e) = ext::ssl_add_chain_cert(ssl, intermediate) {
                // Not fatal: clients that already have the intermediate cached
                // still validate. Log it, because the ones that don't will see
                // an untrusted-issuer error that is otherwise hard to explain.
                tracing::warn!(sni = ?sni, error = %e, "could not add intermediate to chain");
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A self-signed cert/key pair valid for `days`, as PEM.
    pub(crate) fn self_signed(host: &str, days: u32) -> (Vec<u8>, Vec<u8>) {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Name, X509};

        let rsa = Rsa::generate(2048).unwrap();
        let key = PKey::from_rsa(rsa).unwrap();

        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_text("CN", host).unwrap();
        let name = name.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(days).unwrap())
            .unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();

        (
            builder.build().to_pem().unwrap(),
            key.private_key_to_pem_pkcs8().unwrap(),
        )
    }

    /// A self-signed cert covering `domain` *and* `*.domain`, the shape ACME
    /// returns for a wildcard order.
    fn self_signed_wildcard(domain: &str, days: u32) -> (Vec<u8>, Vec<u8>) {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::extension::SubjectAlternativeName;
        use openssl::x509::{X509Name, X509};

        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_text("CN", domain).unwrap();
        let name = name.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        builder.set_not_after(&Asn1Time::days_from_now(days).unwrap()).unwrap();
        let san = SubjectAlternativeName::new()
            .dns(domain)
            .dns(&format!("*.{domain}"))
            .build(&builder.x509v3_context(None, None))
            .unwrap();
        builder.append_extension(san).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();

        (
            builder.build().to_pem().unwrap(),
            key.private_key_to_pem_pkcs8().unwrap(),
        )
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("app-lb-tls-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// One wildcard certificate serving thousands of sandbox hostnames is the
    /// whole reason a fleet is possible; per-host issuance hits Let's Encrypt's
    /// weekly cap immediately.
    #[test]
    fn a_wildcard_cert_serves_any_single_label_beneath_it() {
        let dir = tmpdir("wildcard-lookup");
        let store = CertStore::new(&dir, None);
        let (chain, key) = self_signed_wildcard("sb.example.com", 60);
        store.insert("sb.example.com", &chain, &key).unwrap();

        assert!(store.lookup("sb.example.com").is_some(), "the apex itself");
        assert!(store.lookup("sb-7f3a9c.sb.example.com").is_some());
        assert!(store.lookup("ANYTHING.SB.EXAMPLE.COM").is_some(), "SNI case varies");
        // A wildcard covers exactly one label.
        assert!(store.lookup("a.b.sb.example.com").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The fallback must consult what the certificate actually asserts. A plain
    /// cert for a parent domain must never be served for a subdomain: the
    /// client would reject it on the name, and the failure would look like a
    /// broken LB rather than a missing certificate.
    #[test]
    fn a_plain_parent_cert_is_never_served_for_a_subdomain() {
        let dir = tmpdir("no-wildcard-lookup");
        let store = CertStore::new(&dir, None);
        let (chain, key) = self_signed("example.com", 60);
        store.insert("example.com", &chain, &key).unwrap();

        assert!(store.lookup("example.com").is_some());
        assert!(
            store.lookup("app.example.com").is_none(),
            "no `*.` SAN, so it covers nothing below itself",
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lookup_hits_exact_host_case_insensitively() {
        let dir = tmpdir("lookup");
        let store = CertStore::new(&dir, None);
        let (crt, key) = self_signed("app.example.com", 90);
        store.insert("app.example.com", &crt, &key).unwrap();

        assert!(store.lookup("app.example.com").is_some());
        assert!(store.lookup("APP.Example.COM").is_some(), "SNI case varies");
        assert!(store.lookup("other.example.com").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn miss_falls_back_when_configured() {
        let dir = tmpdir("fallback");
        let (crt, key) = self_signed("fallback.example.com", 90);
        let fallback = Arc::new(CertifiedKey::from_pem(&crt, &key).unwrap());

        let with = CertStore::new(&dir, Some(fallback));
        assert!(with.lookup("nothing.example.com").is_none());
        assert!(with.resolve(Some("nothing.example.com")).is_some());

        let without = CertStore::new(&dir, None);
        assert!(without.resolve(Some("nothing.example.com")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_preserves_sni_wildcard_full_chain_and_fallback() {
        let dir = tmpdir("snapshot");
        let (leaf, key) = self_signed_wildcard("sb.example.com", 60);
        let (intermediate, _) = self_signed("intermediate.example.com", 90);
        let mut chain = leaf;
        chain.extend(intermediate);
        let (fallback_pem, fallback_key) = self_signed("fallback.example.com", 90);
        let fallback = Arc::new(CertifiedKey::from_pem(&fallback_pem, &fallback_key).unwrap());
        let manager = CertStore::new(&dir, Some(fallback));
        manager.insert("sb.example.com", &chain, &key).unwrap();

        let worker = CertStore::from_snapshot(manager.snapshot().unwrap()).unwrap();
        let wildcard = worker.lookup("one.sb.example.com").unwrap();
        assert_eq!(wildcard.chain.len(), 1, "the full chain is transferred");
        assert_eq!(wildcard.leaf.to_pem().unwrap(), X509::stack_from_pem(&chain).unwrap()[0].to_pem().unwrap());
        assert!(worker.lookup("two.levels.sb.example.com").is_none());
        assert_eq!(worker.resolve(Some("unknown.example.com")).unwrap().leaf.to_pem().unwrap(), fallback_pem);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_replacement_removes_stale_hosts_and_fallback() {
        let dir = tmpdir("snapshot-replace");
        let (old_crt, old_key) = self_signed("old.example.com", 90);
        let manager = CertStore::new(&dir, Some(Arc::new(CertifiedKey::from_pem(&old_crt, &old_key).unwrap())));
        manager.insert("old.example.com", &old_crt, &old_key).unwrap();
        let worker = CertStore::from_snapshot(manager.snapshot().unwrap()).unwrap();
        assert!(worker.resolve(Some("unknown.example.com")).is_some());

        let other_dir = tmpdir("snapshot-replace-other");
        let (new_crt, new_key) = self_signed("new.example.com", 90);
        let replacement = CertStore::new(&other_dir, None);
        replacement.insert("new.example.com", &new_crt, &new_key).unwrap();
        worker.replace_snapshot(replacement.snapshot().unwrap()).unwrap();

        assert!(worker.lookup("old.example.com").is_none());
        assert!(worker.lookup("new.example.com").is_some());
        assert!(worker.resolve(Some("unknown.example.com")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&other_dir);
    }

    #[test]
    fn snapshot_pem_travels_as_text_and_legacy_arrays_still_parse() {
        let dir = tmpdir("snapshot-wire");
        let (crt, key) = self_signed("wire.example.com", 90);
        let manager = CertStore::new(&dir, None);
        manager.insert("wire.example.com", &crt, &key).unwrap();
        let wire = serde_json::to_vec(&manager.snapshot().unwrap()).unwrap();
        assert!(wire.len() < (crt.len() + key.len()) * 3 / 2, "{} bytes on the wire", wire.len());

        let legacy = serde_json::json!({
            "certs": { "wire.example.com": { "chain_pem": crt, "key_pem": key } },
            "fallback": null,
        });
        let worker = CertStore::from_snapshot(serde_json::from_value(legacy).unwrap()).unwrap();
        assert!(worker.lookup("wire.example.com").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_replacement_leaves_the_old_view_intact() {
        let dir = tmpdir("snapshot-corrupt");
        let (crt, key) = self_signed("old.example.com", 90);
        let manager = CertStore::new(&dir, None);
        manager.insert("old.example.com", &crt, &key).unwrap();
        let worker = CertStore::from_snapshot(manager.snapshot().unwrap()).unwrap();
        let mut corrupt = manager.snapshot().unwrap();
        corrupt.certs.get_mut("old.example.com").unwrap().chain_pem = b"not PEM".to_vec();

        assert!(worker.replace_snapshot(corrupt).is_err());
        assert!(worker.lookup("old.example.com").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn memory_only_store_refuses_insert_without_touching_disk() {
        let dir = tmpdir("memory-only");
        let manager = CertStore::new(&dir, None);
        let worker = CertStore::from_snapshot(manager.snapshot().unwrap()).unwrap();
        let (crt, key) = self_signed("new.example.com", 90);

        assert!(matches!(
            worker.insert("new.example.com", &crt, &key),
            Err(CertError::ReadOnly)
        ));
        assert_eq!(worker.load_from_disk(), 0);
        assert!(!dir.exists());
    }

    #[test]
    fn certs_round_trip_through_disk() {
        let dir = tmpdir("roundtrip");
        let (crt, key) = self_signed("persist.example.com", 90);
        {
            let store = CertStore::new(&dir, None);
            store.insert("persist.example.com", &crt, &key).unwrap();
        }

        // A fresh store over the same directory is what a restart sees.
        let reloaded = CertStore::new(&dir, None);
        assert_eq!(reloaded.load_from_disk(), 1);
        assert!(reloaded.lookup("persist.example.com").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn renewal_window_tracks_expiry() {
        let (fresh_crt, fresh_key) = self_signed("fresh.example.com", 90);
        let fresh = CertifiedKey::from_pem(&fresh_crt, &fresh_key).unwrap();
        assert!(!fresh.needs_renewal(), "90 days out is not due");

        let (old_crt, old_key) = self_signed("old.example.com", RENEW_BEFORE_DAYS - 1);
        let old = CertifiedKey::from_pem(&old_crt, &old_key).unwrap();
        assert!(old.needs_renewal(), "inside the window is due");
    }

    #[test]
    fn needing_renewal_includes_missing_hosts() {
        let dir = tmpdir("needing");
        let store = CertStore::new(&dir, None);
        let (crt, key) = self_signed("have.example.com", 90);
        store.insert("have.example.com", &crt, &key).unwrap();

        let due = store.needing_renewal(["have.example.com", "missing.example.com"].into_iter());
        assert_eq!(due, vec!["missing.example.com"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hostnames_that_could_escape_the_directory_are_rejected() {
        assert!(normalize_host("../../etc/shadow").is_err());
        assert!(normalize_host("a/b").is_err());
        assert!(normalize_host("").is_err());
        assert!(normalize_host("a..b").is_err());
        // Trailing dot is legal in DNS and must normalize, not fail.
        assert_eq!(normalize_host("App.Example.Com.").unwrap(), "app.example.com");
    }

    #[test]
    fn corrupt_cert_on_disk_is_skipped_not_fatal() {
        let dir = tmpdir("corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("broken.example.com.crt.pem"), b"not a pem").unwrap();
        std::fs::write(dir.join("broken.example.com.key.pem"), b"nope").unwrap();

        let (crt, key) = self_signed("good.example.com", 90);
        let store = CertStore::new(&dir, None);
        store.insert("good.example.com", &crt, &key).unwrap();

        let reloaded = CertStore::new(&dir, None);
        assert_eq!(reloaded.load_from_disk(), 1, "the good cert still loads");
        assert!(reloaded.lookup("good.example.com").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
