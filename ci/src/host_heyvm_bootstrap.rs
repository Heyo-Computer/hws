//! Phase-one host heyvm bootstrap recipe. Deliberately not registered as a CI
//! action yet; tests compile and pin the launcher contract for phase two.
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use sha2::{Digest, Sha256};

const INSTALLER: &str = include_str!("host_heyvm_bootstrap.py");
const MAX_ARTIFACT: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Artifact {
    pub operation_id: String,
    pub artifact_url: String,
    pub artifact_sha256: String,
    pub artifact_size: u64,
    pub inner_path: String,
    pub inner_archive_sha256: String,
    pub heyvm_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
}

#[cfg(test)]
fn digest(value: &[u8]) -> String { hex::encode(Sha256::digest(value)) }

pub(crate) fn recipe(mapping_json: &str, target_alias: &str, artifact: &Artifact) -> Result<String> {
    command(mapping_json, target_alias, artifact, false)
}

pub(crate) fn verification_recipe(mapping_json: &str, target_alias: &str, artifact: &Artifact) -> Result<String> {
    command(mapping_json, target_alias, artifact, true)
}

fn command(mapping_json: &str, target_alias: &str, artifact: &Artifact, verify_only: bool) -> Result<String> {
    ensure!(artifact.artifact_size > 0 && artifact.artifact_size <= MAX_ARTIFACT, "artifact size is outside bound");
    ensure!(artifact.artifact_url.starts_with("https://"), "artifact URL requires HTTPS");
    ensure!([&artifact.artifact_sha256, &artifact.inner_archive_sha256, &artifact.heyvm_sha256]
        .iter().all(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())), "invalid artifact digest");
    ensure!(!mapping_json.is_empty() && mapping_json.len() <= 64 * 1024 && !target_alias.is_empty() && target_alias.len() <= 128,
        "mapping or alias exceeds launcher bound");
    let envelope = serde_json::json!({"mapping_json":mapping_json,"target_alias":target_alias,"request":artifact,"verify_only":verify_only});
    let input = STANDARD.encode(serde_json::to_vec(&envelope)?);
    let script = STANDARD.encode(INSTALLER);
    let command = format!("python3 -c \"import base64;exec(base64.b64decode('{}'))\" '{}'", script, input);
    ensure!(command.len() <= 256 * 1024, "launcher recipe exceeds bound");
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> Artifact { Artifact { operation_id:"op-1".into(), artifact_url:"https://art.example/blob".into(),
        artifact_sha256:"a".repeat(64), artifact_size:42, inner_path:"validation/heyvm.tar.gz".into(),
        inner_archive_sha256:"b".repeat(64), heyvm_sha256:"c".repeat(64), download_token:None, component:None } }

    #[test]
    fn recipe_is_bounded_secret_free_deterministic_and_does_not_embed_executable() {
        let mapping = r#"{"eu1":{"repository":"https://github.com/Heyo-Computer/heyo.git"}}"#;
        let a = recipe(mapping,"eu1",&artifact()).unwrap();
        assert_eq!(a, recipe(mapping,"eu1",&artifact()).unwrap());
        assert!(a.len() < 256 * 1024 && !a.contains("Authorization") && !a.contains("token"));
        assert!(!a.contains("\x7fELF"));
        let encoded = a.rsplit_once(" '").unwrap().1.trim_end_matches('\'');
        let value: serde_json::Value = serde_json::from_slice(&STANDARD.decode(encoded).unwrap()).unwrap();
        assert!(value["request"].get("executable").is_none());
        assert_eq!(value["request"]["artifact_size"],42);
        assert_eq!(value["request"]["inner_archive_sha256"],"b".repeat(64));
    }

    #[test]
    fn artifact_metadata_is_closed_and_bounded() {
        let mut value=serde_json::to_value(artifact()).unwrap(); value["executable"]=serde_json::json!("bad");
        assert!(serde_json::from_value::<Artifact>(value).is_err());
        let mut a=artifact(); a.artifact_size=MAX_ARTIFACT+1; assert!(recipe("{}","x",&a).is_err());
        let mut a=artifact(); a.artifact_url="http://art.example".into(); assert!(recipe("{}","x",&a).is_err());
        let mut a=artifact(); a.heyvm_sha256="A".repeat(64); assert!(recipe("{}","x",&a).is_err());
        assert_eq!(digest(INSTALLER.as_bytes()).len(),64);
    }
}
