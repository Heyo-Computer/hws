//! A repository is a namespace of tags — `heyo/postgres` holds
//! `heyo/postgres:16` and `heyo/postgres:17` — and the unit the public hub
//! deals in.
//!
//! Its metadata is one small JSON file per repository (`repos/<name>.json`,
//! `/` spelled `~`). Nothing about a repository is load-bearing for the
//! content it names: deleting the file makes the repository private and
//! undescribed, and every tag in it still resolves. The tags *are* the
//! repository; this file is what a person has said about it.

use serde::{Deserialize, Serialize};

/// Longest description, matching a label's.
pub const MAX_DESCRIPTION: usize = 2000;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoMeta {
    /// Anyone may pull every tag in this repository — and the manifests and
    /// blobs those tags reach — without a credential, and the hub lists it.
    #[serde(default)]
    pub public: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Seconds since the epoch. Informational; the hub shows it.
    #[serde(default)]
    pub updated: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RepoError {
    #[error("description must be at most {MAX_DESCRIPTION} characters")]
    DescriptionTooLong,
}

impl RepoMeta {
    pub fn validate(&self) -> Result<(), RepoError> {
        if self
            .description
            .as_ref()
            .is_some_and(|d| d.chars().count() > MAX_DESCRIPTION)
        {
            return Err(RepoError::DescriptionTooLong);
        }
        Ok(())
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("RepoMeta always serializes")
    }

    /// Stamp `updated` with the wall clock.
    pub fn touched(mut self) -> RepoMeta {
        self.updated = crate::repos::now_unix();
        self
    }
}

pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_file_is_a_private_repository() {
        let m: RepoMeta = serde_json::from_slice(b"{}").unwrap();
        assert_eq!(m, RepoMeta::default());
        assert!(!m.public);
    }

    #[test]
    fn long_descriptions_are_refused() {
        let m = RepoMeta {
            description: Some("x".repeat(MAX_DESCRIPTION + 1)),
            ..Default::default()
        };
        assert!(m.validate().is_err());
    }
}
