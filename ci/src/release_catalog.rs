//! Immutable service releases with explicitly selected, validated artifacts.
//! Registration does not build, merge, deploy, or infer that every service was
//! built. Daily full-revision builds and environment promotion consume this
//! catalog separately; existing per-submit path filters are not full builds.
use crate::{store::Store, submission};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub workflow: String,
    pub artifact: String,
    pub job: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub name: String,
    pub publication_run_id: String,
    pub components: BTreeMap<String, Selection>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Artifact {
    pub id: String,
    pub run_id: String,
    pub job: String,
    pub workflow: String,
    pub name: String,
    pub sink: String,
    pub uri: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Manifest {
    pub version: u32,
    pub repository: String,
    pub revision: String,
    pub publication_run_id: String,
    pub components: BTreeMap<String, Artifact>,
}

fn name_valid(name: &str) -> bool {
    !name.is_empty() && name.len() <= 128
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn validate(request: &Request) -> Result<()> {
    ensure!(name_valid(&request.name), "release name requires 1-128 ASCII letters, digits, '.', '_' or '-'");
    ensure!(!request.publication_run_id.is_empty(), "publication run is required");
    ensure!(request.components.len() == 1,
        "select exactly one service; multi-service bundles are no longer supported");
    for (name, selection) in &request.components {
        ensure!(name_valid(name), "invalid component name");
        ensure!(!selection.workflow.trim().is_empty() && !selection.artifact.trim().is_empty()
            && !selection.job.trim().is_empty(), "each component requires workflow, artifact and producer job");
    }
    Ok(())
}

pub async fn register(store: &Store, request: Request, actor: &str) -> Result<serde_json::Value> {
    validate(&request)?;
    ensure!(submission::gate(store, &request.publication_run_id).await.map_err(anyhow::Error::msg)?
        == submission::Gate::Ready, "release requires a fully validated submission");
    let publication = sqlx::query(
        "SELECT r.repo_url,r.sha FROM ci_run r JOIN ci_release p ON p.run_id=r.id
         WHERE r.id=$1 AND r.status='success' AND p.status='published'
           AND p.candidate_sha=r.sha AND p.source_sha=r.sha AND NOT r.validation_only")
        .bind(&request.publication_run_id).fetch_optional(store.pool()).await?
        .ok_or_else(|| anyhow::anyhow!("release requires successful publication of the exact validated revision"))?;
    let repository: String = publication.get("repo_url");
    let mut manifest = Manifest { version: 1, repository: repository.clone(),
        revision: publication.get("sha"), publication_run_id: request.publication_run_id.clone(),
        components: BTreeMap::new() };
    for (component, selection) in &request.components {
        let artifact = submission::artifact(store, &request.publication_run_id,
            &selection.workflow, &selection.artifact, Some(&selection.job)).await.map_err(anyhow::Error::msg)?;
        ensure!(artifact.sink != "disk", "release artifacts must be in shared storage, not a runner-local disk");
        let run = submission::artifact_run(store, &request.publication_run_id, &selection.workflow)
            .await.map_err(anyhow::Error::msg)?;
        let id: String = sqlx::query_scalar(
            "SELECT a.id FROM ci_artifact a JOIN ci_job j ON j.id=a.job_id
             WHERE a.run_id=$1 AND a.name=$2 AND j.job_key=$3 AND j.status='success'
               AND a.digest=$4 AND a.uri=$5 AND a.size_bytes=$6 AND a.sink=$7")
            .bind(&run).bind(&selection.artifact).bind(&selection.job)
            .bind(&artifact.digest).bind(&artifact.uri).bind(artifact.size_bytes as i64)
            .bind(artifact.sink).fetch_one(store.pool()).await?;
        manifest.components.insert(component.clone(), Artifact { id, run_id: run,
            job: selection.job.clone(), workflow: selection.workflow.clone(), name: selection.artifact.clone(),
            sink: artifact.sink.into(), uri: artifact.uri,
            sha256: artifact.digest.expect("submission::artifact requires digest").to_lowercase(),
            size_bytes: artifact.size_bytes });
    }
    let value = serde_json::to_value(&manifest)?;
    let digest = hex::encode(Sha256::digest(serde_json::to_vec(&value)?));
    let mut tx = store.pool().begin().await?;
    let proposed_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO ci_release_bundle(id,repository,name,publication_run_id,manifest,manifest_sha256,created_by)
        VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(repository,name) DO NOTHING")
        .bind(&proposed_id).bind(&repository).bind(&request.name).bind(&request.publication_run_id)
        .bind(&value).bind(&digest).bind(actor).execute(&mut *tx).await?;
    let row = sqlx::query("SELECT id,manifest FROM ci_release_bundle WHERE repository=$1 AND name=$2")
        .bind(&repository).bind(&request.name).fetch_one(&mut *tx).await?;
    ensure!(row.get::<serde_json::Value,_>("manifest") == value,
        "release name already identifies different immutable contents; choose another name");
    let id: String = row.get("id");
    for (component, artifact) in &manifest.components {
        sqlx::query("INSERT INTO ci_release_bundle_artifact(bundle_id,component,artifact_id)
            VALUES($1,$2,$3) ON CONFLICT(bundle_id,component) DO NOTHING")
            .bind(&id).bind(component).bind(&artifact.id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(serde_json::json!({"id":id,"name":request.name,"manifest_sha256":digest,"manifest":value}))
}

pub(crate) async fn refresh_pr(d: &crate::dispatch::Dispatcher) -> Result<()> {
    // One bounded lookup per tick, cached outside the immutable manifest.
    // Never call GitHub on the page read path.
    let row = sqlx::query("UPDATE ci_release_bundle SET pr_checked_at=now() WHERE id=(
        SELECT id FROM ci_release_bundle WHERE latest_pr IS NULL
        AND (pr_checked_at IS NULL OR pr_checked_at < now()-interval '1 day')
        ORDER BY created_at DESC,id DESC LIMIT 1 FOR UPDATE SKIP LOCKED)
        RETURNING id,repository,manifest->>'revision' AS revision")
        .fetch_optional(d.store.pool()).await?;
    let Some(row) = row else { return Ok(()); };
    let repository: String = row.get("repository");
    let url = reqwest::Url::parse(&repository)?;
    if url.scheme() != "https" || url.host_str() != Some("github.com") { return Ok(()); }
    let path = url.path().trim_matches('/').trim_end_matches(".git");
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() != 2 || parts.iter().any(|p| p.is_empty()
        || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))) { return Ok(()); }
    let revision: String = row.get("revision");
    if revision.len() != 40 || !revision.bytes().all(|b| b.is_ascii_hexdigit()) { return Ok(()); }
    let policies = crate::release_build::policies(d.config.release_builds.as_deref())?;
    let Some((_, policy)) = policies.iter().find(|(repo,_)| crate::repos::same_repo(repo,&repository)) else { return Ok(()); };
    let resolved = d.secrets.resolve(&crate::secrets::Secrets::prefix(&policy.workflow_id,"default")).await?;
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() < 3 && attempt.url().scheme() == "https"
                && attempt.url().host_str() == Some("api.github.com") {
                attempt.follow()
            } else { attempt.stop() }
        })).build()?;
    let mut request = client.get(format!("https://api.github.com/repos/{path}/commits/{revision}/pulls?per_page=100"))
        .header("User-Agent","heyo-ci").header("Accept","application/vnd.github+json");
    if let Some(token) = resolved.secrets.get("CI_GIT_AUTH_TOKEN").or_else(|| resolved.secrets.get("GITHUB_TOKEN")) {
        request = request.bearer_auth(token);
    }
    let response = request.send().await?;
    ensure!(response.status().is_success(), "PR metadata lookup returned {}", response.status());
    let pulls: Vec<serde_json::Value> = response.json().await?;
    if let Some(pr) = pulls.iter().filter(|p| p["merged_at"].is_string()).max_by_key(|p| p["merged_at"].as_str()) {
        let value = serde_json::json!({"number":pr["number"],"title":pr["title"],"url":pr["html_url"]});
        sqlx::query("UPDATE ci_release_bundle SET latest_pr=$2 WHERE id=$1")
            .bind(row.get::<String,_>("id")).bind(value).execute(d.store.pool()).await?;
    }
    Ok(())
}

pub async fn list(store: &Store, before: Option<&str>) -> Result<Vec<serde_json::Value>> {
    // The ID disambiguates releases with the same timestamp without offsets.
    Ok(sqlx::query_scalar("SELECT to_jsonb(b) || jsonb_build_object('commit_message',
            (SELECT commit_message FROM ci_release_build WHERE id=b.build_id)) FROM ci_release_bundle b
        WHERE (SELECT count(*) FROM jsonb_object_keys(
            CASE WHEN jsonb_typeof(manifest->'components')='object'
            THEN manifest->'components' ELSE '{}'::jsonb END))=1
        AND ($1::text IS NULL OR (created_at,id) <
            (SELECT created_at,id FROM ci_release_bundle WHERE id=$1))
        ORDER BY created_at DESC,id DESC LIMIT 100")
        .bind(before).fetch_all(store.pool()).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_requires_explicit_provenance_not_urls_or_empty_bundles() {
        let mut request = Request { name: "2026-10-05.1".into(), publication_run_id: "published".into(),
            components: BTreeMap::new() };
        assert!(validate(&request).is_err());
        request.components.insert("cloud".into(), Selection { workflow: ".ci/cloud.yml".into(),
            artifact: "cloud-linux".into(), job: "build-linux".into() });
        assert!(validate(&request).is_ok());
        request.components.insert("auth".into(), Selection { workflow: ".ci/auth.yml".into(),
            artifact: "auth-linux".into(), job: "build-linux".into() });
        assert!(validate(&request).unwrap_err().to_string().contains("exactly one service"));
        request.components.remove("auth");
        request.components.get_mut("cloud").unwrap().job.clear();
        assert!(validate(&request).is_err());
        assert!(serde_json::from_value::<Selection>(serde_json::json!({
            "workflow":"build", "artifact":"binary", "job":"build", "uri":"https://untrusted/binary"
        })).is_err());
    }
}
