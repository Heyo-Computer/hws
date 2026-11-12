//! Operator-authorized, read-only import of namespace CI release artifacts.
//! The source CI proves execution; Git proves the executed tree was merged.
//! The destination artifact store proves and retains the bytes before publication.
use crate::{artifacts::StoredArtifact, dispatch::Dispatcher};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub api_url: String,
    /// Key in the destination's existing workflow/default HeyoSecret scope.
    pub token_secret: String,
    pub repository: String,
    pub namespace: String,
    pub workflow: String,
    pub job: String,
    pub artifact: String,
    pub services: Vec<String>,
}

pub fn policies(raw: Option<&str>) -> Result<BTreeMap<String, Policy>> {
    let entries: BTreeMap<String, Policy> = match raw {
        Some(raw) => serde_yaml::from_str(raw)?,
        None => return Ok(BTreeMap::new()),
    };
    for (name, p) in &entries {
        ensure!(
            identifier(name) && identifier(&p.namespace),
            "invalid import identity"
        );
        let url = reqwest::Url::parse(&p.api_url)?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "import requires a trusted HTTPS API URL"
        );
        ensure!(
            !p.token_secret.is_empty()
                && !p.repository.is_empty()
                && !p.workflow.is_empty()
                && !p.job.is_empty()
                && !p.artifact.is_empty()
                && !p.services.is_empty()
                && p.services.iter().all(|s| identifier(s)),
            "import selection must be explicit"
        );
    }
    Ok(entries)
}

fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
}

/// Keyset pagination also finds successful builds merged after newer runs finish.
pub async fn candidates(
    store: &crate::store::Store,
    namespace: &str,
    repository: &str,
    workflow: &str,
    before: Option<&str>,
) -> Result<Value> {
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM ci_run
        WHERE namespace=$1 AND repo_url=$2 AND workflow_path=$3 AND status='success'
        AND ($4::text IS NULL OR (created_at,id) <
            (SELECT created_at,id FROM ci_run WHERE id=$4 AND namespace=$1))
        ORDER BY created_at DESC,id DESC LIMIT 100",
    )
    .bind(namespace)
    .bind(repository)
    .bind(workflow)
    .bind(before)
    .fetch_all(store.pool())
    .await?;
    Ok(json!({"next":if ids.len() == 100 { ids.last() } else { None },"runs":ids}))
}

/// This receipt is available only through the existing namespace read gate.
pub async fn receipt(store: &crate::store::Store, namespace: &str, run_id: &str) -> Result<Value> {
    let run = store
        .get_run_in(namespace, run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("run not found"))?;
    ensure!(
        run.status == "success" && run.finished_at.is_some(),
        "run is not successful"
    );
    let jobs = store.jobs_of(run_id).await?;
    ensure!(
        !jobs.is_empty() && jobs.iter().all(|j| j.status == "success"),
        "release export requires every job to succeed"
    );
    let rows = sqlx::query(
        "SELECT a.id,a.name,a.sink,a.digest,a.size_bytes,a.uri,j.job_key
        FROM ci_artifact a JOIN ci_job j ON j.id=a.job_id
        WHERE a.run_id=$1 AND j.status='success' ORDER BY a.id",
    )
    .bind(run_id)
    .fetch_all(store.pool())
    .await?;
    let artifacts: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id":r.get::<String,_>("id"), "name":r.get::<String,_>("name"),
                "job":r.get::<String,_>("job_key"), "sink":r.get::<String,_>("sink"),
                "sha256":r.get::<Option<String>,_>("digest"),
                "size_bytes":r.get::<i64,_>("size_bytes"), "uri":r.get::<String,_>("uri")
            })
        })
        .collect();
    Ok(json!({"version":1,"namespace":namespace,"run_id":run_id,
        "repository":run.repo_url,"workflow":run.workflow_path,"revision":run.sha,
        "created_at":run.created_at,"status":"success",
        "source":store.source_descriptor(run_id).await?,"artifacts":artifacts}))
}

fn selected<'a>(p: &Policy, run: &str, receipt: &'a Value) -> Result<&'a Value> {
    ensure!(
        receipt["version"] == 1
            && receipt["namespace"] == p.namespace
            && receipt["run_id"] == run
            && receipt["repository"] == p.repository
            && receipt["workflow"] == p.workflow
            && receipt["status"] == "success",
        "remote receipt does not match trusted source selection"
    );
    let artifacts = receipt["artifacts"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("missing artifact receipts"))?;
    let matches: Vec<_> = artifacts
        .iter()
        .filter(|a| a["name"] == p.artifact && a["job"] == p.job)
        .collect();
    ensure!(
        matches.len() == 1,
        "release artifact producer must be unique"
    );
    let a = matches[0];
    ensure!(
        a["sink"] == "artifacts"
            && a["sha256"]
                .as_str()
                .is_some_and(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit()))
            && a["size_bytes"].as_u64().is_some_and(|n| n > 0)
            && a["uri"].as_str().is_some_and(|s| !s.is_empty()),
        "artifact is not verifiable shared storage"
    );
    Ok(a)
}

async fn read(client: &reqwest::Client, url: String, token: &str) -> Result<Value> {
    let mut response = client
        .get(url)
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 64 * 1024 * 1024,
            "import response too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

pub async fn reconcile(d: &Dispatcher) -> Result<()> {
    let imports = policies(d.config.release_imports.as_deref())?;
    if imports.is_empty() {
        return Ok(());
    }
    ensure!(
        d.artifacts.kind() == "artifacts",
        "release import requires retained artifact storage"
    );
    let builds = crate::release_build::policies(d.config.release_builds.as_deref())?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    for (name, p) in imports {
        let build = builds
            .get(&p.repository)
            .ok_or_else(|| anyhow::anyhow!("import repository has no release build policy"))?;
        ensure!(
            p.services.iter().all(|s| build.components.contains_key(s)),
            "import service is not configured"
        );
        let secrets = d
            .secrets
            .resolve(&crate::secrets::Secrets::prefix(
                &build.workflow_id,
                "default",
            ))
            .await?;
        let token = secrets
            .secrets
            .get(&p.token_secret)
            .ok_or_else(|| anyhow::anyhow!("import read credential is missing"))?;
        let base = p.api_url.trim_end_matches('/');
        let mut before: Option<String> = None;
        loop {
            let mut url = reqwest::Url::parse(&format!("{base}/release-artifacts"))?;
            url.query_pairs_mut()
                .append_pair("repository", &p.repository)
                .append_pair("workflow", &p.workflow);
            if let Some(before) = &before {
                url.query_pairs_mut().append_pair("before", before);
            }
            let runs = read(&client, url.into(), token).await?;
            for run in runs["runs"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("missing source runs"))?
            {
                let id = run
                    .as_str()
                    .filter(|s| identifier(s))
                    .ok_or_else(|| anyhow::anyhow!("invalid source run ID"))?;
                let mut receipt = None;
                for service in &p.services {
                    let import_id = format!(
                        "import-{:x}",
                        Sha256::digest(serde_json::to_vec(&json!([name, p, service, id]))?)
                    );
                    let exists: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM ci_release_import WHERE build_id=$1)",
                    )
                    .bind(&import_id)
                    .fetch_one(d.store.pool())
                    .await?;
                    if exists {
                        continue;
                    }
                    if receipt.is_none() {
                        match read(&client, format!("{base}/runs/{id}/release-artifact"), token)
                            .await
                        {
                            Ok(value) => receipt = Some(value),
                            Err(error) => {
                                tracing::warn!(source=%name,run=%id,%error,"release receipt unavailable");
                                break;
                            }
                        }
                    }
                    if let Err(error) = import(
                        d,
                        &p,
                        service,
                        &import_id,
                        id,
                        receipt.as_ref().unwrap(),
                        build,
                        secrets
                            .secrets
                            .get("CI_GIT_AUTH_TOKEN")
                            .or_else(|| secrets.secrets.get("GITHUB_TOKEN"))
                            .map(String::as_str)
                            .unwrap_or(""),
                    )
                    .await
                    {
                        // Unmerged successful builds remain ineligible; a later poll can admit them after merge.
                        tracing::warn!(source=%name,run=%id,service,%error,"release artifact import deferred");
                    }
                }
            }
            let Some(next) = runs["next"].as_str() else {
                break;
            };
            ensure!(
                identifier(next) && before.as_deref() != Some(next),
                "invalid source pagination cursor"
            );
            before = Some(next.to_string());
        }
    }
    Ok(())
}

async fn import(
    d: &Dispatcher,
    p: &Policy,
    service: &str,
    id: &str,
    run: &str,
    receipt: &Value,
    build: &crate::release_build::Policy,
    git_token: &str,
) -> Result<()> {
    selected(p, run, receipt)?;
    let revision = receipt["revision"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing revision"))?;
    let source = crate::release_git::build_source(
        &p.repository,
        &build.git_ref,
        Some(revision),
        &[p.workflow.clone()],
        git_token,
        d.config.max_source_bytes,
    )
    .await
    .map_err(anyhow::Error::msg)?;
    publish(
        &d.store,
        d.artifacts.as_ref(),
        p,
        service,
        id,
        run,
        receipt,
        build,
        &source,
    )
    .await
}

/// Publish only after Git has independently resolved the merged source.
async fn publish(
    store: &crate::store::Store,
    sink: &dyn crate::artifacts::ArtifactSink,
    p: &Policy,
    service: &str,
    id: &str,
    run: &str,
    receipt: &Value,
    build: &crate::release_build::Policy,
    source: &crate::trigger::GitPatchSource,
) -> Result<()> {
    let artifact = selected(p, run, receipt)?;
    ensure!(
        receipt["revision"] == source.base_revision,
        "merged revision differs from receipt"
    );
    let revision = &source.base_revision;
    let executed: crate::trigger::GitPatchSource =
        serde_json::from_value(receipt["source"].clone())?;
    ensure!(
        source.target_tree == executed.target_tree,
        "executed tree differs from merged source"
    );
    ensure!(
        source.workflows.get(&p.workflow) == executed.workflows.get(&p.workflow),
        "executed workflow differs from merged definition"
    );
    let stored = StoredArtifact {
        sink: "artifacts",
        digest: Some(artifact["sha256"].as_str().unwrap().into()),
        size_bytes: artifact["size_bytes"].as_u64().unwrap(),
        uri: artifact["uri"].as_str().unwrap().into(),
        public_url: None,
    };
    // retain verifies the digest and size in the destination's configured global store.
    let retained = sink
        .retain(
            &stored,
            &format!("{id}:{}", stored.digest.as_deref().unwrap()),
        )
        .await?;
    let component = json!({"id":artifact["id"],"run_id":run,"job":build.components[service].job,
        "workflow":build.components[service].workflow,"name":build.components[service].artifact,
        "sink":"artifacts","uri":retained.uri,"sha256":retained.digest,"size_bytes":retained.size_bytes,
        "import_source":p.api_url,"source_workflow":p.workflow,"source_job":p.job,"source_artifact":p.artifact});
    let manifest = json!({"version":2,"repository":p.repository,"revision":revision,
        "build_id":id,"retained":true,"components":{service:component}});
    let digest = hex::encode(Sha256::digest(serde_json::to_vec(&manifest)?));
    let created: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(receipt["created_at"].clone())?;
    let mut selected_policy = build.clone();
    selected_policy.components.retain(|name, _| name == service);
    let mut tx = store.pool().begin().await?;
    sqlx::query("INSERT INTO ci_release_build(id,repository,name,revision,git_ref,policy,created_by,status,created_at)
        VALUES($1,$2,$1,$3,$4,$5,'trusted-namespace-import','ready',$6) ON CONFLICT(id) DO NOTHING")
        .bind(id).bind(&p.repository).bind(revision).bind(&build.git_ref).bind(serde_json::to_value(selected_policy)?)
        .bind(created).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO ci_release_bundle(id,repository,name,build_id,manifest,manifest_sha256,created_by)
        VALUES($1,$2,$1,$1,$3,$4,'trusted-namespace-import') ON CONFLICT(id) DO NOTHING")
        .bind(id).bind(&p.repository).bind(&manifest).bind(&digest).execute(&mut *tx).await?;
    let saved: String =
        sqlx::query_scalar("SELECT manifest_sha256 FROM ci_release_bundle WHERE id=$1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    ensure!(saved == digest, "import replay changed immutable evidence");
    sqlx::query(
        "INSERT INTO ci_release_import(build_id,source,receipt,descriptor) VALUES($1,$2,$3,$4)
        ON CONFLICT(build_id) DO NOTHING",
    )
    .bind(id)
    .bind(&p.api_url)
    .bind(receipt)
    .bind(serde_json::to_vec(&source)?)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Retention(bool);
    #[async_trait::async_trait]
    impl crate::artifacts::ArtifactSink for Retention {
        fn kind(&self) -> &'static str {
            "artifacts"
        }
        async fn put(
            &self,
            _: &crate::artifacts::ArtifactRef,
            _: Vec<u8>,
        ) -> Result<StoredArtifact, crate::artifacts::ArtifactError> {
            unreachable!()
        }
        async fn get(
            &self,
            _: &StoredArtifact,
        ) -> Result<Vec<u8>, crate::artifacts::ArtifactError> {
            unreachable!()
        }
        async fn retain(
            &self,
            stored: &StoredArtifact,
            key: &str,
        ) -> Result<StoredArtifact, crate::artifacts::ArtifactError> {
            if !self.0 {
                return Err(crate::artifacts::ArtifactError::Transport(
                    "unavailable".into(),
                ));
            }
            Ok(StoredArtifact {
                uri: format!("retained:{key}"),
                ..stored.clone()
            })
        }
    }

    fn policy() -> Policy {
        serde_json::from_value(json!({"api_url":"https://preview.example/namespaces/builds/plugins/ci/api",
            "token_secret":"PREVIEW_READ_TOKEN", "repository":"https://github.com/example/runtime.git",
            "namespace":"builds", "workflow":".ci/validate.yml", "job":"test", "artifact":"runtime",
            "services":["heyvm","heyvmd"]})).unwrap()
    }

    #[test]
    fn import_requires_explicit_trusted_source_and_unique_verifiable_artifact() {
        let p = policy();
        let value = json!({"version":1,"namespace":p.namespace,"run_id":"run-1",
            "repository":p.repository,"workflow":p.workflow,"status":"success",
            "artifacts":[{"id":"artifact-1","name":"runtime","job":"test","sink":"artifacts",
                "sha256":"a".repeat(64),"size_bytes":42,"uri":"store:immutable"}]});
        assert!(selected(&p, "run-1", &value).is_ok());
        for field in ["namespace", "run_id", "repository", "workflow", "status"] {
            let mut wrong = value.clone();
            wrong[field] = json!("other");
            assert!(selected(&p, "run-1", &wrong).is_err(), "{field}");
        }
        for (field, replacement) in [
            ("job", json!("other")),
            ("sink", json!("disk")),
            ("sha256", json!("z".repeat(64))),
            ("size_bytes", json!(0)),
            ("uri", json!(null)),
        ] {
            let mut wrong = value.clone();
            wrong["artifacts"][0][field] = replacement;
            assert!(selected(&p, "run-1", &wrong).is_err(), "{field}");
        }
        let mut duplicate = value.clone();
        duplicate["artifacts"]
            .as_array_mut()
            .unwrap()
            .push(value["artifacts"][0].clone());
        assert!(selected(&p, "run-1", &duplicate).is_err());
        assert!(policies(None).unwrap().is_empty());
        assert!(
            policies(Some(
                &serde_yaml::to_string(&BTreeMap::from([("preview", p.clone())])).unwrap()
            ))
            .is_ok()
        );
        for url in [
            "http://preview.example",
            "https://user:password@preview.example",
            "https://preview.example?token=x",
        ] {
            let mut wrong = p.clone();
            wrong.api_url = url.into();
            assert!(
                policies(Some(
                    &serde_yaml::to_string(&BTreeMap::from([("preview", wrong)])).unwrap()
                ))
                .is_err()
            );
        }
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL"]
    async fn export_is_namespace_scoped_complete_and_paginated() {
        let base = std::env::var("CI_TEST_DATABASE_URL").unwrap();
        let admin = sqlx::PgPool::connect(&base).await.unwrap();
        let schema = format!("release_import_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let mut url = reqwest::Url::parse(&base).unwrap();
        url.query_pairs_mut()
            .append_pair("options", &format!("-c search_path={schema}"));
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(
            url.as_str(),
            dir.path().join("logs"),
            std::time::Duration::from_secs(10),
        )
        .await
        .unwrap();
        store.migrate().await.unwrap();
        store.migrate().await.unwrap();
        let p = policy();
        sqlx::query(
            "INSERT INTO ci_run(id,workflow_id,workflow_path,repo_url,namespace,status,finished_at)
            SELECT 'run-'||lpad(n::text,3,'0'),'runtime',$1,$2,$3,'success',now()
            FROM generate_series(1,105) n",
        )
        .bind(&p.workflow)
        .bind(&p.repository)
        .bind(&p.namespace)
        .execute(store.pool())
        .await
        .unwrap();
        let first = candidates(&store, &p.namespace, &p.repository, &p.workflow, None)
            .await
            .unwrap();
        assert_eq!(first["runs"].as_array().unwrap().len(), 100);
        let second = candidates(
            &store,
            &p.namespace,
            &p.repository,
            &p.workflow,
            first["next"].as_str(),
        )
        .await
        .unwrap();
        assert_eq!(
            second["runs"],
            json!(["run-005", "run-004", "run-003", "run-002", "run-001"])
        );
        assert!(second["next"].is_null());
        assert_eq!(
            candidates(&store, "other", &p.repository, &p.workflow, None)
                .await
                .unwrap()["runs"],
            json!([])
        );
        assert!(receipt(&store, "other", "run-001").await.is_err());
        assert!(receipt(&store, &p.namespace, "run-001").await.is_err());
        sqlx::query(
            "INSERT INTO ci_job(id,run_id,job_key,base_id,display,status)
            VALUES('job-1','run-001','test','test','test','success')",
        )
        .execute(store.pool())
        .await
        .unwrap();
        let source = json!({"baseRevision":"a".repeat(40),"targetTree":"b".repeat(40),
            "patchBase64":"","workflows":{p.workflow.clone():"name: test\non: submit\njobs: {}"}});
        sqlx::query("INSERT INTO ci_run_source(run_id,descriptor) VALUES('run-001',$1)")
            .bind(serde_json::to_vec(&source).unwrap())
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO ci_artifact(id,run_id,job_id,name,sink,digest,size_bytes,uri)
            VALUES('artifact-1','run-001','job-1','runtime','artifacts',$1,42,'store:immutable')",
        )
        .bind("a".repeat(64))
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query("UPDATE ci_run SET sha=$1 WHERE id='run-001'")
            .bind("a".repeat(40))
            .execute(store.pool())
            .await
            .unwrap();
        let exported = receipt(&store, &p.namespace, "run-001").await.unwrap();
        assert_eq!(exported["source"]["targetTree"], source["targetTree"]);
        assert!(selected(&p, "run-001", &exported).is_ok());
        let source: crate::trigger::GitPatchSource = serde_json::from_value(source).unwrap();
        let build: crate::release_build::Policy = serde_json::from_value(json!({
            "workflow_id":"runtime","git_ref":"refs/heads/main",
            "components":{"heyvm":{"workflow":".ci/runtime.yml","job":"build","artifact":"heyvm"}}
        }))
        .unwrap();
        assert!(
            publish(
                &store,
                &Retention(false),
                &p,
                "heyvm",
                "import-one",
                "run-001",
                &exported,
                &build,
                &source
            )
            .await
            .is_err()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM ci_release_bundle")
                .fetch_one(store.pool())
                .await
                .unwrap(),
            0
        );
        let mut wrong = source.clone();
        wrong.target_tree = "c".repeat(40);
        assert!(
            publish(
                &store,
                &Retention(true),
                &p,
                "heyvm",
                "import-one",
                "run-001",
                &exported,
                &build,
                &wrong
            )
            .await
            .is_err()
        );
        let (a, b) = tokio::join!(
            publish(
                &store,
                &Retention(true),
                &p,
                "heyvm",
                "import-one",
                "run-001",
                &exported,
                &build,
                &source
            ),
            publish(
                &store,
                &Retention(true),
                &p,
                "heyvm",
                "import-one",
                "run-001",
                &exported,
                &build,
                &source
            )
        );
        a.unwrap();
        b.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM ci_release_bundle")
                .fetch_one(store.pool())
                .await
                .unwrap(),
            1
        );
        let manifest: Value =
            sqlx::query_scalar("SELECT manifest FROM ci_release_bundle WHERE id='import-one'")
                .fetch_one(store.pool())
                .await
                .unwrap();
        let selected = crate::release_environment::artifact(
            &manifest,
            ".ci/runtime.yml",
            "heyvm",
            Some("build"),
        )
        .unwrap();
        assert_eq!(selected.digest, Some("a".repeat(64)));
        assert_eq!(manifest["components"]["heyvm"]["source_job"], "test");
        let descriptor: Vec<u8> = sqlx::query_scalar(
            "SELECT descriptor FROM ci_release_import WHERE build_id='import-one'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(
            crate::trigger::decode_descriptor(&descriptor)
                .unwrap()
                .target_tree,
            source.target_tree
        );
        let mut changed = exported.clone();
        changed["artifacts"][0]["sha256"] = json!("d".repeat(64));
        assert!(
            publish(
                &store,
                &Retention(true),
                &p,
                "heyvm",
                "import-one",
                "run-001",
                &changed,
                &build,
                &source
            )
            .await
            .is_err()
        );
        sqlx::query("UPDATE ci_job SET status='failure' WHERE id='job-1'")
            .execute(store.pool())
            .await
            .unwrap();
        assert!(receipt(&store, &p.namespace, "run-001").await.is_err());
        store.pool().close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }
}
