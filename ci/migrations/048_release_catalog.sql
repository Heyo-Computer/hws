-- Deployable bundles are distinct from ci_release (Git publication receipts).
-- No environment pointer or deployment is changed by registering a bundle.
CREATE TABLE IF NOT EXISTS ci_release_bundle (
    id TEXT PRIMARY KEY,
    repository TEXT NOT NULL,
    name TEXT NOT NULL,
    publication_run_id TEXT NOT NULL REFERENCES ci_run(id) ON DELETE RESTRICT,
    manifest JSONB NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(repository, name)
);

CREATE INDEX IF NOT EXISTS ci_release_bundle_created_idx
    ON ci_release_bundle(created_at DESC, id DESC);

-- Retain artifact provenance even if somebody attempts to delete an old run.
CREATE TABLE IF NOT EXISTS ci_release_bundle_artifact (
    bundle_id TEXT NOT NULL REFERENCES ci_release_bundle(id) ON DELETE RESTRICT,
    component TEXT NOT NULL,
    artifact_id TEXT NOT NULL REFERENCES ci_artifact(id) ON DELETE RESTRICT,
    PRIMARY KEY(bundle_id, component)
);
