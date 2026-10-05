-- Build admission is independent of submit/merge and environment promotion.
-- A name is an idempotency key, not a mutable pointer to the newest revision.
CREATE TABLE IF NOT EXISTS ci_release_build (
    id TEXT PRIMARY KEY,
    repository TEXT NOT NULL,
    name TEXT NOT NULL,
    revision TEXT NOT NULL,
    git_ref TEXT NOT NULL,
    policy JSONB NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT NOT NULL DEFAULT 'building' CHECK(status IN ('building','ready','failure')),
    error TEXT,
    UNIQUE(repository,name)
);

CREATE TABLE IF NOT EXISTS ci_release_build_run (
    build_id TEXT NOT NULL REFERENCES ci_release_build(id) ON DELETE RESTRICT,
    workflow_path TEXT NOT NULL,
    run_id TEXT NOT NULL UNIQUE REFERENCES ci_run(id) ON DELETE RESTRICT,
    PRIMARY KEY(build_id,workflow_path)
);

ALTER TABLE ci_release_bundle ALTER COLUMN publication_run_id DROP NOT NULL;
ALTER TABLE ci_release_bundle ADD COLUMN IF NOT EXISTS build_id TEXT UNIQUE
    REFERENCES ci_release_build(id) ON DELETE RESTRICT;
CREATE INDEX IF NOT EXISTS ci_release_build_pending_idx ON ci_release_build(created_at)
    WHERE status='building';
