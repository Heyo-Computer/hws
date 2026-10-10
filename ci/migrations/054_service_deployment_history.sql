-- Deployment evidence is separate from promotion commands. A single real run
-- may deploy several services; history must never grant execution authority.
CREATE TABLE IF NOT EXISTS ci_release_service_deployment (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES ci_run(id) ON DELETE RESTRICT,
    environment TEXT NOT NULL,
    service TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('ordinary','promotion','legacy_import')),
    automatic BOOLEAN NOT NULL DEFAULT false,
    obligations JSONB NOT NULL,
    bundle_id TEXT REFERENCES ci_release_bundle(id) ON DELETE RESTRICT,
    revision TEXT,
    release_identity JSONB,
    status TEXT NOT NULL DEFAULT 'running'
        CHECK (status IN ('running','success','failure','cancelled','skipped')),
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    UNIQUE(run_id,environment,service),
    FOREIGN KEY(environment,service) REFERENCES ci_release_service_environment(name,service)
        ON DELETE RESTRICT
);
ALTER TABLE ci_release_service_environment ADD COLUMN IF NOT EXISTS current_deployment TEXT
    REFERENCES ci_release_service_deployment(id) ON DELETE RESTRICT;
ALTER TABLE ci_release_service_environment ADD COLUMN IF NOT EXISTS previous_deployment TEXT
    REFERENCES ci_release_service_deployment(id) ON DELETE RESTRICT;
CREATE INDEX IF NOT EXISTS ci_release_service_deployment_pending
    ON ci_release_service_deployment(created_at) WHERE status='running';
