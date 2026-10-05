CREATE TABLE IF NOT EXISTS ci_release_environment (
    name TEXT PRIMARY KEY,
    repository TEXT NOT NULL,
    current_bundle TEXT REFERENCES ci_release_bundle(id) ON DELETE RESTRICT,
    previous_bundle TEXT REFERENCES ci_release_bundle(id) ON DELETE RESTRICT,
    active_run TEXT REFERENCES ci_run(id) ON DELETE RESTRICT,
    automation_held BOOLEAN NOT NULL DEFAULT false,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ci_release_promotion (
    run_id TEXT PRIMARY KEY REFERENCES ci_run(id) ON DELETE RESTRICT,
    environment TEXT NOT NULL REFERENCES ci_release_environment(name) ON DELETE RESTRICT,
    request_id TEXT NOT NULL,
    bundle_id TEXT NOT NULL REFERENCES ci_release_bundle(id) ON DELETE RESTRICT,
    automatic BOOLEAN NOT NULL,
    policy JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    UNIQUE(environment,request_id)
);
