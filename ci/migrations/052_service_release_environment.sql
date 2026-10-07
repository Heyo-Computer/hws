-- Additive only: original binaries retain their name key, request identity,
-- and isolated state. Never backfill unattributed history into a service.
CREATE TABLE IF NOT EXISTS ci_release_service_environment (
    name TEXT NOT NULL,
    service TEXT NOT NULL CHECK (service <> ''),
    repository TEXT NOT NULL,
    current_bundle TEXT REFERENCES ci_release_bundle(id) ON DELETE RESTRICT,
    previous_bundle TEXT REFERENCES ci_release_bundle(id) ON DELETE RESTRICT,
    active_run TEXT REFERENCES ci_run(id) ON DELETE RESTRICT,
    automation_held BOOLEAN NOT NULL DEFAULT false,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (name,service)
);

CREATE TABLE IF NOT EXISTS ci_release_service_promotion (
    run_id TEXT PRIMARY KEY REFERENCES ci_run(id) ON DELETE RESTRICT,
    environment TEXT NOT NULL,
    service TEXT NOT NULL,
    request_id TEXT NOT NULL,
    bundle_id TEXT NOT NULL REFERENCES ci_release_bundle(id) ON DELETE RESTRICT,
    automatic BOOLEAN NOT NULL,
    policy JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    UNIQUE(environment,service,request_id),
    FOREIGN KEY (environment,service) REFERENCES ci_release_service_environment(name,service) ON DELETE RESTRICT
);
