ALTER TABLE ci_release_service_environment
    ADD COLUMN IF NOT EXISTS deployment_mode TEXT
    CHECK (deployment_mode IN ('manual', 'automatic'));
