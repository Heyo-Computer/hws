-- One validated workflow can produce independently retained service releases.
-- Membership remains unique per build/workflow; no producer jobs are duplicated.
ALTER TABLE ci_release_build_run DROP CONSTRAINT IF EXISTS ci_release_build_run_run_id_key;
-- Publication and the originating deployment's release link commit together.
ALTER TABLE ci_release_build ADD COLUMN IF NOT EXISTS source_deployment_id TEXT
    REFERENCES ci_release_service_deployment(id) ON DELETE RESTRICT;
