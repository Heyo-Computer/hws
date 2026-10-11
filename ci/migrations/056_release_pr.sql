-- Optional display metadata, outside immutable release manifests.
ALTER TABLE ci_release_bundle ADD COLUMN IF NOT EXISTS latest_pr JSONB;
ALTER TABLE ci_release_bundle ADD COLUMN IF NOT EXISTS pr_checked_at TIMESTAMPTZ;
