-- No backfill: old preparation evidence has no acknowledged submission proof.
ALTER TABLE ci_host_work ADD COLUMN IF NOT EXISTS image_source TEXT;
ALTER TABLE ci_host_work ADD COLUMN IF NOT EXISTS image_name TEXT;
ALTER TABLE ci_host_work ADD COLUMN IF NOT EXISTS image_submission TEXT
    CHECK (image_submission IN ('uncertain', 'acknowledged'));
