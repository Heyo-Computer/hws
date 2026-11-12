-- Remote provenance is explicit, never represented as locally executed CI jobs.
CREATE TABLE IF NOT EXISTS ci_release_import (
    build_id TEXT PRIMARY KEY REFERENCES ci_release_build(id) ON DELETE RESTRICT,
    source TEXT NOT NULL,
    receipt JSONB NOT NULL,
    descriptor BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
