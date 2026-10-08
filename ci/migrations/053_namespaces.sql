-- Namespace tenancy: which app-lb namespace a registration and a run belong to.
--
-- Same rules as 001: every statement idempotent, because the whole directory is
-- re-executed on every startup.
--
-- `''` is the fleet — every row that existed before this migration, and every
-- registration made on the operator dashboard. A non-empty value is a tenant
-- namespace that installed the `ci` plugin in app-lb; its runs are planned
-- under the tenant policy in `tenancy.rs` and are only ever read back through
-- the `/ns/{ns}/` routes, which scope every lookup by this column.
--
-- Tokens, jobs, steps and artifacts carry no column of their own: they hang
-- off `repo_id` and `run_id`, so their namespace is their parent's.

ALTER TABLE ci_repo ADD COLUMN IF NOT EXISTS namespace TEXT NOT NULL DEFAULT '';
ALTER TABLE ci_run  ADD COLUMN IF NOT EXISTS namespace TEXT NOT NULL DEFAULT '';

-- A clone URL is unique *within* a namespace, not across the installation. Two
-- teams may both build `github.com/acme/app`, and the fleet may build it too;
-- each registration has its own tokens, network and secrets. Keying the upsert
-- on the URL alone would let a tenant registering a fleet repository's URL
-- overwrite the fleet's row — its name, workflow glob and network.
--
-- The new index is built before the old constraint is dropped, so there is no
-- moment at which the URL is unique nowhere. `ci_repo_normalized_key` is the
-- name Postgres gave the inline `UNIQUE` in 002.
CREATE UNIQUE INDEX IF NOT EXISTS ci_repo_namespace_normalized_key
    ON ci_repo (namespace, normalized);
ALTER TABLE ci_repo DROP CONSTRAINT IF EXISTS ci_repo_normalized_key;

-- A namespace's runs page is "this namespace, newest first".
CREATE INDEX IF NOT EXISTS ci_run_namespace_idx ON ci_run (namespace, created_at DESC);
