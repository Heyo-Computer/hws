-- A rejected VM must be removed before its job can return to admission.
ALTER TABLE ci_vm_cleanup ADD COLUMN IF NOT EXISTS requeue BOOLEAN NOT NULL DEFAULT false;

-- Shared admission feedback, not a global execution lock. Expired rows are
-- overwritten on the next rejection from that host.
CREATE TABLE IF NOT EXISTS ci_runner_capacity_wait (
    runner_hd_id TEXT PRIMARY KEY,
    until_at TIMESTAMPTZ NOT NULL
);
