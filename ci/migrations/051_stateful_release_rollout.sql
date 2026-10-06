-- In-place replacement ledger for singleton services whose Firecracker
-- workspace must survive release changes. Intent contains only target
-- identity, immutable artifact/revision identities and spec fingerprints.
CREATE TABLE IF NOT EXISTS ci_stateful_release_rollout (
    id TEXT PRIMARY KEY REFERENCES ci_service_deployment(id) ON DELETE RESTRICT,
    intent JSONB NOT NULL CHECK (
        jsonb_typeof(intent) = 'object'
        AND intent ?& ARRAY[
            'target', 'store', 'artifact', 'sha', 'previous_artifact',
            'previous_revision', 'source_sandbox_id',
            'original_spec_sha256', 'desired_spec_sha256'
        ]
        AND intent - ARRAY[
            'target', 'store', 'artifact', 'sha', 'previous_artifact',
            'previous_revision', 'source_sandbox_id',
            'original_spec_sha256', 'desired_spec_sha256'
        ]::TEXT[] = '{}'::JSONB
    ),
    phase TEXT NOT NULL CHECK (phase IN (
        'prepared', 'submitting', 'verifying', 'rolling_back',
        'verifying_rollback', 'complete', 'settled_failure'
    )),
    deadline TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ci_stateful_release_rollout_open_idx
    ON ci_stateful_release_rollout(updated_at)
    WHERE phase NOT IN ('complete', 'settled_failure');
