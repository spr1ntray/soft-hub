CREATE TABLE IF NOT EXISTS run_account_states (
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL,
    account_label TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN (
            'queued',
            'running',
            'succeeded',
            'partial',
            'failed',
            'skipped',
            'blocked',
            'needs_attention',
            'cancelled',
            'unknown'
        )
    ),
    stage TEXT NOT NULL,
    progress REAL NOT NULL DEFAULT 0 CHECK (progress >= 0 AND progress <= 1),
    last_message TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (run_id, account_id)
);

CREATE INDEX IF NOT EXISTS idx_run_account_states_updated
    ON run_account_states(updated_at DESC, run_id);

-- Old runs did not persist their selected-account set. Preserve the accounts
-- that can be recovered from scoped events/results, but label their lifecycle
-- as unknown instead of guessing a terminal state from an arbitrary last log.
INSERT OR IGNORE INTO run_account_states(
    run_id,
    account_id,
    account_label,
    status,
    stage,
    progress,
    last_message,
    updated_at
)
SELECT
    scoped.run_id,
    scoped.account_id,
    accounts.label,
    'unknown',
    'historical',
    0,
    'Исторический запуск без типизированного account_state',
    COALESCE(runs.finished_at, runs.started_at, runs.requested_at)
FROM (
    SELECT run_id, account_id
    FROM run_events
    WHERE account_id IS NOT NULL AND account_id <> ''
    UNION
    SELECT run_id, account_id
    FROM results
    WHERE account_id IS NOT NULL AND account_id <> ''
) AS scoped
JOIN runs ON runs.id = scoped.run_id
JOIN accounts ON accounts.id = scoped.account_id;
