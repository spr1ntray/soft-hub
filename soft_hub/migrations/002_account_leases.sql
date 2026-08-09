CREATE TABLE IF NOT EXISTS account_leases (
    chain_id INTEGER NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    acquired_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (chain_id, account_id)
);

CREATE INDEX IF NOT EXISTS idx_account_leases_run ON account_leases(run_id);
