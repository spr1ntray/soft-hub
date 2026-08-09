CREATE TABLE IF NOT EXISTS run_account_pins (
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    role TEXT NOT NULL CHECK (role IN ('target', 'referral_parent')),
    PRIMARY KEY (run_id, account_id, role)
);

CREATE INDEX IF NOT EXISTS idx_run_account_pins_account
    ON run_account_pins(account_id, run_id);
