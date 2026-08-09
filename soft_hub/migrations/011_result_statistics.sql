ALTER TABLE runs
    ADD COLUMN output_schema_json TEXT NOT NULL DEFAULT '{}';

ALTER TABLE run_account_states
    ADD COLUMN account_address TEXT NOT NULL DEFAULT '';

-- Public wallet addresses are already plaintext account metadata. Snapshot the
-- address beside the existing label so historical reports remain intelligible
-- after an account is renamed or deleted. Locked-Vault API boundaries continue
-- to protect both fields.
UPDATE run_account_states
SET account_address = COALESCE(
    (SELECT accounts.evm_address
     FROM accounts
     WHERE accounts.id = run_account_states.account_id),
    ''
)
WHERE account_address = '';

CREATE INDEX IF NOT EXISTS idx_results_run_kind_account
    ON results(run_id, kind, account_id);

CREATE INDEX IF NOT EXISTS idx_results_module_created_id
    ON results(module_id, created_at DESC, id);

CREATE INDEX IF NOT EXISTS idx_runs_module_action_requested
    ON runs(module_id, action_id, requested_at DESC);
