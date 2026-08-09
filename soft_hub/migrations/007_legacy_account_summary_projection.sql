-- Known first-party adapter versions released before lifecycle projection could
-- finish successfully with an account-scoped, typed account_summary but no
-- terminal account_state. Recover only those recent `unreported` projections.
-- Arbitrary log text, third-party packages and duplicate summaries are
-- intentionally never interpreted as success.
UPDATE run_account_states AS state
SET
    status = (
        SELECT result.status
        FROM results AS result
        WHERE result.run_id = state.run_id
          AND result.account_id = state.account_id
          AND result.kind = 'account_summary'
        ORDER BY result.created_at DESC, result.rowid DESC
        LIMIT 1
    ),
    stage = CASE (
        SELECT result.status
        FROM results AS result
        WHERE result.run_id = state.run_id
          AND result.account_id = state.account_id
          AND result.kind = 'account_summary'
        ORDER BY result.created_at DESC, result.rowid DESC
        LIMIT 1
    )
        WHEN 'succeeded' THEN 'completed'
        WHEN 'partial' THEN 'partially_completed'
        WHEN 'failed' THEN 'action_failed'
        WHEN 'skipped' THEN 'skipped'
        WHEN 'blocked' THEN 'blocked'
        WHEN 'needs_attention' THEN 'external_state_unknown'
    END,
    progress = CASE WHEN (
        SELECT result.status
        FROM results AS result
        WHERE result.run_id = state.run_id
          AND result.account_id = state.account_id
          AND result.kind = 'account_summary'
        ORDER BY result.created_at DESC, result.rowid DESC
        LIMIT 1
    ) = 'needs_attention' THEN progress ELSE 1 END
WHERE state.status = 'unknown'
  AND state.stage = 'unreported'
  AND EXISTS (
      SELECT 1
      FROM runs AS bridge_run
      WHERE bridge_run.id = state.run_id
        AND (
            (bridge_run.module_id = 'io.sprintray.checkpoint-testnet'
             AND bridge_run.module_version = '1.0.0'
             AND bridge_run.action_id IN ('inspect', 'daily_farm', 'deposit', 'full_cycle', 'create_sell'))
            OR (bridge_run.module_id = 'io.sprintray.sekai-testnet'
                AND bridge_run.module_version = '1.0.0'
                AND bridge_run.action_id IN ('inspect', 'run_cycle'))
            OR (bridge_run.module_id = 'io.sprintray.umia-testnet'
                AND bridge_run.module_version = '1.0.0'
                AND bridge_run.action_id IN ('inspect', 'run_activities'))
        )
  )
  AND (
      SELECT COUNT(*)
      FROM results AS result
      WHERE result.run_id = state.run_id
        AND result.account_id = state.account_id
        AND result.kind = 'account_summary'
  ) = 1
  AND (
      SELECT result.status
      FROM results AS result
      WHERE result.run_id = state.run_id
        AND result.account_id = state.account_id
        AND result.kind = 'account_summary'
      ORDER BY result.created_at DESC, result.rowid DESC
      LIMIT 1
  ) IN ('succeeded', 'partial', 'failed', 'skipped', 'blocked', 'needs_attention');

UPDATE runs
SET
    status = 'needs_attention',
    error = COALESCE(error, 'account_state_requires_attention')
WHERE id IN (
    SELECT state.run_id
    FROM run_account_states AS state
    JOIN runs AS bridge_run ON bridge_run.id = state.run_id
    WHERE state.status = 'needs_attention'
      AND state.stage = 'external_state_unknown'
      AND (
          (bridge_run.module_id = 'io.sprintray.checkpoint-testnet'
           AND bridge_run.module_version = '1.0.0'
           AND bridge_run.action_id IN ('inspect', 'daily_farm', 'deposit', 'full_cycle', 'create_sell'))
          OR (bridge_run.module_id = 'io.sprintray.sekai-testnet'
              AND bridge_run.module_version = '1.0.0'
              AND bridge_run.action_id IN ('inspect', 'run_cycle'))
          OR (bridge_run.module_id = 'io.sprintray.umia-testnet'
              AND bridge_run.module_version = '1.0.0'
              AND bridge_run.action_id IN ('inspect', 'run_activities'))
      )
);
