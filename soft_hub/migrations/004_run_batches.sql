CREATE TABLE IF NOT EXISTS run_batches (
    idempotency_key TEXT PRIMARY KEY,
    request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS run_batch_items (
    idempotency_key TEXT NOT NULL REFERENCES run_batches(idempotency_key) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    run_id TEXT NOT NULL UNIQUE REFERENCES runs(id) ON DELETE RESTRICT,
    PRIMARY KEY (idempotency_key, ordinal)
);

CREATE INDEX IF NOT EXISTS idx_run_batch_items_run ON run_batch_items(run_id);
