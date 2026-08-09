PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vault_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    salt BLOB NOT NULL,
    nonce BLOB NOT NULL,
    verifier BLOB NOT NULL,
    kdf_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    evm_address TEXT NOT NULL UNIQUE,
    key_fingerprint TEXT NOT NULL UNIQUE,
    proxy_label TEXT NOT NULL,
    proxy_fingerprint TEXT NOT NULL UNIQUE,
    email_label TEXT NOT NULL,
    email_fingerprint TEXT NOT NULL UNIQUE,
    tags_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'ready',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS account_secrets (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS modules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    active_path TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    trust_status TEXT NOT NULL DEFAULT 'local_unsigned',
    health TEXT NOT NULL DEFAULT 'ready',
    installed_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS module_versions (
    module_id TEXT NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    path TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    archive_sha256 TEXT NOT NULL,
    installed_at TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (module_id, version)
);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    module_id TEXT NOT NULL REFERENCES modules(id),
    module_version TEXT NOT NULL,
    action_id TEXT NOT NULL,
    status TEXT NOT NULL,
    progress REAL NOT NULL DEFAULT 0,
    account_count INTEGER NOT NULL DEFAULT 0,
    pid INTEGER,
    requested_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    summary_json TEXT,
    error TEXT
);

CREATE INDEX IF NOT EXISTS idx_runs_requested ON runs(requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_runs_module ON runs(module_id, requested_at DESC);

CREATE TABLE IF NOT EXISTS run_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    level TEXT NOT NULL,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    account_id TEXT,
    data_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_run_id ON run_events(run_id, id);

CREATE TABLE IF NOT EXISTS results (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    module_id TEXT NOT NULL REFERENCES modules(id),
    account_id TEXT,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    title TEXT NOT NULL,
    data_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_results_created ON results(created_at DESC);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
