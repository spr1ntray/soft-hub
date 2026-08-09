ALTER TABLE accounts
ADD COLUMN twitter_configured INTEGER NOT NULL DEFAULT 0
CHECK (twitter_configured IN (0, 1));

CREATE TABLE IF NOT EXISTS vault_secrets (
    name TEXT PRIMARY KEY,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    updated_at TEXT NOT NULL
);
