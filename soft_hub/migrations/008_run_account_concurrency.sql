ALTER TABLE runs
    ADD COLUMN account_concurrency INTEGER NOT NULL DEFAULT 1
    CHECK (account_concurrency >= 1 AND account_concurrency <= 20);
