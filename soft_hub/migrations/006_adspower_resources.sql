ALTER TABLE accounts
ADD COLUMN adspower_configured INTEGER NOT NULL DEFAULT 0
CHECK (adspower_configured IN (0, 1));

ALTER TABLE accounts
ADD COLUMN email_password_configured INTEGER NOT NULL DEFAULT 0
CHECK (email_password_configured IN (0, 1));
