CREATE TABLE github_module_sources (
    module_id TEXT NOT NULL,
    version TEXT NOT NULL,
    owner TEXT NOT NULL COLLATE NOCASE,
    repository TEXT NOT NULL COLLATE NOCASE,
    release_tag TEXT NOT NULL,
    asset_name TEXT NOT NULL,
    asset_url TEXT NOT NULL,
    archive_sha256 TEXT NOT NULL,
    installed_at TEXT NOT NULL,
    PRIMARY KEY (module_id, version),
    FOREIGN KEY (module_id, version)
        REFERENCES module_versions(module_id, version) ON DELETE CASCADE,
    UNIQUE (owner, repository, release_tag, asset_name)
);

CREATE INDEX idx_github_module_sources_repository
    ON github_module_sources(owner, repository);
