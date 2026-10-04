PRAGMA foreign_keys = ON;

CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE scan_roots (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL,
    path_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    last_scan_at TEXT
);

CREATE TABLE scan_runs (
    id INTEGER PRIMARY KEY,
    scan_root_id INTEGER NOT NULL REFERENCES scan_roots(id),
    status TEXT NOT NULL CHECK(status IN ('RUNNING','COMPLETED','INTERRUPTED','FAILED')),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    discovery_complete INTEGER NOT NULL DEFAULT 0 CHECK(discovery_complete IN (0,1)),
    discovered_count INTEGER NOT NULL DEFAULT 0,
    reused_count INTEGER NOT NULL DEFAULT 0,
    indexed_count INTEGER NOT NULL DEFAULT 0,
    skipped_count INTEGER NOT NULL DEFAULT 0,
    failed_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE archives (
    id INTEGER PRIMARY KEY,
    scan_root_id INTEGER NOT NULL REFERENCES scan_roots(id),
    path TEXT NOT NULL,
    path_key TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    archive_format TEXT NOT NULL,
    entry_count INTEGER,
    image_count INTEGER,
    content_listing_signature TEXT,
    state TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    indexed_at TEXT,
    inspector_version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(scan_root_id, path_key)
);

CREATE TABLE archive_entries (
    id INTEGER PRIMARY KEY,
    archive_id INTEGER NOT NULL REFERENCES archives(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    path TEXT NOT NULL,
    normalized_path TEXT NOT NULL,
    sort_key TEXT NOT NULL,
    uncompressed_size INTEGER,
    compressed_size INTEGER,
    crc TEXT,
    entry_kind TEXT NOT NULL,
    image_format_hint TEXT,
    UNIQUE(archive_id, position)
);

CREATE TABLE analysis_jobs (
    id INTEGER PRIMARY KEY,
    scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id),
    archive_id INTEGER NOT NULL REFERENCES archives(id),
    stage TEXT NOT NULL CHECK(stage = 'QUICK_INDEX'),
    status TEXT NOT NULL CHECK(status IN ('PENDING','RUNNING','SUCCEEDED','SKIPPED','FAILED')),
    attempts INTEGER NOT NULL DEFAULT 0,
    claim_token TEXT,
    claim_owner_token TEXT,
    last_error_code TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    UNIQUE(scan_run_id, archive_id, stage)
);

CREATE TABLE scan_errors (
    id INTEGER PRIMARY KEY,
    scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id),
    archive_id INTEGER REFERENCES archives(id),
    entry_path TEXT,
    error_code TEXT NOT NULL,
    summary TEXT NOT NULL,
    detail TEXT,
    occurred_at TEXT NOT NULL
);

CREATE TABLE scan_locks (
    db_key TEXT PRIMARY KEY,
    owner_token TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    lease_seconds INTEGER NOT NULL
);

CREATE INDEX idx_archives_root_state ON archives(scan_root_id, state);
CREATE INDEX idx_jobs_run_status ON analysis_jobs(scan_run_id, status);
CREATE INDEX idx_errors_run_code ON scan_errors(scan_run_id, error_code);
