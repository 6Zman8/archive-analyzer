CREATE TABLE deletion_records (
    id INTEGER PRIMARY KEY,
    quarantine_item_id INTEGER NOT NULL UNIQUE REFERENCES quarantine_items(id),
    scan_root_id INTEGER NOT NULL REFERENCES scan_roots(id),
    archive_id INTEGER NOT NULL REFERENCES archives(id),
    path TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('PENDING','DELETED','FAILED')),
    error_code TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT
);

CREATE INDEX idx_deletion_records_root_state
ON deletion_records(scan_root_id, state, id);
