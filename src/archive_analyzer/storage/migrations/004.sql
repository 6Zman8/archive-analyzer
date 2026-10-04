CREATE TABLE sequence_relations (
    id INTEGER PRIMARY KEY,
    scan_root_id INTEGER NOT NULL REFERENCES scan_roots(id),
    archive_a_id INTEGER NOT NULL REFERENCES archives(id) ON DELETE CASCADE,
    archive_b_id INTEGER NOT NULL REFERENCES archives(id) ON DELETE CASCADE,
    relation TEXT NOT NULL CHECK(relation IN ('CONTAINS','PARTIAL_OVERLAP','NONE')),
    container_archive_id INTEGER REFERENCES archives(id) ON DELETE CASCADE,
    matched_pages INTEGER NOT NULL,
    left_pages INTEGER NOT NULL,
    right_pages INTEGER NOT NULL,
    left_coverage REAL NOT NULL CHECK(left_coverage >= 0.0 AND left_coverage <= 1.0),
    right_coverage REAL NOT NULL CHECK(right_coverage >= 0.0 AND right_coverage <= 1.0),
    matched_pairs_json TEXT NOT NULL,
    left_file_size INTEGER NOT NULL,
    left_mtime_ns INTEGER NOT NULL,
    right_file_size INTEGER NOT NULL,
    right_mtime_ns INTEGER NOT NULL,
    algorithm_version INTEGER NOT NULL,
    computed_at TEXT NOT NULL,
    CHECK(archive_a_id < archive_b_id),
    CHECK(container_archive_id IS NULL OR container_archive_id IN (archive_a_id, archive_b_id)),
    UNIQUE(archive_a_id, archive_b_id, algorithm_version)
);

CREATE TABLE edition_profiles (
    archive_id INTEGER PRIMARY KEY REFERENCES archives(id) ON DELETE CASCADE,
    file_size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    sample_count INTEGER NOT NULL,
    color_page_ratio REAL CHECK(color_page_ratio IS NULL OR (color_page_ratio >= 0.0 AND color_page_ratio <= 1.0)),
    median_color_score REAL,
    language_hints_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('SUCCEEDED','FAILED')),
    algorithm_version INTEGER NOT NULL,
    computed_at TEXT NOT NULL,
    error_code TEXT
);

CREATE TABLE edition_relations (
    id INTEGER PRIMARY KEY,
    scan_root_id INTEGER NOT NULL REFERENCES scan_roots(id),
    archive_a_id INTEGER NOT NULL REFERENCES archives(id) ON DELETE CASCADE,
    archive_b_id INTEGER NOT NULL REFERENCES archives(id) ON DELETE CASCADE,
    flags_json TEXT NOT NULL,
    summary TEXT NOT NULL,
    preserve_required INTEGER NOT NULL CHECK(preserve_required IN (0,1)),
    left_file_size INTEGER NOT NULL,
    left_mtime_ns INTEGER NOT NULL,
    right_file_size INTEGER NOT NULL,
    right_mtime_ns INTEGER NOT NULL,
    algorithm_version INTEGER NOT NULL,
    computed_at TEXT NOT NULL,
    CHECK(archive_a_id < archive_b_id),
    UNIQUE(archive_a_id, archive_b_id, algorithm_version)
);

CREATE TABLE quarantine_items (
    id INTEGER PRIMARY KEY,
    scan_root_id INTEGER NOT NULL REFERENCES scan_roots(id),
    archive_id INTEGER NOT NULL REFERENCES archives(id) ON DELETE CASCADE,
    group_key TEXT NOT NULL,
    source_path TEXT NOT NULL,
    destination_path TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    sha256 TEXT,
    status TEXT NOT NULL CHECK(status IN ('PENDING','QUARANTINED','RESTORING','RESTORED','FAILED')),
    error_code TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_sequence_relations_root ON sequence_relations(scan_root_id, algorithm_version);
CREATE INDEX idx_edition_relations_root ON edition_relations(scan_root_id, algorithm_version);
CREATE INDEX idx_quarantine_items_archive ON quarantine_items(archive_id, id);
CREATE UNIQUE INDEX idx_quarantine_active_archive ON quarantine_items(archive_id)
WHERE status IN ('PENDING','QUARANTINED','RESTORING');
