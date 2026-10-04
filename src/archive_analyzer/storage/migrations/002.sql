CREATE TABLE duplicate_analysis_runs (
    id INTEGER PRIMARY KEY,
    scan_root_id INTEGER NOT NULL REFERENCES scan_roots(id),
    status TEXT NOT NULL CHECK(status IN ('RUNNING','COMPLETED','INTERRUPTED','FAILED')),
    stage TEXT NOT NULL CHECK(stage IN ('ARCHIVE_HASH','PROBE','CANDIDATE_BUILD','FULL','MATCH','GROUP')),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    analyzer_version INTEGER NOT NULL,
    archive_total INTEGER NOT NULL DEFAULT 0,
    archive_processed INTEGER NOT NULL DEFAULT 0,
    image_total INTEGER NOT NULL DEFAULT 0,
    image_processed INTEGER NOT NULL DEFAULT 0,
    failed_count INTEGER NOT NULL DEFAULT 0,
    candidate_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE duplicate_analysis_jobs (
    id INTEGER PRIMARY KEY,
    analysis_run_id INTEGER NOT NULL REFERENCES duplicate_analysis_runs(id),
    archive_id INTEGER REFERENCES archives(id) ON DELETE CASCADE,
    stage TEXT NOT NULL CHECK(stage IN ('ARCHIVE_HASH','PROBE','FULL','MATCH')),
    subject_key TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('PENDING','RUNNING','SUCCEEDED','SKIPPED','FAILED')),
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error_code TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    UNIQUE(analysis_run_id, stage, subject_key)
);

CREATE TABLE archive_fingerprints (
    archive_id INTEGER PRIMARY KEY REFERENCES archives(id) ON DELETE CASCADE,
    file_size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    sha256 TEXT,
    hash_state TEXT NOT NULL CHECK(hash_state IN ('NOT_REQUIRED','SUCCEEDED','FAILED')),
    filename_tokens_json TEXT NOT NULL,
    language_hints_json TEXT NOT NULL,
    analyzer_version INTEGER NOT NULL,
    computed_at TEXT NOT NULL,
    error_code TEXT
);

CREATE TABLE image_fingerprints (
    archive_id INTEGER NOT NULL REFERENCES archives(id) ON DELETE CASCADE,
    entry_position INTEGER NOT NULL,
    coverage TEXT NOT NULL CHECK(coverage IN ('PROBE','FULL')),
    byte_sha256 TEXT,
    pixel_sha256 TEXT,
    dhash64 TEXT,
    ahash64 TEXT,
    width INTEGER,
    height INTEGER,
    state TEXT NOT NULL CHECK(state IN ('SUCCEEDED','FAILED')),
    error_code TEXT,
    analyzer_version INTEGER NOT NULL,
    computed_at TEXT NOT NULL,
    PRIMARY KEY(archive_id, entry_position, analyzer_version)
);

CREATE TABLE candidate_relations (
    id INTEGER PRIMARY KEY,
    scan_root_id INTEGER NOT NULL REFERENCES scan_roots(id),
    archive_a_id INTEGER NOT NULL REFERENCES archives(id) ON DELETE CASCADE,
    archive_b_id INTEGER NOT NULL REFERENCES archives(id) ON DELETE CASCADE,
    relation TEXT NOT NULL CHECK(relation IN ('EXACT_ARCHIVE','EXACT_CONTENT','VISUAL_VARIANT','RELATED')),
    confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
    matched_pages INTEGER NOT NULL,
    left_pages INTEGER NOT NULL,
    right_pages INTEGER NOT NULL,
    recommendation TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    analyzer_version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    CHECK(archive_a_id < archive_b_id),
    UNIQUE(archive_a_id, archive_b_id, analyzer_version)
);

CREATE TABLE candidate_groups (
    id INTEGER PRIMARY KEY,
    scan_root_id INTEGER NOT NULL REFERENCES scan_roots(id),
    group_key TEXT NOT NULL UNIQUE,
    strongest_relation TEXT NOT NULL,
    confidence REAL NOT NULL,
    analyzer_version INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE candidate_group_members (
    group_id INTEGER NOT NULL REFERENCES candidate_groups(id) ON DELETE CASCADE,
    archive_id INTEGER NOT NULL REFERENCES archives(id) ON DELETE CASCADE,
    PRIMARY KEY(group_id, archive_id)
);

CREATE TABLE review_actions (
    id INTEGER PRIMARY KEY,
    group_key TEXT NOT NULL,
    archive_id INTEGER NOT NULL REFERENCES archives(id) ON DELETE CASCADE,
    action TEXT NOT NULL CHECK(action IN ('KEEP','REMOVE_CANDIDATE','HOLD')),
    file_size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_duplicate_runs_root ON duplicate_analysis_runs(scan_root_id, id);
CREATE INDEX idx_duplicate_jobs_run_status ON duplicate_analysis_jobs(analysis_run_id, status, id);
CREATE INDEX idx_image_fingerprints_hashes ON image_fingerprints(pixel_sha256, byte_sha256);
CREATE INDEX idx_candidate_relations_root ON candidate_relations(scan_root_id, analyzer_version);
CREATE INDEX idx_candidate_group_members_archive ON candidate_group_members(archive_id);
CREATE INDEX idx_review_actions_group ON review_actions(group_key, id);
