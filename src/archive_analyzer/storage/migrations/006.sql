CREATE TABLE precision_profiles (
    archive_id INTEGER NOT NULL REFERENCES archives(id),
    file_size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    algorithm_version INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('SUCCEEDED','FAILED')),
    sample_count INTEGER NOT NULL,
    language TEXT NOT NULL,
    language_confidence REAL NOT NULL,
    character_counts_json TEXT NOT NULL,
    page_metrics_json TEXT NOT NULL,
    error_code TEXT,
    computed_at TEXT NOT NULL,
    PRIMARY KEY(archive_id, file_size, mtime_ns, algorithm_version)
);

CREATE TABLE precision_relations (
    scan_root_id INTEGER NOT NULL REFERENCES scan_roots(id),
    archive_a_id INTEGER NOT NULL REFERENCES archives(id),
    archive_b_id INTEGER NOT NULL REFERENCES archives(id),
    left_file_size INTEGER NOT NULL,
    left_mtime_ns INTEGER NOT NULL,
    right_file_size INTEGER NOT NULL,
    right_mtime_ns INTEGER NOT NULL,
    algorithm_version INTEGER NOT NULL,
    mosaic_direction TEXT NOT NULL,
    mosaic_confidence REAL NOT NULL,
    quality_direction TEXT NOT NULL,
    quality_confidence REAL NOT NULL,
    evidence_json TEXT NOT NULL,
    computed_at TEXT NOT NULL,
    PRIMARY KEY(archive_a_id, archive_b_id, left_file_size, left_mtime_ns,
                right_file_size, right_mtime_ns, algorithm_version),
    CHECK(archive_a_id < archive_b_id)
);

CREATE TABLE edition_candidate_sets (
    set_key TEXT PRIMARY KEY,
    scan_root_id INTEGER NOT NULL REFERENCES scan_roots(id),
    source_group_key TEXT NOT NULL,
    edition_kind TEXT NOT NULL CHECK(edition_kind IN ('FULL_COLOR','MONOCHROME','MIXED_OR_UNKNOWN')),
    member_ids_json TEXT NOT NULL,
    input_fingerprint TEXT NOT NULL,
    algorithm_version INTEGER NOT NULL,
    computed_at TEXT NOT NULL,
    UNIQUE(source_group_key, edition_kind, input_fingerprint, algorithm_version)
);

CREATE TABLE recommendation_runs (
    id INTEGER PRIMARY KEY,
    scan_root_id INTEGER NOT NULL REFERENCES scan_roots(id),
    criteria_version INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('RUNNING','COMPLETED','FAILED')),
    started_at TEXT NOT NULL,
    completed_at TEXT,
    error_code TEXT
);

CREATE TABLE recommendation_items (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES recommendation_runs(id),
    set_key TEXT NOT NULL REFERENCES edition_candidate_sets(set_key),
    source_group_key TEXT NOT NULL,
    archive_id INTEGER NOT NULL REFERENCES archives(id),
    recommendation TEXT NOT NULL CHECK(recommendation IN ('KEEP','REMOVE_CANDIDATE','NONE')),
    status TEXT NOT NULL,
    criteria_json TEXT NOT NULL,
    reason TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    UNIQUE(run_id, set_key, archive_id)
);

CREATE TABLE recommendation_applications (
    review_action_id INTEGER PRIMARY KEY REFERENCES review_actions(id),
    recommendation_item_id INTEGER NOT NULL REFERENCES recommendation_items(id),
    applied_at TEXT NOT NULL
);

CREATE INDEX idx_precision_profiles_root_inputs
ON precision_profiles(archive_id, algorithm_version, file_size, mtime_ns);

CREATE INDEX idx_precision_relations_root_version
ON precision_relations(scan_root_id, algorithm_version, archive_a_id, archive_b_id);

CREATE INDEX idx_edition_candidate_sets_root_group
ON edition_candidate_sets(scan_root_id, source_group_key, algorithm_version);

CREATE INDEX idx_recommendation_runs_root_state
ON recommendation_runs(scan_root_id, state, id);

CREATE INDEX idx_recommendation_items_set_run
ON recommendation_items(set_key, run_id, archive_id);
