CREATE TABLE filename_evidence (
    archive_id INTEGER NOT NULL REFERENCES archives(id),
    file_size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    path_key TEXT NOT NULL,
    algorithm_version INTEGER NOT NULL,
    tokens_json TEXT NOT NULL,
    language_json TEXT NOT NULL,
    color_json TEXT NOT NULL,
    mosaic_json TEXT NOT NULL,
    title_rank INTEGER NOT NULL,
    computed_at TEXT NOT NULL,
    PRIMARY KEY(archive_id, file_size, mtime_ns, path_key, algorithm_version)
);

CREATE TABLE edition_candidate_generations (
    source_group_key TEXT PRIMARY KEY,
    scan_root_id INTEGER NOT NULL REFERENCES scan_roots(id),
    generation_key TEXT NOT NULL,
    set_keys_json TEXT NOT NULL,
    computed_at TEXT NOT NULL
);

CREATE TABLE precision_page_cache (
    pixel_sha256 TEXT NOT NULL,
    algorithm_version INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('SUCCEEDED','FAILED')),
    language_evidence_json TEXT NOT NULL,
    ocr_confidence REAL NOT NULL,
    metrics_json TEXT NOT NULL,
    error_code TEXT,
    computed_at TEXT NOT NULL,
    PRIMARY KEY(pixel_sha256, algorithm_version)
);

CREATE INDEX idx_filename_evidence_current
ON filename_evidence(archive_id, algorithm_version, file_size, mtime_ns, path_key);

CREATE INDEX idx_edition_candidate_generations_root
ON edition_candidate_generations(scan_root_id, source_group_key);
