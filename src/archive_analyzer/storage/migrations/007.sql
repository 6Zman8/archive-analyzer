ALTER TABLE recommendation_runs ADD COLUMN input_fingerprint TEXT;

CREATE INDEX idx_recommendation_runs_root_fingerprint
ON recommendation_runs(scan_root_id, input_fingerprint, state, id);
