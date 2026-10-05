-- P7 caching (spec §11).
-- Each analyzer's own output for a scan, exactly as it returned it (before VERIFYING/SCORING rewrite
-- the persisted findings): the reuse source of incremental rescans, which re-attach the findings of
-- unchanged files/entrypoints from here (re-validated) instead of paying for them again.
CREATE TABLE analyzer_results (
  scan_id TEXT NOT NULL REFERENCES scans(id),
  analyzer TEXT NOT NULL,
  findings_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (scan_id, analyzer)
);

-- Hash of the result-defining scan options (ScanOptions only: unlike options_hash it leaves out the
-- requested ref, since the resolved commit SHA already pins the code). Together with
-- analyzer_versions_hash and commit_sha it keys the full-scan cache.
ALTER TABLE scans ADD COLUMN result_options_hash TEXT;
CREATE INDEX idx_scans_reuse ON scans (repo_id, result_options_hash, analyzer_versions_hash, state);
