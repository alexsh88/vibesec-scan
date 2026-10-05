CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id),
  analyzer TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  category TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  severity_rank INTEGER NOT NULL,
  risk_score REAL NOT NULL,
  file TEXT NOT NULL,
  start_line INTEGER NOT NULL,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (scan_id, fingerprint)
);
CREATE INDEX idx_findings_scan_order ON findings (scan_id, severity_rank, risk_score DESC);
CREATE INDEX idx_findings_scan_analyzer ON findings (scan_id, analyzer);
CREATE INDEX idx_findings_fingerprint ON findings (fingerprint);
