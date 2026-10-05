-- One scan summary ("first screen": grade, top risks, next actions) per scan, stored as validated JSON.
CREATE TABLE scan_summaries (
  scan_id TEXT PRIMARY KEY REFERENCES scans(id),
  json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
