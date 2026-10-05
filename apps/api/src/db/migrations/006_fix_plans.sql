CREATE TABLE fix_plans (
  scan_id TEXT PRIMARY KEY REFERENCES scans(id),
  json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
