CREATE TABLE scan_files (
  scan_id     TEXT NOT NULL REFERENCES scans(id),
  path        TEXT NOT NULL,
  blob_sha    TEXT NOT NULL,
  size        INTEGER NOT NULL,
  language    TEXT NOT NULL,
  category    TEXT NOT NULL,
  tags_json   TEXT NOT NULL DEFAULT '[]',
  skip_reason TEXT,
  PRIMARY KEY (scan_id, path)
);

CREATE TABLE scan_imports (
  scan_id   TEXT NOT NULL REFERENCES scans(id),
  from_path TEXT NOT NULL,
  specifier TEXT NOT NULL,
  kind      TEXT NOT NULL,
  to_path   TEXT,
  package   TEXT,
  line      INTEGER NOT NULL
);
CREATE INDEX idx_scan_imports_from ON scan_imports (scan_id, from_path);
CREATE INDEX idx_scan_imports_to ON scan_imports (scan_id, to_path);
CREATE INDEX idx_scan_imports_pkg ON scan_imports (scan_id, package);

CREATE TABLE scan_entrypoints (
  scan_id TEXT NOT NULL REFERENCES scans(id),
  path    TEXT NOT NULL,
  kind    TEXT NOT NULL,
  line    INTEGER,
  detail  TEXT
);
CREATE INDEX idx_scan_entrypoints ON scan_entrypoints (scan_id);

ALTER TABLE scans ADD COLUMN index_stats_json TEXT;
