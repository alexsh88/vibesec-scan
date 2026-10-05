CREATE TABLE llm_calls (
  id                 TEXT PRIMARY KEY,
  scan_id            TEXT REFERENCES scans(id),
  analyzer           TEXT NOT NULL,
  purpose            TEXT NOT NULL,
  model              TEXT NOT NULL,
  prompt_version     TEXT NOT NULL,
  input_hash         TEXT NOT NULL,
  input_tokens       INTEGER NOT NULL DEFAULT 0,
  output_tokens      INTEGER NOT NULL DEFAULT 0,
  cache_read_tokens  INTEGER NOT NULL DEFAULT 0,
  cache_write_tokens INTEGER NOT NULL DEFAULT 0,
  cost_usd           REAL NOT NULL DEFAULT 0,
  latency_ms         INTEGER NOT NULL,
  stop_reason        TEXT,
  attempt            INTEGER NOT NULL,
  error_code         TEXT,
  at                 TEXT NOT NULL
);
CREATE INDEX idx_llm_calls_scan ON llm_calls (scan_id, analyzer);
