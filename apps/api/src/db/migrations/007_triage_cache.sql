-- Per-file-content Haiku triage cache (P6). Keyed by sha256(content) + prompt version + model id,
-- so a diff rescan that touches nothing re-triages nothing: unchanged file content always hits.
CREATE TABLE triage_cache (
  cache_key TEXT PRIMARY KEY,
  json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
