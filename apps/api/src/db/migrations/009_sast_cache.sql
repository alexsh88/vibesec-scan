-- Per-file SAST result cache. Keyed by sha256(per-file prompt: content + local context + hints) +
-- SAST prompt version + model id (deep or fast tier), so an unchanged file in an unchanged
-- neighbourhood is never re-reviewed. Stores verified issue LOCATIONS and the model's prose only —
-- never code text: snippets are re-read from the (byte-identical) file on a hit.
CREATE TABLE sast_cache (
  cache_key TEXT PRIMARY KEY,
  json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
