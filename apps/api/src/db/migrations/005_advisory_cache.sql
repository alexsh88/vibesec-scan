CREATE TABLE advisory_cache (
  kind TEXT NOT NULL,
  cache_key TEXT NOT NULL,
  json TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  PRIMARY KEY (kind, cache_key)
);
CREATE INDEX idx_advisory_cache_fetched_at ON advisory_cache (fetched_at);
