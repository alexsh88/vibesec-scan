CREATE TABLE repos (
  id             TEXT PRIMARY KEY,
  owner          TEXT NOT NULL,
  name           TEXT NOT NULL,
  is_private     INTEGER NOT NULL DEFAULT 0,
  default_branch TEXT,
  created_at     TEXT NOT NULL,
  UNIQUE (owner, name)
);

CREATE TABLE scans (
  id                     TEXT PRIMARY KEY,
  repo_id                TEXT NOT NULL REFERENCES repos(id),
  ref                    TEXT,
  commit_sha             TEXT,
  base_scan_id           TEXT REFERENCES scans(id),
  state                  TEXT NOT NULL,
  error_code             TEXT,
  error_message          TEXT,
  options_json           TEXT NOT NULL,
  options_hash           TEXT NOT NULL,
  analyzer_versions_hash TEXT,
  cache_hit              TEXT NOT NULL DEFAULT 'none',
  idempotency_key        TEXT UNIQUE,
  has_auth               INTEGER NOT NULL DEFAULT 0,
  checkpoint_json        TEXT,
  heartbeat_at           TEXT,
  diagnostics_json       TEXT,
  warnings_json          TEXT NOT NULL DEFAULT '[]',
  cost_usd               REAL NOT NULL DEFAULT 0,
  tokens_json            TEXT,
  summary_json           TEXT,
  created_at             TEXT NOT NULL,
  started_at             TEXT,
  finished_at            TEXT
);
CREATE INDEX idx_scans_repo ON scans (repo_id, created_at);
CREATE INDEX idx_scans_state ON scans (state);

CREATE TABLE scan_events (
  scan_id      TEXT NOT NULL REFERENCES scans(id),
  seq          INTEGER NOT NULL,
  type         TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  at           TEXT NOT NULL,
  PRIMARY KEY (scan_id, seq)
);

CREATE TABLE audit_log (
  seq          INTEGER PRIMARY KEY,
  at           TEXT NOT NULL,
  actor        TEXT NOT NULL,
  actor_ip     TEXT,
  user_agent   TEXT,
  action       TEXT NOT NULL,
  target_type  TEXT NOT NULL,
  target_id    TEXT NOT NULL,
  scan_id      TEXT,
  details_json TEXT NOT NULL,
  prev_hash    TEXT NOT NULL,
  hash         TEXT NOT NULL UNIQUE
);
CREATE INDEX idx_audit_action ON audit_log (action, at);
CREATE INDEX idx_audit_target ON audit_log (target_type, target_id);

CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
