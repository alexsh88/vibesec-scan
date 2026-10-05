-- P7 Task A: per-repo finding triage, keyed by fingerprint so it survives across rescans of the
-- same repo (a later scan's identical finding is auto re-annotated by applySuppressions(scanId)).
CREATE TABLE suppressions (
  id TEXT PRIMARY KEY,
  repo_id TEXT NOT NULL REFERENCES repos(id),
  fingerprint TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('false_positive', 'accepted_risk', 'wont_fix')),
  reason TEXT NOT NULL CHECK (length(reason) <= 1000),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  UNIQUE (repo_id, fingerprint)
);
CREATE INDEX idx_suppressions_repo ON suppressions (repo_id);
