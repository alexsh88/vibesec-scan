-- Per-scan, per-analyzer, per-file coverage of the AI review (whole-repo scans under a dollar budget):
-- what was reviewed (deep or fast), served from cache, judged not relevant, failed, or skipped because
-- the budget ran out. Nothing is skipped silently: budget-skipped rows are listed in diagnostics.
CREATE TABLE scan_coverage (
  scan_id TEXT NOT NULL REFERENCES scans(id),
  analyzer TEXT NOT NULL,
  path TEXT NOT NULL,
  status TEXT NOT NULL,
  PRIMARY KEY (scan_id, analyzer, path)
);
