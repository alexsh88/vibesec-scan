/**
 * Pure derivations for the live scan view: the stage timeline, analyzer lanes, deduplicated finding
 * stream and human warning titles — all computed from the SSE event log (useScanContext().events)
 * plus the scan DTO and diagnostics. No React here except the tiny hooks at the bottom.
 */
import { isTerminalState, type Category, type FindingSummary, type ScanDto, type ScanEvent, type ScanState, type Severity } from '@vibesec/shared';
import { useEffect, useState, useSyncExternalStore } from 'react';
import type { LiveEvent } from '@/hooks/useScanEvents';
import type { CoverageStatus, Diagnostics } from '@/lib/api';
import { PIPELINE_STAGES } from '@/lib/scanState';

// ---------------------------------------------------------------------------------------------
// Stage timeline
// ---------------------------------------------------------------------------------------------

export type StageStatus = 'pending' | 'active' | 'done' | 'failed' | 'cancelled' | 'skipped' | 'cached';

export type StageView = {
  state: ScanState;
  label: string;
  status: StageStatus;
  startedAt: number | null;
  endedAt: number | null;
  /** done/total of the stage's own progress events (resolve, clone, index, verify). */
  progress: { done: number; total: number } | null;
};

/** The stages shown in the timeline (QUEUED is folded into the header, not a node). */
export const TIMELINE_STAGES = PIPELINE_STAGES.filter((s) => s.state !== 'QUEUED');

const STAGE_PROGRESS_KEY: Partial<Record<ScanState, (analyzer: string) => boolean>> = {
  RESOLVING: (a) => a === 'resolve',
  CLONING: (a) => a === 'clone' || a.startsWith('clone:'),
  INDEXING: (a) => a === 'index',
  VERIFYING: (a) => a === 'verify',
};

const stageIndex = (s: ScanState) => TIMELINE_STAGES.findIndex((t) => t.state === s);

export type Timeline = {
  stages: StageView[];
  /** Full-cache hit: the pipeline jumped from RESOLVING straight to done. */
  cacheShortcut: boolean;
  queuedAt: number | null;
  terminalAt: number | null;
};

export function deriveTimeline(events: readonly LiveEvent[], current: ScanState, cacheHit: ScanDto['cacheHit']): Timeline {
  const transitions: Array<{ state: ScanState; at: number }> = [];
  const latestProgress = new Map<ScanState, { done: number; total: number }>();
  for (const e of events) {
    if (e.type === 'state' || e.type === 'done') {
      const last = transitions[transitions.length - 1];
      if (!last || last.state !== e.state) transitions.push({ state: e.state, at: Date.parse(e.at) });
    } else if (e.type === 'progress') {
      for (const [stage, match] of Object.entries(STAGE_PROGRESS_KEY)) {
        if (match(e.analyzer)) latestProgress.set(stage as ScanState, { done: e.done, total: e.total });
      }
    }
  }

  const terminal = isTerminalState(current);
  const success = current === 'COMPLETED' || current === 'COMPLETED_WITH_WARNINGS';
  const cacheShortcut = cacheHit === 'full';
  const terminalAt = terminal ? (transitions.find((t) => isTerminalState(t.state))?.at ?? null) : null;

  let reached = -1;
  for (const t of transitions) reached = Math.max(reached, stageIndex(t.state));
  if (!terminal) reached = Math.max(reached, stageIndex(current));

  const stages = TIMELINE_STAGES.map((def, i): StageView => {
    const startIdx = transitions.findIndex((t) => t.state === def.state);
    const start = startIdx >= 0 ? transitions[startIdx]! : null;
    const next = startIdx >= 0 ? transitions[startIdx + 1] : undefined;
    const base = { state: def.state, label: def.label, progress: latestProgress.get(def.state) ?? null };

    if (start) {
      const endedAt = next?.at ?? null;
      let status: StageStatus = endedAt !== null || terminal ? 'done' : 'active';
      if (i === reached && (current === 'FAILED' || current === 'CANCELLED')) status = current === 'FAILED' ? 'failed' : 'cancelled';
      return { ...base, status, startedAt: start.at, endedAt: endedAt ?? (terminal ? terminalAt : null) };
    }

    // No state event for this stage: either the log isn't available (fallback on the DTO's state),
    // the stage was skipped, or it hasn't happened yet.
    let status: StageStatus;
    if (transitions.length === 0) {
      const cur = stageIndex(current);
      if (success) status = cacheShortcut && i > 0 ? 'cached' : 'done';
      else if (cur < 0) status = 'pending';
      else status = i < cur ? 'done' : i === cur ? 'active' : 'pending';
    } else if (success && i > reached) {
      status = cacheShortcut ? 'cached' : 'skipped';
    } else if (i < reached) {
      status = 'skipped';
    } else {
      status = 'pending';
    }
    return { ...base, status, startedAt: null, endedAt: null };
  });

  const queued = transitions.find((t) => t.state === 'QUEUED');
  return { stages, cacheShortcut, queuedAt: queued?.at ?? null, terminalAt };
}

// ---------------------------------------------------------------------------------------------
// Analyzer lanes
// ---------------------------------------------------------------------------------------------

export type AnalyzerDef = {
  id: string;
  label: string;
  blurb: string;
  /** Enabled when any of these categories is in the scan's options. */
  categories: readonly Category[];
  stage: 'ANALYZING' | 'VERIFYING';
};

export const ANALYZERS: readonly AnalyzerDef[] = [
  { id: 'triage', label: 'Triage', blurb: 'Ranks files for deep AI review', categories: ['sast', 'taint', 'config', 'quality'], stage: 'ANALYZING' },
  { id: 'credentials', label: 'Credentials', blurb: 'Patterns, entropy and git history', categories: ['secret'], stage: 'ANALYZING' },
  { id: 'credential-hunter', label: 'Credential hunter', blurb: 'AI hunt for disguised keys', categories: ['secret'], stage: 'ANALYZING' },
  { id: 'dependencies', label: 'Dependencies', blurb: 'Lockfiles → CVEs → reachability', categories: ['dependency'], stage: 'ANALYZING' },
  { id: 'sast', label: 'Code (SAST)', blurb: 'Insecure patterns + AI review', categories: ['sast'], stage: 'ANALYZING' },
  { id: 'taint', label: 'Data flow', blurb: 'Entrypoint → sink tracing', categories: ['taint'], stage: 'ANALYZING' },
  { id: 'config', label: 'Config', blurb: 'CI, infra and framework settings', categories: ['config'], stage: 'ANALYZING' },
  { id: 'quality', label: 'Quality', blurb: 'Security-relevant code smells', categories: ['quality'], stage: 'ANALYZING' },
  { id: 'verify', label: 'Verify', blurb: 'Skeptic pass over every finding', categories: ['secret', 'sast', 'taint', 'dependency', 'config', 'quality'], stage: 'VERIFYING' },
];

export type LaneStatus = 'off' | 'waiting' | 'running' | 'done' | 'failed' | 'cached' | 'stopped' | 'skipped';

export type LaneView = AnalyzerDef & {
  status: LaneStatus;
  /** 0..1, or null for an indeterminate running bar. */
  fraction: number | null;
  progress: { done: number; total: number } | null;
  reviewed: number;
  cached: number;
  budgetSkipped: number;
  failedFiles: number;
  notRelevant: number;
  calls: number;
  costUsd: number;
};

const sumCoverage = (c: Record<CoverageStatus, number> | undefined, ...keys: CoverageStatus[]) =>
  c ? keys.reduce((n, k) => n + (c[k] ?? 0), 0) : 0;

export function deriveLanes(args: {
  timeline: Timeline;
  scan: ScanDto;
  progress: Record<string, { done: number; total: number }>;
  warnings: ReadonlyArray<{ code: string; message: string }>;
  diagnostics: Diagnostics | undefined;
}): LaneView[] {
  const { timeline, scan, progress, warnings, diagnostics } = args;
  const enabledCats = new Set(scan.options.categories);
  const stageStatus = (s: AnalyzerDef['stage']) => timeline.stages.find((t) => t.state === s)?.status ?? 'pending';
  const failedIds = new Set(
    warnings.filter((w) => w.code === 'ANALYZER_FAILED').map((w) => w.message.split(' ')[0] ?? ''),
  );

  return ANALYZERS.map((def): LaneView => {
    const cov = diagnostics?.coverage.byAnalyzer[def.id];
    const llm = diagnostics?.llm.byAnalyzer.find((a) => a.analyzer === def.id);
    const p = progress[def.id] ?? null;
    const metrics = {
      progress: p,
      reviewed: sumCoverage(cov, 'reviewed', 'reviewed-fast'),
      cached: sumCoverage(cov, 'cached'),
      budgetSkipped: sumCoverage(cov, 'budget-skipped'),
      failedFiles: sumCoverage(cov, 'failed'),
      notRelevant: sumCoverage(cov, 'not-relevant'),
      calls: llm?.calls ?? 0,
      costUsd: llm?.costUsd ?? 0,
    };
    if (!def.categories.some((c) => enabledCats.has(c))) return { ...def, ...metrics, status: 'off', fraction: 0 };
    if (failedIds.has(def.id)) return { ...def, ...metrics, status: 'failed', fraction: p && p.total > 0 ? p.done / p.total : 1 };

    const st = stageStatus(def.stage);
    let status: LaneStatus;
    switch (st) {
      case 'active': status = 'running'; break;
      case 'done': status = 'done'; break;
      case 'cached': status = 'cached'; break;
      case 'skipped': status = 'skipped'; break;
      case 'failed':
      case 'cancelled': status = 'stopped'; break;
      default: status = 'waiting';
    }
    const fraction =
      status === 'done' || status === 'cached' ? 1
      : p && p.total > 0 ? Math.min(1, p.done / p.total)
      : status === 'running' ? null
      : 0;
    return { ...def, ...metrics, status, fraction };
  });
}

// ---------------------------------------------------------------------------------------------
// Findings + warnings
// ---------------------------------------------------------------------------------------------

/** Analyzer re-runs can re-emit a finding (see analyzeStage M6) — dedupe by id, newest first. */
export function newestFirstFindings(findings: readonly FindingSummary[]): FindingSummary[] {
  const seen = new Set<string>();
  const out: FindingSummary[] = [];
  for (let i = findings.length - 1; i >= 0; i--) {
    const f = findings[i]!;
    if (seen.has(f.id)) continue;
    seen.add(f.id);
    out.push(f);
  }
  return out;
}

export function countBySeverity(findings: readonly FindingSummary[]): Record<Severity, number> {
  const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}

export type WarningItem = { code: string; message: string; stage?: string; level: 'info' | 'warning' };

/** Live warnings when the event log has them, else the DTO's persisted list; deduplicated. */
export function mergeWarnings(live: ReadonlyArray<Extract<ScanEvent, { type: 'warning' }>>, persisted: ScanDto['warnings']): WarningItem[] {
  const src = live.length > 0 ? live : persisted;
  const seen = new Set<string>();
  const out: WarningItem[] = [];
  for (const w of src) {
    const key = `${w.code}\0${w.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ code: w.code, message: w.message, ...(w.stage ? { stage: w.stage } : {}), level: w.level ?? 'warning' });
  }
  return out;
}

const WARNING_TITLES: Record<string, string> = {
  ANALYZER_FAILED: 'An analyzer failed',
  REPO_TOO_LARGE: 'Repository truncated',
  NO_SOURCE_FILES: 'No supported source files',
  VERIFY_PARTIAL: 'Verification incomplete',
  BUDGET_COVERAGE_PARTIAL: 'AI budget ran out',
  CACHE_UNAVAILABLE: 'Cache not reused',
  CACHE_STATUS_PARTIAL: 'Cached result partly refreshed',
  SYNTHESIS_FALLBACK: 'Summary written without AI',
  SCAN_DEADLINE: 'Scan hit its time limit',
  SANDBOX_UNAVAILABLE: 'Sandbox unavailable',
  TRIAGE_FILE_LIMIT: 'Triage file limit reached',
  CREDENTIALS_HISTORY_TRUNCATED: 'Git history truncated',
};

const SUBJECTS: Record<string, string> = {
  TRIAGE: 'Triage', SAST: 'Code review', TAINT: 'Data-flow analysis', QUALITY: 'Quality review', CONFIG: 'Config review',
  CREDENTIALS: 'Credential scan', CREDENTIAL: 'Credential hunter', DEPENDENCY: 'Dependency analysis', SANDBOX: 'Sandbox',
};
const OUTCOMES: Record<string, string> = {
  PARTIAL: 'incomplete', UNAVAILABLE: 'unavailable', FAILED: 'failed', TRUNCATED: 'truncated', DROPPED: 'dropped findings',
  TIMEOUT: 'timed out', MISMATCH: 'version mismatch',
};

/** "SAST_PARTIAL" → "Code review incomplete". Falls back to a sentence-cased code. */
export function warningTitle(code: string): string {
  if (WARNING_TITLES[code]) return WARNING_TITLES[code];
  const parts = code.split('_');
  const subject = SUBJECTS[parts[0] ?? ''];
  const outcome = OUTCOMES[parts[parts.length - 1] ?? ''];
  if (subject && outcome) return `${subject} ${outcome}`;
  const s = code.toLowerCase().replace(/_/g, ' ');
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// ---------------------------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------------------------

/** A ticking clock (ms) while `active`; frozen otherwise. */
export function useNow(active: boolean, intervalMs = 1_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    setNow(Date.now());
    const t = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(t);
  }, [active, intervalMs]);
  return now;
}

const RM_QUERY = '(prefers-reduced-motion: reduce)';
export function useReducedMotion(): boolean {
  return useSyncExternalStore(
    (cb) => {
      const mq = window.matchMedia(RM_QUERY);
      mq.addEventListener('change', cb);
      return () => mq.removeEventListener('change', cb);
    },
    () => window.matchMedia(RM_QUERY).matches,
    () => false,
  );
}
