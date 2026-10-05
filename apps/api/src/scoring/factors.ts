// SCORING stage, part 1/2 (P7): turns one persisted `Finding` into a flat, typed, deterministic
// bag of signals (`RiskSignals`). This module ONLY reads — it never mutates a Finding, calls the
// network, or touches the DB — so it is trivial to unit-test and safe to call twice (idempotent
// re-scoring, see scoreStage.ts).
//
// Every signal here is derived from either:
//   (a) a field the schema already carries unconditionally (baseSeverity, confidence, secret.*,
//       dependency.*, taintTrace), or
//   (b) a `riskFactors` entry an upstream analyzer already recorded (credentials/dependencies/config
//       — see each analyzer's own computeSeverity/buildFinding for the exact factor names used today).
// (b) has one structural gap worth calling out: some analyzers only push a riskFactor when it
// actually *moved* the severity (`effect !== 0`) — e.g. credentials' `clientExposed` is skipped when
// the secret was already 'critical'. That means a (b)-sourced boolean here can read `false` for a
// real condition that simply had nowhere left to escalate. Documented, not silently hidden: see
// `clientExposed` below.

import type { Finding, Severity } from '@vibesec/shared';

export type FileContext = 'test' | 'example' | 'docs' | 'generated' | 'source';

export type RiskFactorLike = { factor: string; effect: number; reason: string };

export type RiskSignals = {
  /** Echoed through for traceability/debugging in the weighting function and tests; never branch on these. */
  readonly findingId: string;
  readonly category: Finding['category'];
  readonly ruleId: string;

  readonly baseSeverity: Severity;
  readonly confidence: Finding['confidence'];
  /** Max advisory CVSS (0-10) across `dependency.advisories`; null for non-dependency findings or
   *  when no advisory on this finding carries a numeric CVSS. */
  readonly cvss: number | null;

  // --- secret-specific; null/false when the finding has no `secret` block ---
  readonly liveness: NonNullable<Finding['secret']>['liveness'] | null;
  readonly inHistoryOnly: boolean;
  /** See the module header's note on (b)-sourced booleans: this is `riskFactors`-derived only
   *  (the schema has no standalone `clientExposed` field on `secret`), so it can under-report when
   *  the analyzer's own severity bump was a no-op (secret already at 'critical'). */
  readonly clientExposed: boolean;

  // --- dependency-specific; null when the finding has no `dependency` block ---
  readonly reachability: NonNullable<Finding['dependency']>['reachability'] | null;
  readonly scope: NonNullable<Finding['dependency']>['scope'] | null;
  readonly direct: boolean | null;

  /** Path heuristic on `location.file` — see `classifyFileContext`. */
  readonly fileContext: FileContext;
  /** `location.file` is a detected entrypoint, or the taint trace (if any) starts inside one. */
  readonly entrypointExposure: boolean;
  /** Same as `entrypointExposure` but against the (optional, often-absent) known-public subset. */
  readonly publicRouteExposure: boolean;

  /** AI review (config/credentials) explicitly judged this finding a false positive ('ai_refuted' /
   *  'ai_false_positive' — different analyzers named it differently; both mean the same thing). */
  readonly aiRefuted: boolean;
  /** AI review never returned a verdict for this finding ('ai_unreviewed'); fail-open, kept visible. */
  readonly aiUnreviewed: boolean;
  /**
   * The VERIFYING stage's skeptic pass (apps/api/src/findings/skeptic*.ts, developed in parallel on
   * this branch) downgraded this finding. That stage's exact riskFactor name wasn't finalized when
   * this module was written, so detection is a case-insensitive substring match on "skeptic" rather
   * than an exact name — forward-compatible, but re-check this against the real factor name once
   * that stage lands.
   */
  readonly skepticWeakened: boolean;
  /** Known-malicious supply-chain package (ruleId `supply-chain/malicious-package`, or a `malicious`
   *  riskFactor) — never downgraded by reachability/scope upstream. */
  readonly malicious: boolean;

  /**
   * Every `riskFactors` entry that isn't already surfaced as one of the typed flags above (e.g.
   * credentials' `live`/`revoked`, dependencies' `reachability:*`/`devDependency`). Passed through
   * verbatim so the weighting function can use an analyzer signal this module doesn't have a named
   * slot for, without re-parsing `finding.riskFactors` itself.
   */
  readonly otherFactors: readonly RiskFactorLike[];
};

export type RiskSignalContext = {
  /** Repo-relative file paths the indexer flagged as entrypoints (HTTP routes, serverless handlers,
   *  CLIs, scripts, …) — see apps/api/src/index/entrypoints.ts and db/indexRepo.ts#entrypoints. */
  readonly entrypoints: ReadonlySet<string>;
  /**
   * Subset of `entrypoints` known to be reachable without authentication. Optional: nothing in this
   * codebase computes this yet, so when omitted `publicRouteExposure` is simply always false —
   * never a crash, never a silent miscount.
   */
  readonly publicRoutes?: ReadonlySet<string>;
};

const AI_REFUTED_FACTOR_NAMES = new Set(['ai_refuted', 'ai_false_positive']);
const AI_UNREVIEWED_FACTOR_NAMES = new Set(['ai_unreviewed']);
const SKEPTIC_FACTOR_RE = /skeptic/i;
const MALICIOUS_FACTOR_NAME = 'malicious';
const CLIENT_EXPOSED_FACTOR_NAME = 'clientExposed';
export const MALICIOUS_RULE_ID = 'supply-chain/malicious-package';

const TEST_DIR_RE = /(^|\/)(test|__tests__)(\/|$)/i;
const TEST_FILE_RE = /\.(test|spec)\.[^./]+$/i;
const FIXTURES_DIR_RE = /(^|\/)fixtures\//i;
const EXAMPLES_DIR_RE = /(^|\/)examples?\//i;
const DOCS_DIR_RE = /(^|\/)docs\//i;
const MARKDOWN_FILE_RE = /\.md$/i;
const VENDOR_DIR_RE = /(^|\/)vendor\//i;

/**
 * Path-only heuristic (per the spec): test-ish paths first (so e.g. `test/README.md` is 'test', not
 * 'docs'), then examples, then docs, then vendored/generated code, else plain source. Deliberately
 * does not consult the indexer's own `IndexedFile.tags`/`category` — a `Finding` only carries a file
 * path, not the indexed file record, by the time it reaches SCORING.
 */
export function classifyFileContext(path: string): FileContext {
  if (TEST_DIR_RE.test(path) || TEST_FILE_RE.test(path) || FIXTURES_DIR_RE.test(path)) return 'test';
  if (EXAMPLES_DIR_RE.test(path)) return 'example';
  if (DOCS_DIR_RE.test(path) || MARKDOWN_FILE_RE.test(path)) return 'docs';
  if (VENDOR_DIR_RE.test(path)) return 'generated';
  return 'source';
}

function maxCvss(advisories: NonNullable<Finding['dependency']>['advisories']): number | null {
  const scores = advisories.map((a) => a.cvss).filter((c): c is number => c !== null);
  return scores.length > 0 ? Math.max(...scores) : null;
}

/** First file the finding's taint trace touches (its `source` step, conventionally index 0), if any. */
function traceStartFile(finding: Finding): string | undefined {
  return finding.taintTrace?.[0]?.file;
}

export function extractRiskSignals(finding: Finding, ctx: RiskSignalContext): RiskSignals {
  const secret = finding.secret;
  const dependency = finding.dependency;

  let aiRefuted = false;
  let aiUnreviewed = false;
  let skepticWeakened = false;
  let malicious = finding.ruleId === MALICIOUS_RULE_ID;
  let clientExposed = false;
  const otherFactors: RiskFactorLike[] = [];

  for (const rf of finding.riskFactors) {
    let matched = false;
    if (AI_REFUTED_FACTOR_NAMES.has(rf.factor)) { aiRefuted = true; matched = true; }
    if (AI_UNREVIEWED_FACTOR_NAMES.has(rf.factor)) { aiUnreviewed = true; matched = true; }
    if (SKEPTIC_FACTOR_RE.test(rf.factor)) { skepticWeakened = true; matched = true; }
    if (rf.factor === MALICIOUS_FACTOR_NAME) { malicious = true; matched = true; }
    if (rf.factor === CLIENT_EXPOSED_FACTOR_NAME) { clientExposed = true; matched = true; }
    if (!matched) otherFactors.push(rf);
  }

  const startFile = traceStartFile(finding);
  const entrypointExposure = ctx.entrypoints.has(finding.location.file)
    || (startFile !== undefined && ctx.entrypoints.has(startFile));
  const publicRouteExposure = ctx.publicRoutes !== undefined
    && (ctx.publicRoutes.has(finding.location.file) || (startFile !== undefined && ctx.publicRoutes.has(startFile)));

  return {
    findingId: finding.id,
    category: finding.category,
    ruleId: finding.ruleId,
    baseSeverity: finding.baseSeverity,
    confidence: finding.confidence,
    cvss: dependency ? maxCvss(dependency.advisories) : null,
    liveness: secret?.liveness ?? null,
    inHistoryOnly: secret?.inHistoryOnly ?? false,
    clientExposed,
    reachability: dependency?.reachability ?? null,
    scope: dependency?.scope ?? null,
    direct: dependency?.direct ?? null,
    fileContext: classifyFileContext(finding.location.file),
    entrypointExposure,
    publicRouteExposure,
    aiRefuted,
    aiUnreviewed,
    skepticWeakened,
    malicious,
    otherFactors,
  };
}
