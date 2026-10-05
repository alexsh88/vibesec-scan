// Credentials analyzer: wires the pure rules/scanners/filters in this directory into the Analyzer
// contract (apps/api/src/analyzers/types.ts). See each submodule's header for its own security notes;
// this file's own responsibility is to never let a raw secret value or pairedSecret leak into a
// returned Finding (see buildFinding below — it only ever reads `.redacted`/`.hash` off a candidate).

import type { Finding, Severity } from '@vibesec/shared';
import { bumpSeverity, fingerprint, githubPermalink, provisionalScore } from '../../findings/helpers';
import { toAppError } from '../../errors/AppError';
import type { GitService } from '../../git/GitService';
import type { LlmClient } from '../../llm/LlmClient';
import type { Analyzer, AnalyzerContext } from '../types';
import { filterCandidates, JUDGEMENT_TYPES, shouldDrop, type FpVerdict } from './fpFilter';
import { scanHistory } from './history';
import type { SecretType } from './rules';
import { scanText, scanTree, type SecretCandidate } from './scanText';
import { CREDENTIAL_TEMPLATES } from './templates';
import type { SecretVerifier, VerifiableSecret, VerifyResult } from './verifiers';

export type CredentialsAnalyzerDeps = {
  llm: Pick<LlmClient, 'structured'>;
  git: Pick<GitService, 'logPatch'>;
  verifier: Pick<SecretVerifier, 'verify' | 'forget'>;
  /** Bounded concurrency for live-verification calls (default 4). */
  maxConcurrentVerifications?: number;
};

type Confidence = 'high' | 'medium' | 'low';

const SEV_ORDER: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
const sevIndex = (s: Severity): number => SEV_ORDER.indexOf(s);
const clampAtLeast = (s: Severity, floor: Severity): Severity => (sevIndex(s) < sevIndex(floor) ? floor : s);

/** Runs `fn` over `items` with at most `limit` in flight; does not stop early on a rejection
 *  (every item still gets a turn; the first rejection is rethrown once all turns have settled). */
async function forEachLimit<T>(items: readonly T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  let firstError: unknown;
  let hasError = false;
  const worker = async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      try {
        await fn(items[i]!);
      } catch (err) {
        if (!hasError) { hasError = true; firstError = err; }
      }
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
  if (hasError) throw firstError;
}

function candidateKey(c: Pick<SecretCandidate, 'type' | 'hash'>): string {
  return `${c.type}|${c.hash}`;
}

/**
 * Merges tree + history candidates per the spec: a history candidate whose (type, hash) also occurs
 * in the tree is dropped (the tree finding is authoritative — the secret is still present today).
 * Remaining history-only candidates are deduped by (type, hash), keeping the newest commit: `logPatch`
 * returns commits newest-first, so the first candidate encountered for a given key is the newest.
 */
function mergeTreeAndHistory(tree: readonly SecretCandidate[], history: readonly SecretCandidate[]): SecretCandidate[] {
  const treeKeys = new Set(tree.map(candidateKey));
  const historyOnly = new Map<string, SecretCandidate>();
  for (const c of history) {
    const key = candidateKey(c);
    if (treeKeys.has(key) || historyOnly.has(key)) continue;
    historyOnly.set(key, c);
  }
  return [...tree, ...historyOnly.values()];
}

function confidenceFor(type: SecretType, verdict: FpVerdict | undefined): Confidence {
  if (!JUDGEMENT_TYPES.has(type)) return 'high';
  if (verdict !== undefined && verdict.isLikelyReal === true && verdict.confidence === 'high') return 'high';
  return 'medium';
}

type RiskFactor = { factor: string; effect: number; reason: string };

/**
 * Applies the liveness/history/exposure adjustments on top of the type's base severity, recording
 * every adjustment that actually moved the needle (post-floor/ceiling) as a riskFactor. Order: live
 * (overrides to critical) or revoked (−2, floored at low) based on liveness; then, only when not live,
 * an additional −1 for history-only (floored at low); then +1 for client exposure (bumpSeverity already
 * ceilings at critical).
 */
function computeSeverity(
  base: Severity,
  secret: { liveness: VerifyResult['liveness']; inHistoryOnly: boolean; clientExposed: boolean },
): { severity: Severity; riskFactors: RiskFactor[] } {
  let current = base;
  const riskFactors: RiskFactor[] = [];

  const apply = (next: Severity, factor: string, reason: string): void => {
    const effect = sevIndex(next) - sevIndex(current);
    if (effect !== 0) riskFactors.push({ factor, effect, reason });
    current = next;
  };

  if (secret.liveness === 'live') {
    apply('critical', 'live', 'Verified live against the provider API');
  } else if (secret.liveness === 'revoked') {
    apply(clampAtLeast(bumpSeverity(current, -2), 'low'), 'revoked', 'Verified revoked/inactive against the provider API');
  }

  if (secret.liveness !== 'live' && secret.inHistoryOnly) {
    apply(clampAtLeast(bumpSeverity(current, -1), 'low'), 'inHistoryOnly', 'Only present in commit history, not the current code');
  }

  if (secret.clientExposed) {
    apply(bumpSeverity(current, 1), 'clientExposed', 'Located in client-exposed code (public/static asset or a *_PUBLIC_-style variable)');
  }

  return { severity: current, riskFactors };
}

function shortSha(sha: string): string {
  return sha.slice(0, 7);
}

function buildFinding(
  ctx: AnalyzerContext,
  candidate: SecretCandidate,
  verify: VerifyResult,
  verdict: FpVerdict | undefined,
): Finding {
  const template = CREDENTIAL_TEMPLATES[candidate.type];
  const inHistoryOnly = candidate.source === 'history';
  const { severity, riskFactors } = computeSeverity(template.baseSeverity, {
    liveness: verify.liveness,
    inHistoryOnly,
    clientExposed: candidate.clientExposed,
  });
  const confidence = confidenceFor(candidate.type, verdict);
  const ruleId = `secret/${candidate.type}`;
  const fp = fingerprint(['secret', ruleId, candidate.file, candidate.hash]);
  const id = fingerprint([ctx.scanId, fp]).slice(0, 32);
  const historyCommit = candidate.commit;
  const explanation = inHistoryOnly && historyCommit !== undefined
    ? `${template.explanation} The value was removed from the current code but remains in commit ${shortSha(historyCommit)}.`
    : template.explanation;
  const producedBy = JUDGEMENT_TYPES.has(candidate.type) && verdict !== undefined ? ['regex+llm'] : ['regex'];

  return {
    id,
    scanId: ctx.scanId,
    fingerprint: fp,
    category: 'secret',
    ruleId,
    cwe: 'CWE-798',
    title: template.title,
    baseSeverity: template.baseSeverity,
    riskScore: provisionalScore(severity),
    severity,
    riskFactors,
    confidence,
    location: {
      file: candidate.file,
      startLine: candidate.line,
      endLine: candidate.endLine,
      startCol: candidate.startCol,
      snippet: candidate.snippet,
      permalink: githubPermalink(ctx.repo, historyCommit ?? ctx.commitSha, candidate.file, candidate.line, candidate.endLine),
    },
    secret: {
      type: candidate.type,
      redacted: candidate.redacted,
      liveness: verify.liveness,
      inHistoryOnly,
      ...(verify.checkedAt !== undefined ? { checkedAt: verify.checkedAt } : {}),
      ...(historyCommit !== undefined ? { commit: historyCommit } : {}),
    },
    explanation,
    impact: template.impact,
    remediation: template.remediation,
    scanStatus: 'new',
    producedBy,
  };
}

function toVerifiable(c: SecretCandidate): VerifiableSecret {
  return {
    type: c.type,
    value: c.value,
    redacted: c.redacted,
    hash: c.hash,
    ...(c.pairedSecret !== undefined ? { pairedSecret: c.pairedSecret } : {}),
  };
}

export function createCredentialsAnalyzer(deps: CredentialsAnalyzerDeps): Analyzer {
  return {
    id: 'credentials',
    version: '1',
    category: 'secret',

    async run(ctx: AnalyzerContext): Promise<Finding[]> {
      const treeResult = await scanTree({ repoDir: ctx.repoDir, files: ctx.files, signal: ctx.signal, touch: ctx.touch });

      let historyCandidates: SecretCandidate[] = [];
      const historyDepth = ctx.scan.options.historyDepth;
      if (historyDepth > 0) {
        try {
          const historyResult = await scanHistory<SecretCandidate>({
            logPatch: (signal) => deps.git.logPatch(ctx.repoDir, historyDepth, signal, ctx.token),
            scan: scanText,
            signal: ctx.signal,
            touch: ctx.touch,
          });
          historyCandidates = historyResult.candidates;
          if (historyResult.truncated) {
            ctx.warn('CREDENTIALS_HISTORY_TRUNCATED', 'Commit history scan was truncated; some older commits were not scanned for credentials');
          }
        } catch (raw) {
          const err = toAppError(raw);
          if (err.kind === 'cancelled' || ctx.signal.aborted) throw err;
          // History scanning is best-effort: never fail the analyzer for it, just report tree results.
          ctx.warn('CREDENTIALS_HISTORY_FAILED', `Scanning commit history for credentials failed: ${err.userMessage}`);
        }
      }

      const merged = mergeTreeAndHistory(treeResult.candidates, historyCandidates);

      const verdicts = await filterCandidates(deps.llm, ctx.scanId, merged, ctx.signal, { warn: ctx.warn });
      const kept = merged.filter((c) => !shouldDrop(verdicts.get(c.id)));

      const verifyEnabled = ctx.scan.options.verifySecrets;
      const findings: Finding[] = [];
      try {
        await forEachLimit(kept, deps.maxConcurrentVerifications ?? 4, async (candidate) => {
          const verify: VerifyResult = verifyEnabled
            ? await deps.verifier.verify(ctx.scanId, toVerifiable(candidate), ctx.signal)
            : { liveness: 'not_checked' };
          ctx.touch();
          findings.push(buildFinding(ctx, candidate, verify, verdicts.get(candidate.id)));
        });
      } finally {
        deps.verifier.forget(ctx.scanId);
      }

      return findings;
    },
  };
}
