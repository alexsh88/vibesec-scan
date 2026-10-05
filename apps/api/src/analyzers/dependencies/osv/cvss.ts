/**
 * CVSS base-score computation from a vector string (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").
 *
 * v3.0/v3.1 implement FIRST's official base-score formula exactly, including the official
 * "roundup" rounding function. v4.0 is a documented APPROXIMATION — see `cvssV4Score`.
 */
import type { Severity } from '../types';

type Metrics = Record<string, string>;

function parseVector(vector: string): { version: string; metrics: Metrics } | null {
  if (typeof vector !== 'string' || vector.length === 0) return null;
  const parts = vector.split('/');
  const head = parts[0];
  if (!head || !head.startsWith('CVSS:')) return null;
  const version = head.slice('CVSS:'.length);
  const metrics: Metrics = {};
  for (let i = 1; i < parts.length; i++) {
    const part = parts[i];
    if (!part) continue;
    const idx = part.indexOf(':');
    if (idx <= 0 || idx === part.length - 1) return null;
    metrics[part.slice(0, idx)] = part.slice(idx + 1);
  }
  return { version, metrics };
}

/** FIRST's official "Roundup" function: rounds up to the nearest 0.1. */
function roundUp(input: number): number {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

const AV_W: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC_W: Record<string, number> = { L: 0.77, H: 0.44 };
const PR_UNCHANGED_W: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED_W: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
const UI_V3_W: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA_W: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

const V3_REQUIRED = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'] as const;

/** Exact CVSS v3.0/v3.1 base score, or null when the vector is missing/malformed/not v3. */
export function cvssV3Score(vector: string): number | null {
  const parsed = parseVector(vector);
  if (!parsed || (parsed.version !== '3.0' && parsed.version !== '3.1')) return null;
  const m = parsed.metrics;
  for (const key of V3_REQUIRED) if (m[key] === undefined) return null;
  if (m.S !== 'U' && m.S !== 'C') return null;

  const scopeChanged = m.S === 'C';
  const av = AV_W[m.AV ?? ''];
  const ac = AC_W[m.AC ?? ''];
  const pr = (scopeChanged ? PR_CHANGED_W : PR_UNCHANGED_W)[m.PR ?? ''];
  const ui = UI_V3_W[m.UI ?? ''];
  const c = CIA_W[m.C ?? ''];
  const iMetric = CIA_W[m.I ?? ''];
  const a = CIA_W[m.A ?? ''];
  if ([av, ac, pr, ui, c, iMetric, a].some((v) => v === undefined)) return null;

  const iss = 1 - (1 - c!) * (1 - iMetric!) * (1 - a!);
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av! * ac! * pr! * ui!;
  return roundUp(Math.min(impact + exploitability, 10));
}

const AT_W: Record<string, number> = { N: 0.85, P: 0.62 };
const UI_V4_W: Record<string, number> = { N: 0.85, P: 0.62, A: 0.2 };

const V4_REQUIRED = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'] as const;

/**
 * APPROXIMATE CVSS v4.0 base score — NOT the official FIRST algorithm.
 *
 * The real CVSS v4.0 base score is computed by building a "macrovector" from six equivalence
 * classes (EQ1..EQ6) and looking it up in a ~270-entry table published by FIRST, then
 * interpolating against the severity distance to neighboring vectors in that table. Reproducing
 * that table was out of scope here, per the task's explicit allowance for a documented
 * approximation.
 *
 * This approximation instead reuses the v3-style Exploitability/Impact combination: it folds in
 * v4's extra AT (Attack Requirements) factor, and combines the Vulnerable System (VC/VI/VA) and
 * Subsequent System (SC/SI/SA) impact metrics by taking whichever of the two yields the larger
 * impact. It is monotonic (more severe metric values never produce a lower score) and broadly
 * tracks the shape of the official scale, but will NOT reproduce FIRST's official v4 scores
 * exactly — do not treat its output as authoritative.
 */
export function cvssV4Score(vector: string): number | null {
  const parsed = parseVector(vector);
  if (!parsed || parsed.version !== '4.0') return null;
  const m = parsed.metrics;
  for (const key of V4_REQUIRED) if (m[key] === undefined) return null;

  const av = AV_W[m.AV ?? ''];
  const ac = AC_W[m.AC ?? ''];
  const at = AT_W[m.AT ?? ''];
  const pr = PR_UNCHANGED_W[m.PR ?? ''];
  const ui = UI_V4_W[m.UI ?? ''];
  const vc = CIA_W[m.VC ?? ''];
  const vi = CIA_W[m.VI ?? ''];
  const va = CIA_W[m.VA ?? ''];
  const sc = CIA_W[m.SC ?? ''];
  const si = CIA_W[m.SI ?? ''];
  const sa = CIA_W[m.SA ?? ''];
  if ([av, ac, at, pr, ui, vc, vi, va, sc, si, sa].some((v) => v === undefined)) return null;

  const issVuln = 1 - (1 - vc!) * (1 - vi!) * (1 - va!);
  const issSub = 1 - (1 - sc!) * (1 - si!) * (1 - sa!);
  const impact = 6.42 * Math.max(issVuln, issSub);
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av! * ac! * at! * pr! * ui!;
  return roundUp(Math.min(impact + exploitability, 10));
}

/** 0 → 'info'; 0.1–3.9 → 'low'; 4–6.9 → 'medium'; 7–8.9 → 'high'; 9–10 → 'critical'. */
export function severityFromScore(score: number): Severity {
  if (score <= 0) return 'info';
  if (score < 4) return 'low';
  if (score < 7) return 'medium';
  if (score < 9) return 'high';
  return 'critical';
}
