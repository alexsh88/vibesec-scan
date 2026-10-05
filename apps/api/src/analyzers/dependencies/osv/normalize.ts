/**
 * Normalizes a raw OSV vulnerability record (from /v1/vulns/{id} or the batch API's cached detail)
 * into our `OsvAdvisory` shape, scoped to one concrete package version. Tolerant of unknown
 * fields; any shape we don't recognize, or any record that turns out not to actually affect the
 * given version, normalizes to `null` rather than throwing.
 */
import { z } from 'zod';
import type { Ecosystem, OsvAdvisory, Severity } from '../types';
import { compareVersions, isValidVersion } from '../versions';
import { cvssV3Score, cvssV4Score, severityFromScore } from './cvss';

const EventSchema = z
  .object({
    introduced: z.string().optional(),
    fixed: z.string().optional(),
    last_affected: z.string().optional(),
    limit: z.string().optional(),
  })
  .passthrough();

const RangeSchema = z
  .object({
    type: z.enum(['SEMVER', 'ECOSYSTEM', 'GIT']),
    events: z.array(EventSchema),
  })
  .passthrough();

const AffectedSchema = z
  .object({
    package: z
      .object({
        ecosystem: z.string().optional(),
        name: z.string().optional(),
        purl: z.string().optional(),
      })
      .passthrough()
      .optional(),
    ranges: z.array(RangeSchema).optional(),
    versions: z.array(z.string()).optional(),
    ecosystem_specific: z.unknown().optional(),
    database_specific: z.unknown().optional(),
  })
  .passthrough();

const SeverityEntrySchema = z
  .object({
    type: z.string(),
    score: z.string(),
  })
  .passthrough();

const ReferenceSchema = z
  .object({
    type: z.string().optional(),
    url: z.string(),
  })
  .passthrough();

const OsvRecordSchema = z
  .object({
    id: z.string().min(1),
    summary: z.string().optional(),
    details: z.string().optional(),
    aliases: z.array(z.string()).optional(),
    published: z.string().optional(),
    modified: z.string().optional(),
    severity: z.array(SeverityEntrySchema).optional(),
    affected: z.array(AffectedSchema).optional(),
    references: z.array(ReferenceSchema).optional(),
    database_specific: z.unknown().optional(),
  })
  .passthrough();

type AffectedEntry = z.infer<typeof AffectedSchema>;
type EventEntry = z.infer<typeof EventSchema>;

function normalizeName(eco: Ecosystem, name: string): string {
  return eco === 'PyPI' ? name.toLowerCase().replace(/[-_.]+/g, '-') : name;
}

function safeCompare(eco: Ecosystem, a: string, b: string): number | null {
  try {
    return compareVersions(eco, a, b);
  } catch {
    return null;
  }
}

type Interval = { from: string | undefined; toExclusive: string | undefined; toInclusive: string | undefined };

function buildIntervals(events: readonly EventEntry[]): Interval[] {
  const intervals: Interval[] = [];
  let current: Interval | undefined;
  for (const e of events) {
    if (e.introduced !== undefined) {
      if (current) intervals.push(current);
      current = { from: e.introduced, toExclusive: undefined, toInclusive: undefined };
      continue;
    }
    if (!current) current = { from: undefined, toExclusive: undefined, toInclusive: undefined };
    if (e.fixed !== undefined) current.toExclusive = e.fixed;
    if (e.last_affected !== undefined) current.toInclusive = e.last_affected;
    if (e.limit !== undefined && current.toExclusive === undefined) current.toExclusive = e.limit;
  }
  if (current) intervals.push(current);
  return intervals;
}

function isVersionInRanges(eco: Ecosystem, version: string, ranges: readonly { type: string; events: readonly EventEntry[] }[]): boolean {
  for (const range of ranges) {
    if (range.type !== 'SEMVER' && range.type !== 'ECOSYSTEM') continue;
    for (const iv of buildIntervals(range.events)) {
      if (iv.from !== undefined && iv.from !== '0') {
        const cmp = safeCompare(eco, version, iv.from);
        if (cmp === null || cmp < 0) continue;
      }
      if (iv.toExclusive !== undefined) {
        const cmp = safeCompare(eco, version, iv.toExclusive);
        if (cmp === null || cmp >= 0) continue;
      }
      if (iv.toInclusive !== undefined) {
        const cmp = safeCompare(eco, version, iv.toInclusive);
        if (cmp === null || cmp > 0) continue;
      }
      return true;
    }
  }
  return false;
}

function isVersionAffected(eco: Ecosystem, version: string, affected: AffectedEntry): boolean {
  if (affected.versions?.includes(version)) return true;
  const ranges = affected.ranges ?? [];
  const usableRanges = ranges.filter((r) => r.type === 'SEMVER' || r.type === 'ECOSYSTEM');
  if (usableRanges.length === 0) {
    // No usable ranges: if an explicit (possibly empty) versions list was given and didn't
    // match above, this entry does not cover `version`. Otherwise there is nothing to go on,
    // so we trust that the record lists this package as affected at all.
    return affected.versions === undefined;
  }
  return isVersionInRanges(eco, version, usableRanges);
}

function dedupeSortedVersions(eco: Ecosystem, versions: readonly string[]): string[] {
  const unique = [...new Set(versions)].filter((v) => isValidVersion(eco, v));
  unique.sort((a, b) => compareVersions(eco, a, b));
  return unique;
}

function dedupe(items: readonly string[]): string[] {
  return [...new Set(items)];
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

function extractSymbols(affected: AffectedEntry): string[] {
  const out: string[] = [];
  const es = asRecord(affected.ecosystem_specific);
  if (es) {
    const imports = es.imports;
    if (Array.isArray(imports)) {
      for (const imp of imports) {
        const impRec = asRecord(imp);
        if (impRec) out.push(...asStringArray(impRec.symbols));
      }
    }
    const esAffects = asRecord(es.affects);
    if (esAffects) out.push(...asStringArray(esAffects.functions));
  }
  const ds = asRecord(affected.database_specific);
  if (ds) {
    const dsAffects = asRecord(ds.affects);
    if (dsAffects) out.push(...asStringArray(dsAffects.functions));
  }
  return out;
}

function extractCwes(databaseSpecific: unknown): string[] {
  const ds = asRecord(databaseSpecific);
  return ds ? asStringArray(ds.cwe_ids) : [];
}

function mapDbSeverity(value: unknown): Severity | null {
  const ds = asRecord(value);
  const sev = ds?.severity;
  if (typeof sev !== 'string') return null;
  switch (sev.toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MODERATE':
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return null;
  }
}

type ScoredVector = { score: number; vector: string };

function computeSeverity(
  entries: readonly { type: string; score: string }[],
  databaseSpecific: unknown,
): { severity: Severity; cvss: number | null; cvssVector: string | null } {
  const v4: ScoredVector[] = [];
  const v3: ScoredVector[] = [];
  for (const e of entries) {
    if (e.type === 'CVSS_V4') {
      const score = cvssV4Score(e.score);
      if (score !== null) v4.push({ score, vector: e.score });
    } else if (e.type === 'CVSS_V3') {
      const score = cvssV3Score(e.score);
      if (score !== null) v3.push({ score, vector: e.score });
    }
  }
  const pool = v4.length > 0 ? v4 : v3;
  if (pool.length > 0) {
    const best = pool.reduce((a, b) => (b.score > a.score ? b : a));
    return { severity: severityFromScore(best.score), cvss: best.score, cvssVector: best.vector };
  }
  const dbSeverity = mapDbSeverity(databaseSpecific);
  if (dbSeverity) return { severity: dbSeverity, cvss: null, cvssVector: null };
  return { severity: 'medium', cvss: null, cvssVector: null };
}

function pickUrl(references: readonly { type?: string; url: string }[]): string | null {
  const advisory = references.find((r) => r.type === 'ADVISORY');
  if (advisory) return advisory.url;
  const web = references.find((r) => r.type === 'WEB');
  if (web) return web.url;
  return null;
}

export function normalizeOsv(record: unknown, pkg: { ecosystem: Ecosystem; name: string; version: string }): OsvAdvisory | null {
  const parsed = OsvRecordSchema.safeParse(record);
  if (!parsed.success) return null;
  const rec = parsed.data;

  const pkgNameKey = normalizeName(pkg.ecosystem, pkg.name);
  const matched = (rec.affected ?? []).filter((a) => {
    const aEco = a.package?.ecosystem;
    const aName = a.package?.name;
    if (!aEco || !aName || aEco !== pkg.ecosystem) return false;
    return normalizeName(pkg.ecosystem, aName) === pkgNameKey;
  });
  if (matched.length === 0) return null;
  if (!matched.some((a) => isVersionAffected(pkg.ecosystem, pkg.version, a))) return null;

  const fixedVersions = dedupeSortedVersions(
    pkg.ecosystem,
    matched.flatMap((a) =>
      (a.ranges ?? [])
        .filter((r) => r.type === 'SEMVER' || r.type === 'ECOSYSTEM')
        .flatMap((r) => r.events.map((e) => e.fixed).filter((f): f is string => f !== undefined)),
    ),
  );

  const { severity, cvss, cvssVector } = computeSeverity(rec.severity ?? [], rec.database_specific);

  return {
    id: rec.id,
    aliases: rec.aliases ?? [],
    summary: rec.summary ?? '',
    details: rec.details ?? '',
    severity,
    cvss,
    cvssVector,
    fixedVersions,
    affectedSymbols: dedupe(matched.flatMap((a) => extractSymbols(a))),
    cwes: extractCwes(rec.database_specific),
    url: pickUrl(rec.references ?? []),
    published: rec.published ?? null,
    malicious: rec.id.startsWith('MAL-'),
  };
}
