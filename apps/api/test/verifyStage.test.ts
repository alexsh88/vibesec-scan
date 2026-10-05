import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { FindingSchema, type Finding, type ScanEvent } from '@vibesec/shared';
import { FindingRepo } from '../src/db/findingRepo';
import { ScanRepo, type ScanWarning } from '../src/db/scanRepo';
import { AppError } from '../src/errors/AppError';
import { skepticMockResponder } from '../src/findings/skeptic';
import type { LlmClient, StructuredCall, StructuredResult } from '../src/llm/LlmClient';
import { buildRequestParts } from '../src/llm/prompt';
import type { LlmRequest } from '../src/llm/transport';
import { readRepoFile, verifyStage } from '../src/pipeline/stages/verifyStage';
import type { PipelineContext } from '../src/pipeline/types';
import { mkFinding } from './findingFactory';
import { memoryDb } from './helpers';

const ZERO = { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 };
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

const REDIRECT = [
  "import { Router } from 'express';",
  'export const r = Router();',
  "r.get('/go', (req, res) => {",
  '  const target = req.query.to as string;',
  '  res.redirect(target);',
  '});',
  "r.get('/go-safe', (req, res) => {",
  '  const target = req.query.to as string;',
  "  if (!target.startsWith('/') || target.startsWith('//')) return res.status(400).end();",
  '  res.redirect(target);',
  '});',
  '// ---', '// ---', '// ---', '// ---', '// ---', '// ---',
  "r.get('/run', (req, res) => {",
  '  run(req.query.c);',
  '});',
].join('\n');

function mockLlm(override?: (call: StructuredCall<unknown>) => Promise<unknown>) {
  const calls: StructuredCall<unknown>[] = [];
  const llm = {
    async structured<T>(call: StructuredCall<T>): Promise<StructuredResult<T>> {
      calls.push(call as StructuredCall<unknown>);
      if (override) await override(call as StructuredCall<unknown>);
      const parts = buildRequestParts(call);
      const req: LlmRequest = { model: 'mock', system: parts.system, messages: parts.messages, maxTokens: 100, thinking: false, schema: call.schema };
      return { output: call.schema.parse(skepticMockResponder(req)), model: 'mock', usage: ZERO, costUsd: 0, callIds: [], degraded: false, fellBackOnRefusal: false };
    },
  } as Pick<LlmClient, 'structured'>;
  return { llm, calls };
}

function setup() {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const findings = new FindingRepo(db);
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const scanId = scans.insertScan({
    repoId: repo.id, ref: null, options: { verifySecrets: false, historyDepth: 50, categories: ['sast', 'taint'] },
    optionsHash: randomUUID(), idempotencyKey: null, hasAuth: false,
  }).id;
  const root = mkdtempSync(join(tmpdir(), 'vs-verify-'));
  dirs.push(root);
  const repoDir = join(root, 'repo');
  mkdirSync(join(repoDir, 'api'), { recursive: true });
  writeFileSync(join(repoDir, 'api', 'redirect.ts'), REDIRECT);
  writeFileSync(join(root, 'outside.ts'), 'outside');
  const controller = new AbortController();
  const warnings: ScanWarning[] = [];
  const events: ScanEvent[] = [];
  const ctx: PipelineContext = {
    scanId, scan: scans.getDto(scanId)!, secrets: {}, signal: controller.signal, checkpointData: {},
    emit: (e) => { events.push(e); }, warn: (w) => { warnings.push(w); }, touch: () => {},
  };
  const f = (o: Parameters<typeof mkFinding>[0]): Finding => mkFinding({ scanId, file: 'api/redirect.ts', ...o });
  return { findings, scanId, ctx, warnings, events, controller, repoDir, git: { repoDir: () => repoDir }, f };
}

function seed(s: ReturnType<typeof setup>) {
  const sastRaw = s.f({ ruleId: 'sast/open-redirect', cwe: 'CWE-601', line: 5 });
  const taintRaw = s.f({
    category: 'taint', ruleId: 'taint/unvalidated-redirect', cwe: undefined, line: 5, producedBy: ['taint:agent'],
    taintTrace: [
      { kind: 'source', file: 'api/redirect.ts', line: 4, code: 'req.query.to', note: '' },
      { kind: 'sink', file: 'api/redirect.ts', line: 5, code: 'res.redirect(target)', note: '' },
    ],
  });
  const sastSafe = s.f({ ruleId: 'sast/open-redirect', cwe: 'CWE-601', line: 10 });
  const authn = s.f({ ruleId: 'vibesec/missing-authn', cwe: 'CWE-306', line: 18, endLine: 20 });
  const cmd = s.f({ ruleId: 'sast/command-injection', cwe: 'CWE-78', severity: 'critical', line: 19 });
  const quality = s.f({ category: 'quality', ruleId: 'quality/null-dereference', cwe: undefined, severity: 'medium', line: 9 });
  s.findings.replaceForAnalyzer(s.scanId, 'sast', [sastRaw, sastSafe, authn, cmd]);
  s.findings.replaceForAnalyzer(s.scanId, 'taint', [taintRaw]);
  s.findings.replaceForAnalyzer(s.scanId, 'quality', [quality]);
  return { sastRaw, taintRaw, sastSafe, authn, cmd, quality };
}

const state = (s: ReturnType<typeof setup>) => s.findings.all(s.scanId).map((r) => r.finding).sort((a, b) => (a.id < b.id ? -1 : 1));

describe('verifyStage', () => {
  it('is the degradable VERIFYING stage', () => {
    const st = verifyStage({ findings: new FindingRepo(memoryDb()), llm: mockLlm().llm, git: { repoDir: () => '/x' } });
    expect(st.name).toBe('VERIFYING');
    expect(st.fatal).toBe(false);
  });

  it('dedupes across analyzers, runs the skeptic, refutes (not hides) the sanitized redirect, persists once', async () => {
    const s = setup();
    const seeded = seed(s);
    const { llm, calls } = mockLlm();
    await verifyStage({ findings: s.findings, llm, git: s.git }).run(s.ctx);

    const after = new Map(state(s).map((f) => [f.id, f]));
    expect(after.has(seeded.sastRaw.id)).toBe(false);
    const winner = after.get(seeded.taintRaw.id)!;
    expect(winner.producedBy).toEqual(['taint:agent', 'sast:llm', 'skeptic:upheld']);
    expect(winner.explanation).toContain('Also reported by: sast (sast/open-redirect');

    const safe = after.get(seeded.sastSafe.id)!;
    expect(safe.severity).toBe('info');
    expect(safe.confidence).toBe('low');
    expect(safe.riskFactors[0]!.factor).toBe('ai_refuted');

    expect(after.get(seeded.authn.id)!.producedBy).toContain('skeptic:upheld');
    expect(after.get(seeded.cmd.id)!.severity).toBe('critical');
    expect(after.get(seeded.quality.id)).toEqual(seeded.quality);
    expect(after.size).toBe(5);
    for (const f of after.values()) expect(() => FindingSchema.parse(f)).not.toThrow();

    expect(calls).toHaveLength(1); // 4 findings in one file → one batch
    expect(s.warnings).toEqual([]);
    expect(s.events.every((e) => e.type === 'progress')).toBe(true);
    expect(s.events.at(-1)).toEqual({ type: 'progress', analyzer: 'verify', done: 1, total: 1 });
  });

  it('is idempotent: a second run changes nothing and makes no LLM calls', async () => {
    const s = setup();
    seed(s);
    const { llm, calls } = mockLlm();
    const stage = verifyStage({ findings: s.findings, llm, git: s.git });
    await stage.run(s.ctx);
    const first = state(s);
    const n = calls.length;
    await stage.run(s.ctx);
    expect(state(s)).toEqual(first);
    expect(calls).toHaveLength(n);
  });

  it('fails open: LLM failure keeps the dedupe result, findings unverified, one VERIFY_PARTIAL warning', async () => {
    const s = setup();
    const seeded = seed(s);
    const { llm } = mockLlm(async () => { throw new AppError('LLM_UNAVAILABLE', 'transient', 'provider said: raw details'); });
    await verifyStage({ findings: s.findings, llm, git: s.git }).run(s.ctx);
    const after = new Map(state(s).map((f) => [f.id, f]));
    expect(after.has(seeded.sastRaw.id)).toBe(false);
    expect(after.get(seeded.sastSafe.id)!.severity).toBe('high');
    expect(s.warnings).toHaveLength(1);
    expect(s.warnings[0]).toMatchObject({ code: 'VERIFY_PARTIAL', stage: 'VERIFYING' });
    expect(s.warnings[0]!.message).toContain('transport');
    expect(s.warnings[0]!.message).not.toContain('raw details');
  });

  it('propagates cancellation without persisting', async () => {
    const s = setup();
    seed(s);
    const before = state(s);
    const { llm } = mockLlm(async () => {
      s.controller.abort();
      throw new AppError('CANCELLED', 'cancelled', 'cancelled');
    });
    await expect(verifyStage({ findings: s.findings, llm, git: s.git }).run(s.ctx)).rejects.toMatchObject({ kind: 'cancelled' });
    expect(state(s)).toEqual(before);
  });

  it('no findings → no calls, no writes', async () => {
    const s = setup();
    const { llm, calls } = mockLlm();
    await verifyStage({ findings: s.findings, llm, git: s.git }).run(s.ctx);
    expect(calls).toHaveLength(0);
    expect(s.warnings).toEqual([]);
  });

  it('reads code repo-confined only', async () => {
    const s = setup();
    expect(await readRepoFile(s.repoDir, 'api/redirect.ts')).toBe(REDIRECT);
    expect(await readRepoFile(s.repoDir, '../outside.ts')).toBeNull();
    expect(await readRepoFile(s.repoDir, 'missing.ts')).toBeNull();
  });
});
