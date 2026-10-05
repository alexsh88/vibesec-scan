import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { FindingSchema, ScanOptionsSchema, type ScanDto } from '@vibesec/shared';
import {
  createQualityAnalyzer, QUALITY_PROMPT_VERSION, QUALITY_TASK_MARKER, qualityMockResponder,
} from '../src/analyzers/code/quality/qualityAnalyzer';
import type { AnalyzerContext } from '../src/analyzers/types';
import { AppError } from '../src/errors/AppError';
import type { IndexedFile, Language } from '../src/index/types';
import type { LlmClient, StructuredCall, StructuredResult } from '../src/llm/LlmClient';
import { buildRequestParts } from '../src/llm/prompt';
import type { LlmRequest } from '../src/llm/transport';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'vibesec-quality-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

function languageOf(path: string): Language {
  if (path.endsWith('.py')) return 'python';
  if (path.endsWith('.ts')) return 'typescript';
  if (path.endsWith('.js')) return 'javascript';
  if (path.endsWith('.md')) return 'markdown';
  return 'other';
}

async function writeRepoFiles(files: Record<string, string>): Promise<IndexedFile[]> {
  const indexed: IndexedFile[] = [];
  for (const [path, content] of Object.entries(files)) {
    const abs = join(dir, ...path.split('/'));
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, content, 'utf8');
    indexed.push({ path, blobSha: 'deadbeef', size: Buffer.byteLength(content), language: languageOf(path), category: 'source', tags: [], skipReason: null });
  }
  return indexed;
}

function makeScan(): ScanDto {
  return {
    id: 'scan-1',
    repo: { id: 'repo-1', owner: 'acme', name: 'app', isPrivate: false },
    ref: null,
    commitSha: 'c'.repeat(40),
    state: 'ANALYZING',
    errorCode: null,
    errorMessage: null,
    cacheHit: 'none',
    options: ScanOptionsSchema.parse({}),
    costUsd: 0,
    createdAt: new Date().toISOString(),
    startedAt: null,
    finishedAt: null,
    warnings: [],
  };
}

function makeCtx(files: IndexedFile[], opts: { warnings?: string[][] } = {}): AnalyzerContext {
  const scan = makeScan();
  const warnings = opts.warnings ?? [];
  return {
    scanId: scan.id,
    scan,
    repoDir: dir,
    commitSha: scan.commitSha!,
    repo: scan.repo,
    files,
    signal: new AbortController().signal,
    touch: () => {},
    warn: (code, message) => { warnings.push([code, message]); },
    progress: () => {},
  };
}

type QIssue = {
  ruleId: string; title: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'info'; confidence: 'high' | 'medium' | 'low';
  startLine: number; endLine: number; snippet: string; explanation: string; impact: string; remediation: string;
};
type QOut = { issues: QIssue[] };

const ZERO = { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 };

function okResult(issues: QIssue[]): StructuredResult<QOut> {
  return { output: { issues }, model: 'claude-haiku-4-5', usage: ZERO, costUsd: 0, callIds: ['c'], degraded: false, fellBackOnRefusal: false };
}

/** A `Pick<LlmClient, 'structured'>` stub: records every StructuredCall it receives. */
function stubLlm(impl: (call: StructuredCall<QOut>) => Promise<StructuredResult<QOut>>): {
  llm: Pick<LlmClient, 'structured'>;
  calls: StructuredCall<QOut>[];
} {
  const calls: StructuredCall<QOut>[] = [];
  const structured = async (call: StructuredCall<QOut>) => {
    calls.push(call);
    return impl(call);
  };
  return { llm: { structured: structured as unknown as LlmClient['structured'] }, calls };
}

/** Converts a StructuredCall into the LlmRequest a responder would see, and validates the responder's
 *  output against the call's real zod schema (so these tests prove the mock is schema-valid). */
function stubLlmFromResponder(responder: (req: LlmRequest) => unknown): Pick<LlmClient, 'structured'> {
  return {
    async structured<T>(call: StructuredCall<T>): Promise<StructuredResult<T>> {
      const parts = buildRequestParts(call);
      const req: LlmRequest = { model: 'mock', system: parts.system, messages: parts.messages, maxTokens: 100, thinking: false, schema: call.schema };
      const output = responder(req) ?? { issues: [] };
      return { output: call.schema.parse(output), model: 'mock', usage: ZERO, costUsd: 0, callIds: [], degraded: false, fellBackOnRefusal: false };
    },
  };
}

function longFunctionSource(name: string, bodyLines: number): string {
  const body = Array.from({ length: bodyLines }, (_, i) => `  doWork(${i});`).join('\n');
  return [`function ${name}() {`, body, '}', ''].join('\n');
}

describe('createQualityAnalyzer', () => {
  it('reviews every file (worst metrics first) with role fast in budget tier 3, recording coverage', async () => {
    const files = await writeRepoFiles({
      'src/big.ts': longFunctionSource('bigFn', 90), // long-function + deep-ish score, ranks first
      'src/tiny.ts': 'export const a = 1;\n', // trivial: ranks last
    });
    const { llm, calls } = stubLlm(async () => okResult([]));
    const analyzer = createQualityAnalyzer({ llm });
    const ctx = makeCtx(files);
    const coverage = new Map<string, string>();
    ctx.recordCoverage = (a, path, status) => { expect(a).toBe('quality'); coverage.set(path, status); };

    await analyzer.run(ctx);

    expect(calls).toHaveLength(2);
    const c = calls[0]!;
    expect(c.role).toBe('fast');
    expect(c.tier).toBe(3);
    expect(c.analyzer).toBe('quality');
    expect(c.purpose).toBe('quality-review');
    expect(c.promptVersion).toBe(QUALITY_PROMPT_VERSION);
    expect(c.system).toContain(QUALITY_TASK_MARKER);
    expect(c.prompt).toContain('path="src/big.ts"');
    expect(calls[1]!.prompt).toContain('path="src/tiny.ts"');
    expect(Object.fromEntries(coverage)).toEqual({ 'src/big.ts': 'reviewed', 'src/tiny.ts': 'reviewed' });
  });

  it('records files the budget could not cover as budget-skipped, without a per-analyzer warning', async () => {
    const files = await writeRepoFiles({ 'src/a.ts': longFunctionSource('a', 90), 'src/b.ts': 'export const b = 1;\n' });
    const { llm, calls } = stubLlm(async () => { throw new AppError('BUDGET_EXHAUSTED', 'budget', 'out'); });
    const warnings: string[][] = [];
    const ctx = makeCtx(files, { warnings });
    const coverage = new Map<string, string>();
    ctx.recordCoverage = (_a, path, status) => { coverage.set(path, status); };
    expect(await createQualityAnalyzer({ llm }).run(ctx)).toEqual([]);
    expect(calls.length).toBeGreaterThanOrEqual(1);
    expect(warnings).toEqual([]);
    expect(Object.fromEntries(coverage)).toEqual({ 'src/a.ts': 'budget-skipped', 'src/b.ts': 'budget-skipped' });
  });

  it('puts the deterministic metrics in the prompt as facts (never as findings themselves)', async () => {
    const files = await writeRepoFiles({ 'src/big.ts': longFunctionSource('bigFn', 90) });
    const { llm, calls } = stubLlm(async () => okResult([]));
    const findings = await createQualityAnalyzer({ llm }).run(makeCtx(files));

    expect(calls[0]!.prompt).toContain('Metrics for src/big.ts');
    expect(calls[0]!.prompt).toContain('Longest function: "bigFn" lines 1-92');
    expect(findings).toHaveLength(0); // the stub reported no issues: metrics alone never become findings
  });

  it('clamps a severity above medium down to medium', async () => {
    const files = await writeRepoFiles({ 'src/a.ts': 'function f() {\n  doThing();\n}\n' });
    const { llm } = stubLlm(async () => okResult([{
      ruleId: 'quality/swallowed-error', title: 'x', severity: 'critical', confidence: 'high',
      startLine: 2, endLine: 2, snippet: '  doThing();', explanation: 'e', impact: 'i', remediation: 'r',
    }]));
    const findings = await createQualityAnalyzer({ llm }).run(makeCtx(files));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('medium');
    expect(findings[0]!.category).toBe('quality');
    expect(findings[0]!.ruleId).toBe('quality/swallowed-error');
    expect(findings[0]!.producedBy).toEqual(['quality:llm']);
  });

  it('verifies the reported location: drops a hallucinated snippet, keeps/relocates a real one', async () => {
    const files = await writeRepoFiles({ 'src/a.ts': 'function f() {\n  const x = 1;\n  return x;\n}\n' });
    const { llm } = stubLlm(async () => okResult([
      {
        ruleId: 'quality/dead-code', title: 'real', severity: 'low', confidence: 'medium',
        startLine: 2, endLine: 2, snippet: '  const x = 1;', explanation: 'e', impact: 'i', remediation: 'r',
      },
      {
        ruleId: 'quality/fake', title: 'hallucinated', severity: 'low', confidence: 'medium',
        startLine: 2, endLine: 2, snippet: 'this line does not exist anywhere in the file', explanation: 'e', impact: 'i', remediation: 'r',
      },
    ]));
    const findings = await createQualityAnalyzer({ llm }).run(makeCtx(files));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe('quality/dead-code');
    expect(findings[0]!.location.startLine).toBe(2);
  });

  it('fails open per file: a file whose AI review throws produces no findings and warns QUALITY_PARTIAL once; other files are unaffected', async () => {
    const files = await writeRepoFiles({
      'src/ok.ts': 'function f() {\n  doThing();\n}\n',
      'src/bad.ts': 'function g() {\n  doOther();\n}\n',
    });
    const { llm } = stubLlm(async (call) => {
      if (call.prompt.includes('path="src/bad.ts"')) throw new AppError('LLM_UNAVAILABLE', 'transient', 'down');
      return okResult([{
        ruleId: 'quality/x', title: 't', severity: 'low', confidence: 'medium',
        startLine: 2, endLine: 2, snippet: '  doThing();', explanation: 'e', impact: 'i', remediation: 'r',
      }]);
    });
    const warnings: string[][] = [];
    const findings = await createQualityAnalyzer({ llm }).run(makeCtx(files, { warnings }));

    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.file).toBe('src/ok.ts');
    expect(warnings.filter(([code]) => code === 'QUALITY_PARTIAL')).toHaveLength(1);
  });

  it('rethrows cancellation instead of failing open', async () => {
    const files = await writeRepoFiles({ 'src/a.ts': 'function f() {\n  doThing();\n}\n' });
    const { llm } = stubLlm(async () => { throw new AppError('CANCELLED', 'cancelled', 'stop'); });
    await expect(createQualityAnalyzer({ llm }).run(makeCtx(files))).rejects.toMatchObject({ code: 'CANCELLED' });
  });

  it('produces Findings that satisfy FindingSchema', async () => {
    const files = await writeRepoFiles({ 'src/a.ts': 'function f() {\n  doThing();\n}\n' });
    const { llm } = stubLlm(async () => okResult([{
      ruleId: 'Swallowed Error!', title: 't', severity: 'high', confidence: 'high',
      startLine: 2, endLine: 2, snippet: '  doThing();', explanation: 'e', impact: 'i', remediation: 'r',
    }]));
    const findings = await createQualityAnalyzer({ llm }).run(makeCtx(files));
    expect(findings).toHaveLength(1);
    expect(() => FindingSchema.parse(findings[0])).not.toThrow();
    expect(findings[0]!.ruleId).toBe('quality/swallowed-error'); // normalized to quality/<kebab>
  });

  it('skips non-JS/TS/Python files entirely (never sent to the model)', async () => {
    const files = await writeRepoFiles({ 'README.md': '# hi\n', 'src/a.ts': 'const a = 1;\n' });
    const { llm, calls } = stubLlm(async () => okResult([]));
    await createQualityAnalyzer({ llm }).run(makeCtx(files));
    expect(calls).toHaveLength(1);
    expect(calls[0]!.prompt).toContain('path="src/a.ts"');
  });
});

describe('qualityMockResponder', () => {
  it('ignores requests whose system prompt does not carry the quality task marker', () => {
    const req: LlmRequest = {
      model: 'm', system: [{ type: 'text', text: 'some other task' }],
      messages: [{ role: 'user', content: [{ type: 'text', text: 'anything' }] }],
      maxTokens: 100, thinking: false,
    };
    expect(qualityMockResponder(req)).toBeUndefined();
  });

  it('returns one schema-valid, verifiable issue for the longest function', async () => {
    const files = await writeRepoFiles({ 'src/big.ts': longFunctionSource('bigFn', 90) });
    const llm = stubLlmFromResponder(qualityMockResponder);
    const findings = await createQualityAnalyzer({ llm }).run(makeCtx(files));

    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.ruleId).toBe('quality/long-function');
    expect(f.location.file).toBe('src/big.ts');
    expect(f.location.startLine).toBe(1);
    expect(() => FindingSchema.parse(f)).not.toThrow();
  });

  it('returns no issues for a file with no functions', async () => {
    const files = await writeRepoFiles({ 'src/consts.ts': 'export const a = 1;\nexport const b = 2;\n' });
    const llm = stubLlmFromResponder(qualityMockResponder);
    const findings = await createQualityAnalyzer({ llm }).run(makeCtx(files));
    expect(findings).toHaveLength(0);
  });
});
