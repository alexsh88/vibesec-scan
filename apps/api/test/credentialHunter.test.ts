import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { FindingSchema, ScanOptionsSchema, type ScanDto } from '@vibesec/shared';
import {
  createCredentialHunter, credentialHunterMockResponder, selectHunterFiles,
  CREDENTIAL_HUNTER_PROMPT_VERSION, CREDENTIAL_HUNTER_TASK_MARKER, type CredentialHunterDeps,
} from '../src/analyzers/credentials/hunter';
import type { FileTriage, TriageResult } from '../src/analyzers/code/types';
import type { AnalyzerContext } from '../src/analyzers/types';
import { AppError } from '../src/errors/AppError';
import type { IndexedFile } from '../src/index/types';
import type { LlmClient, StructuredCall, StructuredResult } from '../src/llm/LlmClient';
import { estimateTokens, untrustedFile } from '../src/llm/prompt';
import type { LlmRequest } from '../src/llm/transport';
import { fake } from './fakeCredentials';

const ZERO_USAGE = { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 };

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'vibesec-cred-hunter-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

async function writeRepoFiles(files: Record<string, string>, overrides: Partial<Record<string, Partial<IndexedFile>>> = {}): Promise<IndexedFile[]> {
  const indexed: IndexedFile[] = [];
  for (const [path, content] of Object.entries(files)) {
    const abs = join(dir, ...path.split('/'));
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, content, 'utf8');
    indexed.push({
      path, blobSha: 'deadbeef', size: Buffer.byteLength(content), language: 'other', category: 'other',
      tags: [], skipReason: null, ...(overrides[path] ?? {}),
    });
  }
  return indexed;
}

function makeScan(): ScanDto {
  return {
    id: 'scan-1', repo: { id: 'repo-1', owner: 'acme', name: 'app', isPrivate: false }, ref: null,
    commitSha: 'c'.repeat(40), state: 'ANALYZING', errorCode: null, errorMessage: null, cacheHit: 'none',
    options: ScanOptionsSchema.parse({}), costUsd: 0, createdAt: new Date().toISOString(),
    startedAt: null, finishedAt: null, warnings: [],
  };
}

function makeCtx(files: IndexedFile[], opts: { warnings?: string[][]; signal?: AbortSignal } = {}): AnalyzerContext {
  const scan = makeScan();
  const warnings = opts.warnings ?? [];
  return {
    scanId: scan.id, scan, repoDir: dir, commitSha: scan.commitSha!, repo: scan.repo, files,
    signal: opts.signal ?? new AbortController().signal, touch: () => {},
    warn: (code, message) => { warnings.push([code, message]); }, progress: () => {},
  };
}

function triageStub(credentialRisk: Record<string, boolean> = {}): CredentialHunterDeps['triage'] {
  const entries: [string, FileTriage][] = Object.entries(credentialRisk).map(([path, risk]) => [
    path, { path, relevance: 3, sources: [], sinks: [], securityTopics: ['secrets'], credentialRisk: risk },
  ]);
  const result: TriageResult = { files: new Map(entries), skipped: [], warnings: [] };
  return { forScan: async () => result };
}

/** Adapts a raw implementation (return value or throw) into `Pick<LlmClient, 'structured'>`. */
function stubLlm<T>(impl: (call: StructuredCall<T>) => unknown | Promise<unknown>): {
  llm: Pick<LlmClient, 'structured'>; calls: StructuredCall<T>[];
} {
  const calls: StructuredCall<T>[] = [];
  const structured = async (call: StructuredCall<T>): Promise<StructuredResult<T>> => {
    calls.push(call);
    const output = await impl(call);
    return { output: call.schema.parse(output) as T, model: 'mock', usage: ZERO_USAGE, costUsd: 0, callIds: ['c'], degraded: false, fellBackOnRefusal: false };
  };
  return { llm: { structured: structured as unknown as LlmClient['structured'] }, calls };
}

/** Routes a StructuredCall through a MockResponder-shaped function, the way createTransport/MockTransport would. */
function stubLlmFromResponder(responder: (req: LlmRequest) => unknown = credentialHunterMockResponder) {
  return stubLlm((call: StructuredCall<unknown>) => {
    const req: LlmRequest = {
      model: 'mock', system: [{ type: 'text', text: call.system }],
      messages: [{ role: 'user', content: [{ type: 'text', text: call.prompt }] }],
      maxTokens: 100, thinking: false, schema: call.schema,
    };
    return responder(req) ?? { results: [] };
  });
}

function makeAnalyzer(llm: Pick<LlmClient, 'structured'>, triage: CredentialHunterDeps['triage'], extra: Partial<CredentialHunterDeps> = {}) {
  return createCredentialHunter({ llm, triage, ...extra });
}

// --- selection --------------------------------------------------------------------------------

describe('selectHunterFiles', () => {
  function file(path: string, over: Partial<IndexedFile> = {}): IndexedFile {
    return { path, blobSha: 'x', size: 100, language: 'other', category: 'other', tags: [], skipReason: null, ...over };
  }

  it('selects config/CI/infra files by path alone', () => {
    const files = [
      file('.github/workflows/ci.yml'),
      file('Dockerfile'),
      file('docker-compose.yml'),
      file('.env'),
      file('infra/main.tf'),
      file('settings.py'),
      file('src/config.js'),
      file('config/app.json'),
    ];
    const selected = selectHunterFiles(files, new Set(), 200 * 1024);
    expect(selected.map((f) => f.path).sort()).toEqual(files.map((f) => f.path).sort());
  });

  it('excludes .env.example, lockfiles, vendor/minified/symlinked files, and oversized files', () => {
    const files = [
      file('.env.example'),
      file('package-lock.json', { category: 'lockfile' }),
      file('vendor/thing.yml', { skipReason: 'vendor' }),
      file('dist/bundle.min.json', { skipReason: 'minified' }),
      file('config/link.yml', { skipReason: 'symlink' }),
      file('config/huge.yml', { size: 500 * 1024 }),
    ];
    const selected = selectHunterFiles(files, new Set(), 200 * 1024);
    expect(selected).toHaveLength(0);
  });

  it('includes source files the triage pass flagged credentialRisk, but not other source files', () => {
    const files = [file('src/payment.ts'), file('src/util.ts')];
    const selected = selectHunterFiles(files, new Set(['src/payment.ts']), 200 * 1024);
    expect(selected.map((f) => f.path)).toEqual(['src/payment.ts']);
  });

  it('prioritizes env files, then other config/CI/infra files, then credentialRisk source files, with no count cap', () => {
    const files = [file('src/risky.ts'), file('Dockerfile'), file('.env'), ...Array.from({ length: 40 }, (_, i) => file(`config/c${i}.yml`))];
    const selected = selectHunterFiles(files, new Set(['src/risky.ts']), 200 * 1024);
    expect(selected).toHaveLength(43);
    expect(selected.map((f) => f.path).slice(0, 2)).toEqual(['.env', 'Dockerfile']);
    expect(selected.at(-1)!.path).toBe('src/risky.ts');
  });
});

// --- batching -----------------------------------------------------------------------------------

describe('createCredentialHunter batching', () => {
  it('packs small files into a single batch', async () => {
    const files = await writeRepoFiles({ 'a.env': 'FOO=1', 'b.env': 'BAR=2', 'c.env': 'BAZ=3' });
    const { llm, calls } = stubLlm(async () => ({ results: [] }));
    const analyzer = makeAnalyzer(llm, triageStub());

    await analyzer.run(makeCtx(files));

    expect(calls).toHaveLength(1);
    for (const f of files) expect(calls[0]!.prompt).toContain(`path="${f.path}"`);
    expect(calls[0]).toMatchObject({ analyzer: 'credential-hunter', purpose: 'credential-hunt', role: 'fast', promptVersion: CREDENTIAL_HUNTER_PROMPT_VERSION });
  });

  it('splits into multiple batches once the token budget is exceeded', async () => {
    const content = 'x'.repeat(300); // no trailing newline -> exactly one numbered line per file
    const files = await writeRepoFiles({ 'a.env': content, 'b.env': content, 'c.env': content });
    const blockTokens = estimateTokens(untrustedFile('a.env', `1: ${content}`));
    const { llm, calls } = stubLlm(async () => ({ results: [] }));
    const analyzer = makeAnalyzer(llm, triageStub(), { batchTokens: blockTokens * 2 });

    await analyzer.run(makeCtx(files));

    expect(calls).toHaveLength(2); // ceil(3 files / 2 per batch)
    const allPrompts = calls.map((c) => c.prompt).join('\n');
    for (const f of files) expect(allPrompts).toContain(`path="${f.path}"`);
  });

  it('after a budget refusal, records the refused and every later batch as budget-skipped (no further calls)', async () => {
    const content = 'x'.repeat(300);
    const files = await writeRepoFiles({ 'a.env': content, 'b.env': content, 'c.env': content });
    const blockTokens = estimateTokens(untrustedFile('a.env', `1: ${content}`));
    const { llm, calls } = stubLlm(async () => { throw new AppError('BUDGET_EXHAUSTED', 'budget', 'out'); });
    const warnings: string[][] = [];
    const ctx = makeCtx(files, { warnings });
    const coverage = new Map<string, string>();
    ctx.recordCoverage = (a, path, status) => { expect(a).toBe('credential-hunter'); coverage.set(path, status); };
    await makeAnalyzer(llm, triageStub(), { batchTokens: blockTokens }).run(ctx);
    expect(calls).toHaveLength(1);
    expect(warnings).toEqual([]);
    expect(Object.fromEntries(coverage)).toEqual({ 'a.env': 'budget-skipped', 'b.env': 'budget-skipped', 'c.env': 'budget-skipped' });
  });
});

// --- verification (drops hallucinations) ---------------------------------------------------------

describe('verification', () => {
  it('drops a result whose snippet is not found anywhere in the file, while keeping a verified one from the same batch', async () => {
    const files = await writeRepoFiles({
      'config/app.yml': 'service:\n  name: demo\n  mode: production\n',
      'config/other.yml': 'auth:\n  licenseSeed: zzzzzzzzzzzzzzzzzzzzzzzzzzzz\n',
    });
    const { llm } = stubLlm(async () => ({
      results: [
        { file: 'config/app.yml', startLine: 2, snippet: 'this text does not exist anywhere in the file', kind: 'custom-token', description: 'hallucinated', confidence: 'high' },
        { file: 'config/other.yml', startLine: 2, snippet: '  licenseSeed: zzzzzzzzzzzzzzzzzzzzzzzzzzzz', kind: 'custom-token', description: 'internal license seed, non-standard format', confidence: 'high' },
      ],
    }));
    const analyzer = makeAnalyzer(llm, triageStub());

    const findings = await analyzer.run(makeCtx(files));

    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.file).toBe('config/other.yml');
    expect(findings[0]!.location.startLine).toBe(2);
  });

  it('relocates a result reported at the wrong line to where the snippet actually is', async () => {
    const files = await writeRepoFiles({ 'config/app.yml': 'service:\n  name: demo\n  licenseSeed: zzzzzzzzzzzzzzzzzzzzzzzzzzzz\n' });
    const { llm } = stubLlm(async () => ({
      results: [{ file: 'config/app.yml', startLine: 1, snippet: '  licenseSeed: zzzzzzzzzzzzzzzzzzzzzzzzzzzz', kind: 'custom-token', description: 'license seed', confidence: 'high' }],
    }));
    const analyzer = makeAnalyzer(llm, triageStub());

    const findings = await analyzer.run(makeCtx(files));

    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.startLine).toBe(3);
  });
});

// --- masking --------------------------------------------------------------------------------------

describe('masking', () => {
  it('never leaks the raw value for a split-string credential or a base64-encoded one', async () => {
    const files = await writeRepoFiles({
      'src/config.js': [
        "const dbPassword = 'AK' + 'IA1234567890ABCDEFGH';",
        "const authToken = Buffer.from('c3VwZXJzZWNyZXR0b2tlbnZhbHVl', 'base64').toString('utf8');",
        '',
      ].join('\n'),
    });
    const { llm } = stubLlmFromResponder();
    const analyzer = makeAnalyzer(llm, triageStub());

    const findings = await analyzer.run(makeCtx(files));

    const kinds = findings.map((f) => f.secret!.type).sort();
    expect(kinds).toEqual(['hunter-encoded', 'hunter-split-string']);

    const serialized = JSON.stringify(findings);
    expect(serialized).not.toContain('IA1234567890ABCDEFGH');
    expect(serialized).not.toContain('AKIA1234567890ABCDEFGH');
    expect(serialized).not.toContain('c3VwZXJzZWNyZXR0b2tlbnZhbHVl');
    for (const f of findings) expect(() => FindingSchema.parse(f)).not.toThrow();
  });

  it('masks a connection-object password literal reported by the model', async () => {
    const files = await writeRepoFiles({
      'config/db.yml': "connection:\n  password: 'zzzzzzzzzzzzzzzzzzzz'\n",
    });
    const rawPassword = 'zzzzzzzzzzzzzzzzzzzz';
    const { llm } = stubLlm(async () => ({
      results: [{ file: 'config/db.yml', startLine: 2, snippet: `  password: '${rawPassword}'`, kind: 'connection-password', description: 'DB connection password literal', confidence: 'high' }],
    }));
    const analyzer = makeAnalyzer(llm, triageStub());

    const findings = await analyzer.run(makeCtx(files));

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('high'); // connection-password + high confidence
    expect(JSON.stringify(findings)).not.toContain(rawPassword);
  });
});

// --- dedupe against the regex scanner --------------------------------------------------------------

describe('dedupe vs the regex credential scanner', () => {
  it('drops a hunter result that overlaps a regex-recognizable candidate on the same file+line', async () => {
    const token = fake.github();
    const files = await writeRepoFiles({ 'config/app.yml': `ghToken: ${token}\nother: value\n` });
    const { llm } = stubLlm(async () => ({
      results: [{ file: 'config/app.yml', startLine: 1, snippet: `ghToken: ${token}`, kind: 'other', description: 'looks like a token', confidence: 'high' }],
    }));
    const analyzer = makeAnalyzer(llm, triageStub());

    const findings = await analyzer.run(makeCtx(files));

    expect(findings).toHaveLength(0);
  });

  it('keeps a hunter result on a line the regex scanner does not already cover', async () => {
    const files = await writeRepoFiles({ 'config/app.yml': "licenseSeed: 'zzzzzzzzzzzzzzzzzzzzzzzzzzzz'\n" });
    const { llm } = stubLlm(async () => ({
      results: [{ file: 'config/app.yml', startLine: 1, snippet: "licenseSeed: 'zzzzzzzzzzzzzzzzzzzzzzzzzzzz'", kind: 'custom-token', description: 'internal license seed', confidence: 'high' }],
    }));
    const analyzer = makeAnalyzer(llm, triageStub());

    const findings = await analyzer.run(makeCtx(files));

    expect(findings).toHaveLength(1);
  });
});

// --- fail-open ----------------------------------------------------------------------------------

describe('fail-open', () => {
  it('warns CREDENTIAL_HUNTER_PARTIAL and returns no findings (not a throw) when the LLM call fails', async () => {
    const files = await writeRepoFiles({ '.env': 'FOO=bar\n' });
    const { llm } = stubLlm(async () => { throw new Error('llm unavailable'); });
    const warnings: string[][] = [];
    const analyzer = makeAnalyzer(llm, triageStub());

    const findings = await analyzer.run(makeCtx(files, { warnings }));

    expect(findings).toEqual([]);
    expect(warnings.filter(([code]) => code === 'CREDENTIAL_HUNTER_PARTIAL')).toHaveLength(1);
  });
});

// --- cancellation ---------------------------------------------------------------------------------

describe('cancellation', () => {
  it('rejects immediately on an already-aborted signal, before calling triage or the LLM', async () => {
    const files = await writeRepoFiles({ '.env': 'FOO=bar\n' });
    const controller = new AbortController();
    controller.abort();
    const forScan = vi.fn();
    const { llm } = stubLlm(async () => ({ results: [] }));
    const analyzer = makeAnalyzer(llm, { forScan });

    await expect(analyzer.run(makeCtx(files, { signal: controller.signal }))).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(forScan).not.toHaveBeenCalled();
  });

  it('propagates a cancellation thrown by the LLM call instead of failing open', async () => {
    const files = await writeRepoFiles({ '.env': 'FOO=bar\n' });
    const { llm } = stubLlm(async () => { throw new AppError('CANCELLED', 'cancelled', 'stop'); });
    const analyzer = makeAnalyzer(llm, triageStub());

    await expect(analyzer.run(makeCtx(files))).rejects.toMatchObject({ code: 'CANCELLED' });
  });
});

// --- mock responder --------------------------------------------------------------------------------

describe('credentialHunterMockResponder', () => {
  function requestFor(prompt: string, system = `${CREDENTIAL_HUNTER_TASK_MARKER}\nhunt for credentials`): LlmRequest {
    return {
      model: 'mock', system: [{ type: 'text', text: system }],
      messages: [{ role: 'user', content: [{ type: 'text', text: prompt }] }],
      maxTokens: 100, thinking: false,
    };
  }

  it('ignores requests whose system prompt does not carry the task marker', () => {
    expect(credentialHunterMockResponder(requestFor('anything', 'some other task'))).toBeUndefined();
  });

  it('flags a split-string concatenation assigned to a credential-like name, reconstructed=true', () => {
    const prompt = untrustedFile('src/config.js', "1: const apiToken = 'AAAA' + 'BBBBBBBBBBBB';");
    const out = credentialHunterMockResponder(requestFor(prompt)) as { results: unknown[] } | undefined;
    expect(out).toBeDefined();
    expect(out!.results).toEqual([
      expect.objectContaining({ file: 'src/config.js', startLine: 1, kind: 'split-string', reconstructed: true }),
    ]);
  });

  it('flags a Buffer.from(..., "base64") literal, reconstructed=true', () => {
    const prompt = untrustedFile('src/config.js', "1: const key = Buffer.from('c3VwZXJzZWNyZXQ=', 'base64');");
    const out = credentialHunterMockResponder(requestFor(prompt)) as { results: unknown[] } | undefined;
    expect(out!.results).toEqual([
      expect.objectContaining({ file: 'src/config.js', startLine: 1, kind: 'encoded', reconstructed: true }),
    ]);
  });

  it('flags an atob(...) literal as encoded', () => {
    const prompt = untrustedFile('src/web.js', "1: const key = atob('c3VwZXJzZWNyZXQ=');");
    const out = credentialHunterMockResponder(requestFor(prompt)) as { results: unknown[] } | undefined;
    expect(out!.results).toEqual([expect.objectContaining({ kind: 'encoded' })]);
  });

  it('flags a password key with a literal value in an object literal as connection-password', () => {
    const prompt = untrustedFile('src/db.js', "1: const cfg = { host: 'db', password: 'zzzzzzzzzzzz' };");
    const out = credentialHunterMockResponder(requestFor(prompt)) as { results: unknown[] } | undefined;
    expect(out!.results).toEqual([expect.objectContaining({ kind: 'connection-password' })]);
  });

  it('reports nothing for ordinary code', () => {
    const prompt = untrustedFile('src/math.js', '1: const sum = a + b;');
    const out = credentialHunterMockResponder(requestFor(prompt)) as { results: unknown[] } | undefined;
    expect(out!.results).toEqual([]);
  });
});

// --- end-to-end: FindingSchema validity + determinism --------------------------------------------

describe('end-to-end findings', () => {
  it('produces FindingSchema-valid, deterministic findings across runs, via the mock responder, for config and triage-flagged source files', async () => {
    const files = await writeRepoFiles({
      'config/service.yml': "auth:\n  apiToken: 'AAAA' + 'BBBBBBBBBBBB'\n",
      'src/payment.ts': [
        "const key = Buffer.from('c3VwZXJzZWNyZXR0b2tlbnZhbHVl', 'base64');",
        "const cfg = { host: 'db.internal', password: 'zzzzzzzzzzzzzzzzzzzz' };",
        '',
      ].join('\n'),
    }, { 'src/payment.ts': { language: 'typescript', category: 'source' } });

    const makeRun = () => makeAnalyzer(stubLlmFromResponder().llm, triageStub({ 'src/payment.ts': true }));
    const run1 = await makeRun().run(makeCtx(files));
    const run2 = await makeRun().run(makeCtx(files));

    expect(run1.length).toBeGreaterThan(0);
    for (const f of run1) expect(() => FindingSchema.parse(f)).not.toThrow();
    expect(run1.map((f) => f.id).sort()).toEqual(run2.map((f) => f.id).sort());
    expect(run1.map((f) => f.fingerprint).sort()).toEqual(run2.map((f) => f.fingerprint).sort());

    for (const f of run1) {
      expect(f.category).toBe('secret');
      expect(f.cwe).toBe('CWE-798');
      expect(f.producedBy).toEqual(['credential-hunter:llm']);
      expect(f.ruleId.startsWith('secret/hunter-')).toBe(true);
    }

    const serialized = JSON.stringify(run1);
    expect(serialized).not.toContain('BBBBBBBBBBBB');
    expect(serialized).not.toContain('c3VwZXJzZWNyZXR0b2tlbnZhbHVl');
    expect(serialized).not.toContain('zzzzzzzzzzzzzzzzzzzz');
  });
});
