import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { FindingSchema, ScanOptionsSchema, type ScanDto, type ScanOptions } from '@vibesec/shared';
import { createCredentialsAnalyzer, type CredentialsAnalyzerDeps } from '../src/analyzers/credentials/credentialsAnalyzer';
import { credentialsFpMockResponder } from '../src/analyzers/credentials/fpFilter';
import type { SecretVerifier, VerifyResult } from '../src/analyzers/credentials/verifiers';
import type { AnalyzerContext } from '../src/analyzers/types';
import { AppError } from '../src/errors/AppError';
import type { IndexedFile } from '../src/index/types';
import type { LlmClient, StructuredCall, StructuredResult } from '../src/llm/LlmClient';
import type { LlmRequest } from '../src/llm/transport';
import { fake } from './fakeCredentials';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'vibesec-credentials-analyzer-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

async function writeRepoFiles(files: Record<string, string>): Promise<IndexedFile[]> {
  const indexed: IndexedFile[] = [];
  for (const [path, content] of Object.entries(files)) {
    const abs = join(dir, ...path.split('/'));
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, content, 'utf8');
    indexed.push({ path, blobSha: 'deadbeef', size: Buffer.byteLength(content), language: 'other', category: 'other', tags: [], skipReason: null });
  }
  return indexed;
}

/** Stub `llm.structured`: by default re-uses the real mock-responder heuristic (test/fixture paths
 *  are false positives), adapted from the StructuredCall shape to the LlmRequest shape it expects. */
function stubLlm(responder: (req: LlmRequest) => unknown = credentialsFpMockResponder): Pick<LlmClient, 'structured'> {
  return {
    async structured<T>(call: StructuredCall<T>): Promise<StructuredResult<T>> {
      const req: LlmRequest = {
        model: 'mock',
        system: [{ type: 'text', text: call.system }],
        messages: [{ role: 'user', content: [{ type: 'text', text: call.prompt }] }],
        maxTokens: 100,
        thinking: false,
        schema: call.schema,
      };
      const output = responder(req) ?? { results: [] };
      return {
        output: call.schema.parse(output),
        model: 'mock',
        usage: { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 },
        costUsd: 0,
        callIds: [],
        degraded: false,
        fellBackOnRefusal: false,
      };
    },
  };
}

function throwingLlm(message = 'llm unavailable'): Pick<LlmClient, 'structured'> {
  return { structured: async () => { throw new Error(message); } };
}

function stubVerifier(impl: (secretType: string) => VerifyResult = () => ({ liveness: 'unknown' })) {
  return {
    verify: vi.fn(async (_scanId: string, secret: { type: string }) => impl(secret.type)),
    forget: vi.fn(),
  };
}

function fakeGit(patch: { text: string; truncated: boolean } | (() => Promise<{ text: string; truncated: boolean }>)): CredentialsAnalyzerDeps['git'] {
  return {
    logPatch: async () => (typeof patch === 'function' ? patch() : patch),
  };
}

function makeScan(options: Partial<ScanOptions> = {}): ScanDto {
  return {
    id: 'scan-1',
    repo: { id: 'repo-1', owner: 'acme', name: 'app', isPrivate: false },
    ref: null,
    commitSha: 'c'.repeat(40),
    state: 'ANALYZING',
    errorCode: null,
    errorMessage: null,
    cacheHit: 'none',
    options: ScanOptionsSchema.parse(options),
    costUsd: 0,
    createdAt: new Date().toISOString(),
    startedAt: null,
    finishedAt: null,
    warnings: [],
  };
}

function makeCtx(files: IndexedFile[], opts: {
  options?: Partial<ScanOptions>; warnings?: string[][];
} = {}): AnalyzerContext {
  const scan = makeScan(opts.options);
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

/** One `\0COMMIT <sha>` block adding a single line at `line` in `file`, matching `git log -p --unified=0`. */
function historyBlock(sha: string, file: string, line: number, text: string): string {
  return [`\0COMMIT ${sha}`, `diff --git a/${file} b/${file}`, `--- a/${file}`, `+++ b/${file}`, `@@ -0,0 +${line},1 @@`, `+${text}`].join('\n') + '\n';
}

const NO_HISTORY = { text: '', truncated: false };

describe('createCredentialsAnalyzer', () => {
  it('merges tree and history: a shared secret yields one (tree) finding; a history-only secret is flagged inHistoryOnly with a commit permalink, deduped to the newest commit', async () => {
    const dup = fake.github(); // present in both tree and history -> history copy must be dropped
    const historyOnly = fake.github(); // present only in two historical commits -> kept once, newest commit wins
    const files = await writeRepoFiles({ 'src/dup.ts': `const t = "${dup}";\n` });

    const newSha = '1'.repeat(40);
    const oldSha = '2'.repeat(40);
    const dupSha = '3'.repeat(40);
    const patchText = [
      historyBlock(newSha, 'newer.ts', 5, `const y = "${historyOnly}";`),
      historyBlock(oldSha, 'older.ts', 9, `const y2 = "${historyOnly}";`),
      historyBlock(dupSha, 'src/dup.ts', 1, `const t = "${dup}";`),
    ].join('');

    const analyzer = createCredentialsAnalyzer({
      llm: stubLlm(), git: fakeGit({ text: patchText, truncated: false }), verifier: stubVerifier(),
    });
    const ctx = makeCtx(files, { options: { historyDepth: 50, verifySecrets: false } });
    const findings = await analyzer.run(ctx);

    const dupFindings = findings.filter((f) => f.secret!.redacted === findingRedacted(dup));
    expect(dupFindings).toHaveLength(1);
    expect(dupFindings[0]!.secret!.inHistoryOnly).toBe(false);
    expect(dupFindings[0]!.location.permalink).toContain(ctx.commitSha);

    const historyOnlyFindings = findings.filter((f) => f.secret!.redacted === findingRedacted(historyOnly));
    expect(historyOnlyFindings).toHaveLength(1);
    const hf = historyOnlyFindings[0]!;
    expect(hf.secret!.inHistoryOnly).toBe(true);
    expect(hf.secret!.commit).toBe(newSha); // newest of the two duplicate history commits
    expect(hf.location.permalink).toContain(newSha);
    expect(hf.explanation).toContain(newSha.slice(0, 7));
    expect(hf.explanation).toContain('removed from the current code');
  });

  it('I6: downgrades (never drops) a candidate the FP filter flags as a false positive (test-path heuristic)', async () => {
    const value = fake.genericSecretValue(24);
    const files = await writeRepoFiles({ 'test/fixtures/sample.ts': `export const password = "${value}";\n` });
    const analyzer = createCredentialsAnalyzer({ llm: stubLlm(), git: fakeGit(NO_HISTORY), verifier: stubVerifier() });
    const findings = await analyzer.run(makeCtx(files, { options: { historyDepth: 0 } }));
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.severity).toBe('info');
    expect(f.confidence).toBe('low');
    expect(f.riskScore).toBe(5);
    expect(f.riskFactors).toContainEqual(expect.objectContaining({ factor: 'ai_false_positive' }));
    expect(f.explanation).toContain('AI triage');
  });

  it('keeps a candidate the FP filter judges real, at medium confidence when its confidence is not high', async () => {
    const value = fake.genericSecretValue(24);
    const files = await writeRepoFiles({ 'src/config.ts': `export const password = "${value}";\n` });
    const analyzer = createCredentialsAnalyzer({ llm: stubLlm(), git: fakeGit(NO_HISTORY), verifier: stubVerifier() });
    const findings = await analyzer.run(makeCtx(files, { options: { historyDepth: 0 } }));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.confidence).toBe('medium');
  });

  it('fails open when the FP filter call throws: the candidate survives with medium confidence', async () => {
    const value = fake.genericSecretValue(24);
    const files = await writeRepoFiles({ 'test/fixtures/sample.ts': `export const password = "${value}";\n` });
    const analyzer = createCredentialsAnalyzer({ llm: throwingLlm(), git: fakeGit(NO_HISTORY), verifier: stubVerifier() });
    const warnings: string[][] = [];
    const findings = await analyzer.run(makeCtx(files, { options: { historyDepth: 0 }, warnings }));
    expect(findings).toHaveLength(1); // kept: no verdict means it is never dropped
    expect(findings[0]!.confidence).toBe('medium');
    expect(warnings.some(([code]) => code === 'CREDENTIALS_FP_FILTER_UNAVAILABLE')).toBe(true);
  });

  it('does not call the verifier and reports not_checked when verifySecrets is false', async () => {
    const files = await writeRepoFiles({ 'src/config.ts': `export const token = "${fake.github()}";\n` });
    const verifier = stubVerifier();
    const analyzer = createCredentialsAnalyzer({ llm: stubLlm(), git: fakeGit(NO_HISTORY), verifier });
    const findings = await analyzer.run(makeCtx(files, { options: { historyDepth: 0, verifySecrets: false } }));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.secret!.liveness).toBe('not_checked');
    expect(verifier.verify).not.toHaveBeenCalled();
    expect(verifier.forget).toHaveBeenCalledWith('scan-1');
  });

  it('a live credential becomes critical severity, with a riskFactor recording the adjustment', async () => {
    const files = await writeRepoFiles({ 'src/config.ts': `export const token = "${fake.github()}";\n` }); // base: high
    const verifier = stubVerifier(() => ({ liveness: 'live', checkedAt: '2024-01-01T00:00:00.000Z', provider: 'github' }));
    const analyzer = createCredentialsAnalyzer({ llm: stubLlm(), git: fakeGit(NO_HISTORY), verifier });
    const findings = await analyzer.run(makeCtx(files, { options: { historyDepth: 0, verifySecrets: true } }));
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.severity).toBe('critical');
    expect(f.baseSeverity).toBe('high');
    expect(f.riskScore).toBe(90);
    expect(f.riskFactors).toContainEqual(expect.objectContaining({ factor: 'live', effect: 1 }));
  });

  it('a revoked credential is lowered in severity', async () => {
    const files = await writeRepoFiles({ 'src/config.ts': `export const token = "${fake.github()}";\n` }); // base: high
    const verifier = stubVerifier(() => ({ liveness: 'revoked', checkedAt: '2024-01-01T00:00:00.000Z', provider: 'github' }));
    const analyzer = createCredentialsAnalyzer({ llm: stubLlm(), git: fakeGit(NO_HISTORY), verifier });
    const findings = await analyzer.run(makeCtx(files, { options: { historyDepth: 0, verifySecrets: true } }));
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.severity).toBe('low');
    expect(f.riskFactors).toContainEqual(expect.objectContaining({ factor: 'revoked', effect: -2 }));
  });

  it('client-exposed code raises severity by one step', async () => {
    const files = await writeRepoFiles({ 'public/index.html': `<script>const NEXT_PUBLIC_KEY = "${fake.google()}";</script>\n` }); // base: medium
    const analyzer = createCredentialsAnalyzer({ llm: stubLlm(), git: fakeGit(NO_HISTORY), verifier: stubVerifier() });
    const findings = await analyzer.run(makeCtx(files, { options: { historyDepth: 0, verifySecrets: false } }));
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.baseSeverity).toBe('medium');
    expect(f.severity).toBe('high');
    expect(f.riskFactors).toContainEqual(expect.objectContaining({ factor: 'clientExposed', effect: 1 }));
  });

  it('a history-scan failure (not cancellation) is reported as a warning; tree findings are still returned', async () => {
    const files = await writeRepoFiles({ 'src/config.ts': `export const token = "${fake.github()}";\n` });
    const git: CredentialsAnalyzerDeps['git'] = { logPatch: async () => { throw new Error('git log failed'); } };
    const analyzer = createCredentialsAnalyzer({ llm: stubLlm(), git, verifier: stubVerifier() });
    const warnings: string[][] = [];
    const findings = await analyzer.run(makeCtx(files, { options: { historyDepth: 50 }, warnings }));
    expect(findings).toHaveLength(1);
    expect(warnings.some(([code]) => code === 'CREDENTIALS_HISTORY_FAILED')).toBe(true);
  });

  it('produces Findings that all satisfy FindingSchema, with deterministic ids/fingerprints across runs, and never leaks a raw value or pairedSecret', async () => {
    const githubToken = fake.github();
    const stripeKey = fake.stripeLive();
    const awsAccess = fake.awsAccessKey();
    const awsSecret = fake.awsSecretKey();
    const files = await writeRepoFiles({
      'src/config.ts': `export const token = "${githubToken}";\nexport const stripe = "${stripeKey}";\n`,
      'infra/deploy.ts': `const awsAccessKeyId = "${awsAccess}";\nconst awsSecretAccessKey = "${awsSecret}";\n`,
    });
    const verifier = stubVerifier(() => ({ liveness: 'unknown' }));
    const makeAnalyzer = () => createCredentialsAnalyzer({ llm: stubLlm(), git: fakeGit(NO_HISTORY), verifier });

    const run1 = await makeAnalyzer().run(makeCtx(files, { options: { historyDepth: 0, verifySecrets: true } }));
    const run2 = await makeAnalyzer().run(makeCtx(files, { options: { historyDepth: 0, verifySecrets: true } }));

    expect(run1.length).toBeGreaterThanOrEqual(3);
    for (const f of run1) expect(() => FindingSchema.parse(f)).not.toThrow();

    expect(run1.map((f) => f.id).sort()).toEqual(run2.map((f) => f.id).sort());
    expect(run1.map((f) => f.fingerprint).sort()).toEqual(run2.map((f) => f.fingerprint).sort());

    const serialized = JSON.stringify(run1);
    for (const raw of [githubToken, stripeKey, awsAccess, awsSecret]) {
      expect(serialized.includes(raw)).toBe(false);
    }
  });

  it('M3: a throwing verifier degrades that candidate to unknown with a single warning, instead of failing the analyzer', async () => {
    const files = await writeRepoFiles({ 'src/config.ts': `export const token = "${fake.github()}";\n` });
    const forget = vi.fn();
    const verifier: Pick<SecretVerifier, 'verify' | 'forget'> = {
      verify: async () => { throw new Error('network exploded'); },
      forget,
    };
    const analyzer = createCredentialsAnalyzer({ llm: stubLlm(), git: fakeGit(NO_HISTORY), verifier });
    const warnings: string[][] = [];
    const findings = await analyzer.run(makeCtx(files, { options: { historyDepth: 0, verifySecrets: true }, warnings }));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.secret!.liveness).toBe('unknown');
    expect(warnings.filter(([code]) => code === 'CREDENTIALS_VERIFICATION_FAILED')).toHaveLength(1);
    expect(forget).toHaveBeenCalledWith('scan-1');
  });

  it('M3: cancellation from a verification call still propagates (is not degraded into a warning)', async () => {
    const files = await writeRepoFiles({ 'src/config.ts': `export const token = "${fake.github()}";\n` });
    const forget = vi.fn();
    const verifier: Pick<SecretVerifier, 'verify' | 'forget'> = {
      verify: async () => { throw new AppError('CANCELLED', 'cancelled', 'scan cancelled'); },
      forget,
    };
    const analyzer = createCredentialsAnalyzer({ llm: stubLlm(), git: fakeGit(NO_HISTORY), verifier });
    await expect(analyzer.run(makeCtx(files, { options: { historyDepth: 0, verifySecrets: true } })))
      .rejects.toMatchObject({ code: 'CANCELLED' });
    expect(forget).toHaveBeenCalledWith('scan-1');
  });

  it('I5: dedupes a secret repeated on multiple lines of the same file into one finding, keeping the lowest line and noting the extra occurrences', async () => {
    const value = fake.github();
    const files = await writeRepoFiles({
      'src/config.ts': `const a = "${value}";\nconst b = "${value}";\nconst c = "${value}";\n`,
    });
    const analyzer = createCredentialsAnalyzer({ llm: stubLlm(), git: fakeGit(NO_HISTORY), verifier: stubVerifier() });
    const findings = await analyzer.run(makeCtx(files, { options: { historyDepth: 0, verifySecrets: false } }));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.startLine).toBe(1);
    expect(findings[0]!.explanation).toContain('Found on 3 lines in this file');
  });
});

/** redact() is pure and deterministic, so this reproduces what the analyzer must have stored. */
function findingRedacted(value: string): string {
  if (value.length < 12) return value.length <= 2 ? value : `${value.slice(0, 2)}…`;
  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}
