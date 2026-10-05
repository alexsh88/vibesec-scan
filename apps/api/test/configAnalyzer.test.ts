import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { FindingSchema, ScanOptionsSchema, type ScanDto } from '@vibesec/shared';
import {
  configMockResponder, CONFIG_PROMPT_VERSION, CONFIG_TASK_MARKER, createConfigAnalyzer,
} from '../src/analyzers/code/config/configAnalyzer';
import type { AnalyzerContext } from '../src/analyzers/types';
import { AppError } from '../src/errors/AppError';
import type { IndexedFile } from '../src/index/types';
import type { LlmClient, StructuredCall, StructuredResult } from '../src/llm/LlmClient';
import { buildRequestParts } from '../src/llm/prompt';
import type { LlmRequest } from '../src/llm/transport';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'vibesec-config-'));
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
    indexed.push({ path, blobSha: 'deadbeef', size: Buffer.byteLength(content), language: 'other', category: 'config', tags: [], skipReason: null });
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

type HintVerdict = { hintId: string; confirmed: boolean; reason: string };
type AdditionalIssue = {
  ruleId: string; title: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'info'; confidence: 'high' | 'medium' | 'low';
  file: string; startLine: number; endLine: number; snippet: string; explanation: string; impact: string; remediation: string;
};
type COut = { hintVerdicts: HintVerdict[]; issues: AdditionalIssue[] };

const ZERO = { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 };

function okResult(out: COut): StructuredResult<COut> {
  return { output: out, model: 'claude-sonnet-5', usage: ZERO, costUsd: 0, callIds: ['c'], degraded: false, fellBackOnRefusal: false };
}

/** A `Pick<LlmClient, 'structured'>` stub: records every StructuredCall it receives. */
function stubLlm(impl: (call: StructuredCall<COut>) => Promise<StructuredResult<COut>>): {
  llm: Pick<LlmClient, 'structured'>;
  calls: StructuredCall<COut>[];
} {
  const calls: StructuredCall<COut>[] = [];
  const structured = async (call: StructuredCall<COut>) => {
    calls.push(call);
    return impl(call);
  };
  return { llm: { structured: structured as unknown as LlmClient['structured'] }, calls };
}

/** Converts a StructuredCall into the LlmRequest a responder would see, and validates the
 *  responder's output against the call's real zod schema. */
function stubLlmFromResponder(responder: (req: LlmRequest) => unknown): Pick<LlmClient, 'structured'> {
  return {
    async structured<T>(call: StructuredCall<T>): Promise<StructuredResult<T>> {
      const parts = buildRequestParts(call);
      const req: LlmRequest = { model: 'mock', system: parts.system, messages: parts.messages, maxTokens: 100, thinking: false, schema: call.schema };
      const output = responder(req) ?? { hintVerdicts: [], issues: [] };
      return { output: call.schema.parse(output), model: 'mock', usage: ZERO, costUsd: 0, callIds: [], degraded: false, fellBackOnRefusal: false };
    },
  };
}

/** Extracts the hintId of every <hint id="..."> block in a combined prompt, in order. */
function hintIdsOf(prompt: string): string[] {
  return [...prompt.matchAll(/<hint id="([^"]*)">/g)].map((m) => m[1]!);
}

const WORKFLOW = [
  'on: pull_request_target',
  'jobs:',
  '  build:',
  '    runs-on: ubuntu-latest',
  '    steps:',
  '      - uses: actions/checkout@v4',
  '        with:',
  '          ref: ${{ github.event.pull_request.head.sha }}',
].join('\n');

const DOCKERFILE_NO_USER = 'FROM node:20\nRUN npm ci\nCMD ["node", "server.js"]\n';

// Same checkout vulnerability as WORKFLOW, but with an explicit `permissions:` block so it produces
// exactly one hint (gha-pull-request-target-checkout) instead of also tripping gha-excessive-permissions.
const WORKFLOW_SINGLE_HINT = [
  'permissions:',
  '  contents: read',
  'on: pull_request_target',
  'jobs:',
  '  build:',
  '    runs-on: ubuntu-latest',
  '    steps:',
  '      - uses: actions/checkout@v4',
  '        with:',
  '          ref: ${{ github.event.pull_request.head.sha }}',
].join('\n');

describe('createConfigAnalyzer: file collection', () => {
  it('collects known config/IaC patterns, detects Kubernetes manifests by content, and excludes everything else', async () => {
    const files = await writeRepoFiles({
      '.github/workflows/ci.yml': WORKFLOW,
      Dockerfile: DOCKERFILE_NO_USER,
      'docker-compose.yml': 'version: "3"\nservices:\n  web:\n    image: nginx\n',
      '.env': 'API_KEY=zK9pQ7xT2vL8mN4r\n',
      '.env.example': 'API_KEY=changeme\n', // template — must be excluded
      'supabase/migrations/0001_init.sql': 'create table public.users (id uuid primary key);\n',
      'firebase.json': '{"hosting": {}}\n',
      'firestore.rules': 'service cloud.firestore {\n}\n',
      'vercel.json': '{}\n',
      'netlify.toml': '[build]\n  command = "npm run build"\n',
      'infra/main.tf': 'resource "aws_s3_bucket" "b" {}\n',
      'k8s/deployment.yaml': 'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\n',
      'charts/values.yaml': 'replicas: 3\n', // plain yaml, no apiVersion/kind — must be excluded
      'src/app.ts': 'export const a = 1;\n', // unrelated source — must be excluded
    });
    const { llm, calls } = stubLlm(async () => okResult({ hintVerdicts: [], issues: [] }));
    await createConfigAnalyzer({ llm }).run(makeCtx(files));

    const combined = calls.map((c) => c.prompt).join('\n');
    for (const expected of [
      '.github/workflows/ci.yml', 'Dockerfile', 'docker-compose.yml', '.env', 'supabase/migrations/0001_init.sql',
      'firebase.json', 'firestore.rules', 'vercel.json', 'netlify.toml', 'infra/main.tf', 'k8s/deployment.yaml',
    ]) {
      expect(combined).toContain(`path="${expected}"`);
    }
    for (const excluded of ['.env.example', 'charts/values.yaml', 'src/app.ts']) {
      expect(combined).not.toContain(`path="${excluded}"`);
    }
    expect(calls.every((c) => c.role === 'deep' && c.analyzer === 'config' && c.purpose === 'config-review' && c.promptVersion === CONFIG_PROMPT_VERSION && c.system.includes(CONFIG_TASK_MARKER))).toBe(true);
  });

  it('reviews every config file (no cap) and records coverage', async () => {
    const entries: Record<string, string> = {};
    for (let i = 0; i < 45; i++) entries[`infra/stack${i}.tf`] = `resource "null_resource" "r${i}" {}\n`;
    const files = await writeRepoFiles(entries);
    const { llm, calls } = stubLlm(async () => okResult({ hintVerdicts: [], issues: [] }));
    const warnings: string[][] = [];
    const ctx = makeCtx(files, { warnings });
    const coverage = new Map<string, string>();
    ctx.recordCoverage = (a, path, status) => { expect(a).toBe('config'); coverage.set(path, status); };
    await createConfigAnalyzer({ llm }).run(ctx);

    const combined = calls.map((c) => c.prompt).join('\n');
    const seen = new Set([...combined.matchAll(/path="(infra\/stack\d+\.tf)"/g)].map((m) => m[1]));
    expect(seen.size).toBe(45);
    expect(warnings).toEqual([]);
    expect([...coverage.values()].filter((s) => s === 'reviewed')).toHaveLength(45);
  });

  it('after a budget refusal keeps the rule hints at low confidence and records budget-skipped', async () => {
    const files = await writeRepoFiles({ Dockerfile: 'FROM node:20\nRUN curl -sSL https://x.sh | sh\n' });
    const { llm } = stubLlm(async () => { throw new AppError('BUDGET_EXHAUSTED', 'budget', 'out'); });
    const ctx = makeCtx(files);
    const coverage = new Map<string, string>();
    ctx.recordCoverage = (_a, path, status) => { coverage.set(path, status); };
    const findings = await createConfigAnalyzer({ llm }).run(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.confidence === 'low')).toBe(true);
    expect(Object.fromEntries(coverage)).toEqual({ Dockerfile: 'budget-skipped' });
  });
});

describe('createConfigAnalyzer: .env redaction', () => {
  it('never sends the raw .env value to the model, only the key and its first 2 characters', async () => {
    const files = await writeRepoFiles({ '.env': 'API_KEY=zK9pQ7xT2vL8mN4r\nDB_PASSWORD=ab\n' });
    const { llm, calls } = stubLlm(async () => okResult({ hintVerdicts: [], issues: [] }));
    await createConfigAnalyzer({ llm }).run(makeCtx(files));

    const combined = calls.map((c) => `${c.system}\n${c.prompt}`).join('\n');
    expect(combined).not.toContain('zK9pQ7xT2vL8mN4r');
    expect(combined).toContain('API_KEY=zK…');
    expect(combined).toContain('DB_PASSWORD=…'); // value.length <= 2: fully redacted, still no raw value
    expect(combined).not.toContain('=ab');
  });
});

describe('createConfigAnalyzer: hints and additional issues', () => {
  it('confirmed hints become findings (hint location, reason appended, producedBy rule+llm) at their original severity', async () => {
    const files = await writeRepoFiles({ '.github/workflows/ci.yml': WORKFLOW_SINGLE_HINT, Dockerfile: DOCKERFILE_NO_USER });
    const { llm, calls } = stubLlm(async (call) => {
      const ids = hintIdsOf(call.prompt);
      const ghId = ids.find((id) => id.includes('ci.yml'))!;
      const dockerId = ids.find((id) => id.includes('Dockerfile'))!;
      return okResult({
        hintVerdicts: [
          { hintId: ghId, confirmed: true, reason: 'checks out untrusted PR head' },
          { hintId: dockerId, confirmed: false, reason: 'base image already drops privileges' },
        ],
        issues: [],
      });
    });
    const findings = await createConfigAnalyzer({ llm }).run(makeCtx(files));

    expect(calls.length).toBeGreaterThan(0);
    expect(findings).toHaveLength(2);
    const f = findings.find((x) => x.ruleId === 'config/gha-pull-request-target-checkout')!;
    expect(f.location.file).toBe('.github/workflows/ci.yml');
    expect(f.producedBy).toEqual(['config:rule', 'config:llm']);
    expect(f.explanation).toContain('checks out untrusted PR head');
    expect(f.severity).toBe('critical'); // unchanged by confirmation
    expect(f.riskFactors).toEqual([]);
  });

  it('a refuted hint is downgraded to info/low with an ai_refuted riskFactor, never dropped', async () => {
    const files = await writeRepoFiles({ Dockerfile: DOCKERFILE_NO_USER });
    const { llm } = stubLlm(async (call) => {
      const dockerId = hintIdsOf(call.prompt)[0]!;
      return okResult({
        hintVerdicts: [{ hintId: dockerId, confirmed: false, reason: 'base image already drops privileges' }],
        issues: [],
      });
    });
    const findings = await createConfigAnalyzer({ llm }).run(makeCtx(files));

    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.ruleId).toBe('config/docker-root-user');
    expect(f.severity).toBe('info');
    expect(f.confidence).toBe('low');
    expect(f.producedBy).toEqual(['config:rule', 'config:llm']);
    expect(f.explanation).toContain('AI review judged this a likely false positive: base image already drops privileges');
    expect(f.riskFactors).toHaveLength(1);
    expect(f.riskFactors[0]).toMatchObject({ factor: 'ai_refuted', reason: 'base image already drops privileges' });
    expect(f.riskFactors[0]!.effect).toBeLessThan(0);
    expect(() => FindingSchema.parse(f)).not.toThrow();
  });

  it('a hint the AI response never mentions keeps its original severity, drops to low confidence, and gets an ai_unreviewed riskFactor', async () => {
    const files = await writeRepoFiles({ Dockerfile: DOCKERFILE_NO_USER });
    const { llm } = stubLlm(async () => okResult({ hintVerdicts: [], issues: [] }));
    const findings = await createConfigAnalyzer({ llm }).run(makeCtx(files));

    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.ruleId).toBe('config/docker-root-user');
    expect(f.severity).toBe('medium'); // unchanged
    expect(f.confidence).toBe('low');
    expect(f.producedBy).toEqual(['config:rule']);
    expect(f.riskFactors).toEqual([{
      factor: 'ai_unreviewed', effect: 0,
      reason: 'AI review returned no verdict for this hint; kept at its original severity (fail-open)',
    }]);
    expect(() => FindingSchema.parse(f)).not.toThrow();
  });

  it('verifies additional issues before they become findings: drops a hallucinated one, keeps a real one', async () => {
    const files = await writeRepoFiles({ 'netlify.toml': '[build]\n  command = "npm run build"\n' });
    const { llm } = stubLlm(async () => okResult({
      hintVerdicts: [],
      issues: [
        {
          ruleId: 'config/debug-mode-enabled', title: 'debug on', severity: 'medium', confidence: 'medium',
          file: 'netlify.toml', startLine: 2, endLine: 2, snippet: '  command = "npm run build"',
          explanation: 'e', impact: 'i', remediation: 'r',
        },
        {
          ruleId: 'config/fake', title: 'hallucinated', severity: 'medium', confidence: 'medium',
          file: 'netlify.toml', startLine: 2, endLine: 2, snippet: 'this text is not in the file anywhere',
          explanation: 'e', impact: 'i', remediation: 'r',
        },
      ],
    }));
    const findings = await createConfigAnalyzer({ llm }).run(makeCtx(files));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe('config/debug-mode-enabled');
    expect(findings[0]!.producedBy).toEqual(['config:llm']);
  });

  it('dedupes an additional issue against an already-confirmed hint at the same file/overlapping lines/ruleId', async () => {
    const files = await writeRepoFiles({ Dockerfile: DOCKERFILE_NO_USER });
    const { llm } = stubLlm(async (call) => {
      const id = hintIdsOf(call.prompt)[0]!;
      return okResult({
        hintVerdicts: [{ hintId: id, confirmed: true, reason: 'confirmed' }],
        issues: [{
          ruleId: 'config/docker-root-user', title: 'dup', severity: 'medium', confidence: 'medium',
          file: 'Dockerfile', startLine: 1, endLine: 1, snippet: 'FROM node:20',
          explanation: 'e', impact: 'i', remediation: 'r',
        }],
      });
    });
    const findings = await createConfigAnalyzer({ llm }).run(makeCtx(files));
    expect(findings.filter((f) => f.ruleId === 'config/docker-root-user')).toHaveLength(1);
  });

  it('fails open per batch: an AI failure keeps that batch\'s hints as low-confidence findings, warns CONFIG_AI_UNAVAILABLE once; cancellation rethrows', async () => {
    const files = await writeRepoFiles({ '.github/workflows/ci.yml': WORKFLOW_SINGLE_HINT });
    const { llm } = stubLlm(async () => { throw new AppError('LLM_UNAVAILABLE', 'transient', 'down'); });
    const warnings: string[][] = [];
    const findings = await createConfigAnalyzer({ llm }).run(makeCtx(files, { warnings }));

    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe('config/gha-pull-request-target-checkout');
    expect(findings[0]!.confidence).toBe('low');
    expect(warnings.filter(([code]) => code === 'CONFIG_AI_UNAVAILABLE')).toHaveLength(1);

    const { llm: cancelLlm } = stubLlm(async () => { throw new AppError('CANCELLED', 'cancelled', 'stop'); });
    await expect(createConfigAnalyzer({ llm: cancelLlm }).run(makeCtx(files))).rejects.toMatchObject({ code: 'CANCELLED' });
  });

  it('produces Findings that satisfy FindingSchema and never puts a credential value into a finding', async () => {
    const files = await writeRepoFiles({ '.env': 'API_KEY=zK9pQ7xT2vL8mN4r\n' });
    const { llm } = stubLlm(async () => okResult({
      hintVerdicts: [], // the .env file's own 'config/env-file-committed' hint goes unmentioned -> ai_unreviewed
      issues: [{
        ruleId: 'config/debug-mode-enabled', title: 't', severity: 'medium', confidence: 'medium',
        file: '.env', startLine: 1, endLine: 1, snippet: 'API_KEY=zK…',
        explanation: 'e', impact: 'i', remediation: 'r',
      }],
    }));
    const findings = await createConfigAnalyzer({ llm }).run(makeCtx(files));
    expect(findings).toHaveLength(2);
    for (const f of findings) expect(() => FindingSchema.parse(f)).not.toThrow();
    expect(JSON.stringify(findings)).not.toContain('zK9pQ7xT2vL8mN4r');

    const hintFinding = findings.find((f) => f.ruleId === 'config/env-file-committed')!;
    expect(hintFinding.confidence).toBe('low');
    expect(hintFinding.riskFactors.some((r) => r.factor === 'ai_unreviewed')).toBe(true);
  });
});

describe('configMockResponder', () => {
  it('ignores requests whose system prompt does not carry the config task marker', () => {
    const req: LlmRequest = {
      model: 'm', system: [{ type: 'text', text: 'some other task' }],
      messages: [{ role: 'user', content: [{ type: 'text', text: 'anything' }] }],
      maxTokens: 100, thinking: false,
    };
    expect(configMockResponder(req)).toBeUndefined();
  });

  it('confirms every hint and adds a supabase RLS issue when a table lacks it; both are schema-valid, verified findings', async () => {
    const files = await writeRepoFiles({
      '.github/workflows/ci.yml': WORKFLOW,
      'supabase/migrations/0001_init.sql': 'create table public.users (id uuid primary key);\n',
    });
    const llm = stubLlmFromResponder(configMockResponder);
    const findings = await createConfigAnalyzer({ llm }).run(makeCtx(files));

    expect(findings.some((f) => f.ruleId === 'config/gha-pull-request-target-checkout' && (f.producedBy ?? []).includes('config:llm'))).toBe(true);
    expect(findings.some((f) => f.ruleId === 'config/supabase-table-without-rls')).toBe(true);
    for (const f of findings) expect(() => FindingSchema.parse(f)).not.toThrow();
  });

  it('does not add a supabase RLS issue when the migration already enables it', async () => {
    const files = await writeRepoFiles({
      'supabase/migrations/0001_init.sql': 'create table public.users (id uuid primary key);\nalter table public.users enable row level security;\n',
    });
    const llm = stubLlmFromResponder(configMockResponder);
    const findings = await createConfigAnalyzer({ llm }).run(makeCtx(files));
    expect(findings.some((f) => f.ruleId === 'config/supabase-table-without-rls')).toBe(false);
  });
});
