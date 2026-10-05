import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CategorySchema, SeveritySchema } from '@vibesec/shared';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { detectSecrets } from '../src/analyzers/credentials/rules';

// apps/api/test/vulnAppFixture.test.ts -> apps/api/test -> apps/api -> apps -> <repo root>
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const FIXTURE_ROOT = resolve(REPO_ROOT, 'fixtures', 'vuln-app');

const IssueSchema = z.object({
  id: z.string().min(1),
  category: CategorySchema,
  cwe: z.string().optional(),
  ruleHint: z.string().min(1),
  file: z.string().min(1),
  line: z.number().int().positive(),
  lineContains: z.string().min(1),
  lineTolerance: z.number().int().nonnegative(),
  severityAtLeast: SeveritySchema,
  description: z.string().min(1),
});

const SafeSchema = z.object({
  file: z.string().min(1),
  line: z.number().int().positive(),
  lineContains: z.string().min(1),
  description: z.string().min(1),
});

const ExpectedSchema = z.object({
  version: z.literal(1),
  issues: z.array(IssueSchema),
  safe: z.array(SafeSchema),
});

function readExpected() {
  const raw = JSON.parse(readFileSync(join(FIXTURE_ROOT, 'expected.json'), 'utf8'));
  return ExpectedSchema.parse(raw);
}

/** The line (1-indexed) of `file`, or undefined if the file/line doesn't exist. */
function lineAt(file: string, line: number): string | undefined {
  const abs = resolve(FIXTURE_ROOT, file);
  if (!existsSync(abs)) return undefined;
  const lines = readFileSync(abs, 'utf8').split(/\r\n|\r|\n/);
  return lines[line - 1];
}

/** Every regular file under `dir`, recursively, as an absolute path. */
function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const abs = join(dir, name);
    const stat = statSync(abs);
    if (stat.isDirectory()) out.push(...walk(abs));
    else out.push(abs);
  }
  return out;
}

describe('vuln-app fixture: expected.json', () => {
  it('validates against the ground-truth schema', () => {
    expect(() => readExpected()).not.toThrow();
  });

  it('plants at least 18 issues, spread across more than one file', () => {
    const expected = readExpected();
    expect(expected.issues.length).toBeGreaterThanOrEqual(18);
    const files = new Set(expected.issues.map((i) => i.file));
    expect(files.size).toBeGreaterThan(5);
  });

  it('has unique issue ids', () => {
    const expected = readExpected();
    const ids = expected.issues.map((i) => i.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('every issue file exists and the referenced line contains lineContains', () => {
    const expected = readExpected();
    for (const issue of expected.issues) {
      const abs = resolve(FIXTURE_ROOT, issue.file);
      expect(existsSync(abs), `${issue.id}: missing file ${issue.file}`).toBe(true);
      const line = lineAt(issue.file, issue.line);
      expect(line, `${issue.id}: ${issue.file}:${issue.line} does not exist`).toBeDefined();
      expect(line, `${issue.id}: ${issue.file}:${issue.line} does not contain "${issue.lineContains}"`).toContain(
        issue.lineContains,
      );
    }
  });

  it('every safe-lookalike file exists and the referenced line contains lineContains', () => {
    const expected = readExpected();
    for (const safe of expected.safe) {
      const abs = resolve(FIXTURE_ROOT, safe.file);
      expect(existsSync(abs), `missing file ${safe.file}`).toBe(true);
      const line = lineAt(safe.file, safe.line);
      expect(line, `${safe.file}:${safe.line} does not exist`).toBeDefined();
      expect(line, `${safe.file}:${safe.line} does not contain "${safe.lineContains}"`).toContain(safe.lineContains);
    }
  });

  it('does not reference the same file/line from both an issue and a safe entry', () => {
    const expected = readExpected();
    const issueKeys = new Set(expected.issues.map((i) => `${i.file}:${i.line}`));
    for (const safe of expected.safe) {
      expect(issueKeys.has(`${safe.file}:${safe.line}`)).toBe(false);
    }
  });
});

describe('vuln-app fixture: credential realism', () => {
  it('contains no provider-format credential patterns — only generic-secret/database-url', () => {
    const allowed = new Set(['generic-secret', 'database-url']);
    const offenders: string[] = [];
    for (const abs of walk(FIXTURE_ROOT)) {
      if (abs.endsWith('expected.json')) continue; // ground truth, not scanned app source
      const text = readFileSync(abs, 'utf8');
      for (const match of detectSecrets(text)) {
        if (!allowed.has(match.type)) {
          offenders.push(`${relative(FIXTURE_ROOT, abs)}:${match.line} (${match.type})`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it('plants at least one generic-secret and one database-url credential', () => {
    const types = new Set<string>();
    for (const abs of walk(FIXTURE_ROOT)) {
      if (abs.endsWith('expected.json')) continue;
      for (const match of detectSecrets(readFileSync(abs, 'utf8'))) types.add(match.type);
    }
    expect(types.has('generic-secret')).toBe(true);
    expect(types.has('database-url')).toBe(true);
  });
});

describe('vuln-app fixture: excluded from the real build', () => {
  it('sits outside every npm workspace (apps/*, packages/*), so no tsconfig or vitest include can reach it', () => {
    expect(FIXTURE_ROOT.startsWith(resolve(REPO_ROOT, 'apps'))).toBe(false);
    expect(FIXTURE_ROOT.startsWith(resolve(REPO_ROOT, 'packages'))).toBe(false);
  });

  it('is not matched by the root vitest include globs', () => {
    const vitestConfig = readFileSync(resolve(REPO_ROOT, 'vitest.config.ts'), 'utf8');
    // Both include globs are rooted at "apps/*/test/" and "packages/*/test/"; the fixture lives
    // under "fixtures/", so neither can ever match a file inside it.
    expect(vitestConfig).toContain("'packages/*/test/**/*.test.ts'");
    expect(vitestConfig).toContain("'apps/*/test/**/*.test.ts'");
    const relToRepo = relative(REPO_ROOT, FIXTURE_ROOT).replace(/\\/g, '/');
    expect(relToRepo.startsWith('apps/') || relToRepo.startsWith('packages/')).toBe(false);
  });

  it('is not reachable by apps/api or packages/shared tsconfig "include"', () => {
    for (const pkg of ['apps/api', 'packages/shared']) {
      const tsconfigPath = resolve(REPO_ROOT, pkg, 'tsconfig.json');
      const tsconfig = JSON.parse(readFileSync(tsconfigPath, 'utf8')) as { include?: string[] };
      for (const entry of tsconfig.include ?? []) {
        // Every include entry is a plain subdirectory name (src/test/scripts) with no "..", so it
        // can only ever resolve *inside* the package directory, never out to fixtures/.
        expect(entry.includes('..')).toBe(false);
      }
    }
  });
});
