import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { scanText, scanTree } from '../src/analyzers/credentials/scanText';
import type { IndexedFile } from '../src/index/types';
import { fake } from './fakeCredentials';

function file(path: string, skipReason: IndexedFile['skipReason'] = null, size = 0): IndexedFile {
  return { path, blobSha: 'deadbeef', size, language: 'other', category: 'other', tags: [], skipReason };
}

describe('scanText', () => {
  it('builds a candidate whose snippet never contains the raw value', () => {
    const token = fake.github();
    const text = `line one\nconst t = "${token}";\nline three\n`;
    const [candidate] = scanText('src/config.ts', text);
    expect(candidate).toBeDefined();
    expect(candidate!.value).toBe(token);
    expect(candidate!.hash).toHaveLength(64);
    expect(candidate!.redacted).not.toBe(token);
    expect(candidate!.snippet.includes(token)).toBe(false);
    expect(candidate!.snippet).toContain(candidate!.redacted);
    expect(candidate!.source).toBe('tree');
  });

  it('marks client-exposed lines', () => {
    const key = fake.google();
    const [candidate] = scanText('public/index.html', `<script>const NEXT_PUBLIC_KEY = "${key}";</script>`);
    expect(candidate).toBeDefined();
    expect(candidate!.clientExposed).toBe(true);
  });

  it('tags history candidates with commit and remapped line numbers', () => {
    const token = fake.github();
    const [candidate] = scanText('src/a.ts', `const t = "${token}";\n`, {
      source: 'history',
      commit: 'abc123',
      lineOffset: (line) => line + 99,
    });
    expect(candidate!.source).toBe('history');
    expect(candidate!.commit).toBe('abc123');
    expect(candidate!.line).toBe(100);
  });

  it('two-profile ~/.aws/credentials: each key pairs with its own secret and no snippet leaks either secret', () => {
    const k1 = fake.awsAccessKey();
    const k2 = fake.awsAccessKey();
    const s1 = fake.awsSecretKey();
    const s2 = fake.awsSecretKey();
    const text = `[default]\naws_access_key_id = ${k1}\naws_secret_access_key = ${s1}\n[prod]\naws_access_key_id = ${k2}\naws_secret_access_key = ${s2}\n`;
    const candidates = scanText('.aws/credentials', text);
    const c1 = candidates.find((c) => c.value === k1)!;
    const c2 = candidates.find((c) => c.value === k2)!;
    expect(c1.pairedSecret).toBe(s1);
    expect(c2.pairedSecret).toBe(s2);
    expect(candidates.length).toBeGreaterThan(0);
    for (const c of candidates) {
      expect(c.snippet.includes(s1)).toBe(false);
      expect(c.snippet.includes(s2)).toBe(false);
      expect(c.snippet.includes(c.value)).toBe(false);
    }
  });

  it('redacts unpaired AWS-secret-shaped tokens on aws/secret context lines', () => {
    const token = fake.github();
    const orphan = fake.awsSecretKey();
    const text = `# old aws key: ${orphan}\nconst t = "${token}";\n`;
    const [candidate] = scanText('src/config.ts', text);
    expect(candidate!.value).toBe(token);
    expect(candidate!.snippet.includes(orphan)).toBe(false);
  });

  it('redact-only matches (anon JWT) are not candidates but are redacted in neighbours\' snippets', () => {
    const anon = fake.supabaseAnonJwt();
    const token = fake.github();
    expect(scanText('src/supabase.ts', `const anon = "${anon}";\n`)).toHaveLength(0);
    const candidates = scanText('src/config.ts', `const anon = "${anon}";\nconst t = "${token}";\n`);
    expect(candidates.map((c) => c.value)).toEqual([token]);
    expect(candidates[0]!.snippet.includes(anon)).toBe(false);
  });

  it('uses the type-aware redaction for candidate.redacted', () => {
    const value = fake.genericSecretValue(24);
    const [candidate] = scanText('.env', `API_SECRET_TOKEN=${value}\n`);
    expect(candidate!.type).toBe('generic-secret');
    expect(candidate!.redacted).toBe(`${value.slice(0, 2)}…`);
  });

  it('builds snippets for 20k tokens in < 1 s and never leaks a raw value', () => {
    const tokens = Array.from({ length: 20_000 }, () => fake.github());
    const text = tokens.join('\n');
    const t0 = performance.now();
    const candidates = scanText('big.txt', text);
    const elapsed = performance.now() - t0;
    expect(candidates).toHaveLength(20_000);
    expect(elapsed).toBeLessThan(1000);
    for (const c of candidates) {
      const at = c.line - 1;
      for (const neighbour of [tokens[at - 1], tokens[at], tokens[at + 1]]) {
        if (neighbour) expect(c.snippet.includes(neighbour)).toBe(false);
      }
    }
  }, 30_000);

  it('handles 5k tokens on one long line without leaking or stalling', () => {
    const tokens = Array.from({ length: 5_000 }, () => fake.github());
    const text = tokens.map((t) => `"${t}"`).join(',');
    const t0 = performance.now();
    const candidates = scanText('bundle.min.js', text);
    expect(performance.now() - t0).toBeLessThan(1000);
    expect(candidates).toHaveLength(5_000);
    expect(candidates[0]!.snippet.includes(tokens[0]!)).toBe(false);
    expect(candidates[0]!.snippet.includes(tokens[1]!)).toBe(false);
  }, 30_000);

  it('ids are deterministic for the same file/line/hash', () => {
    const token = fake.github();
    const text = `const t = "${token}";\n`;
    const a = scanText('src/a.ts', text)[0]!;
    const b = scanText('src/a.ts', text)[0]!;
    expect(a.id).toBe(b.id);
    expect(a.id).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe('scanTree', () => {
  let dir: string;

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'vibesec-credential-scan-'));
    await mkdir(join(dir, 'app'), { recursive: true });
    await mkdir(join(dir, 'dist'), { recursive: true });
    await mkdir(join(dir, 'vendor'), { recursive: true });

    await writeFile(join(dir, 'app', 'config.ts'), `export const token = "${fake.github()}";\n`, 'utf8');
    await writeFile(join(dir, '.env'), `API_SECRET_TOKEN=${fake.genericSecretValue(24)}\n`, 'utf8');
    await writeFile(join(dir, 'dist', 'bundle.gen.js'), `var k="${fake.stripeLive()}";\n`, 'utf8');
    await writeFile(join(dir, 'vendor', 'lib.js'), `var k="${fake.stripeLive()}";\n`, 'utf8');
    await writeFile(join(dir, 'binary.bin'), Buffer.from([0, 1, 2, 3, 0, 5]));
    await writeFile(join(dir, 'link-target.ts'), `export const token = "${fake.github()}";\n`, 'utf8');

    const padding = 'x'.repeat(500);
    await writeFile(join(dir, 'large.txt'), `${padding}\n${fake.github()}\n`, 'utf8');
  }, 30_000);

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  });

  const baseFiles = (): IndexedFile[] => [
    file('app/config.ts', null),
    file('.env', 'vendor'), // .env override: scanned despite a non-binary/symlink skipReason
    file('dist/bundle.gen.js', 'generated'),
    file('vendor/lib.js', 'vendor'),
    file('binary.bin', 'binary'),
    file('link-target.ts', 'symlink'),
    file('large.txt', null),
    file('../escape.ts', null), // path-traversal attempt: must be skipped, not read
  ];

  it('scans eligible files, honours the .env override, and skips vendor/binary/symlink', async () => {
    const result = await scanTree({ repoDir: dir, files: baseFiles(), signal: new AbortController().signal });
    const byFile = new Set(result.candidates.map((c) => c.file));

    expect(byFile.has('app/config.ts')).toBe(true);
    expect(byFile.has('.env')).toBe(true);
    expect(byFile.has('dist/bundle.gen.js')).toBe(true);
    expect(byFile.has('large.txt')).toBe(true);

    expect(byFile.has('vendor/lib.js')).toBe(false);
    expect(byFile.has('binary.bin')).toBe(false);
    expect(byFile.has('link-target.ts')).toBe(false);
    expect(byFile.has('../escape.ts')).toBe(false);

    expect(result.filesScanned).toBeGreaterThan(0);
    expect(result.skipped).toBeGreaterThanOrEqual(4); // vendor, binary, symlink, traversal
  });

  it('never leaks a raw secret value into any snippet', async () => {
    const result = await scanTree({ repoDir: dir, files: baseFiles(), signal: new AbortController().signal });
    expect(result.candidates.length).toBeGreaterThan(0);
    for (const c of result.candidates) {
      expect(c.snippet.includes(c.value)).toBe(false);
    }
  });

  it('produces deterministic ids across two independent runs', async () => {
    const [r1, r2] = await Promise.all([
      scanTree({ repoDir: dir, files: baseFiles(), signal: new AbortController().signal }),
      scanTree({ repoDir: dir, files: baseFiles(), signal: new AbortController().signal }),
    ]);
    const ids1 = r1.candidates.map((c) => c.id).sort();
    const ids2 = r2.candidates.map((c) => c.id).sort();
    expect(ids1).toEqual(ids2);
  });

  it('respects maxFileBytes: a secret past the cutoff is not found', async () => {
    const withDefault = await scanTree({ repoDir: dir, files: [file('large.txt', null)], signal: new AbortController().signal });
    expect(withDefault.candidates.length).toBeGreaterThan(0);

    const withSmallLimit = await scanTree({
      repoDir: dir, files: [file('large.txt', null)], signal: new AbortController().signal, maxFileBytes: 50,
    });
    expect(withSmallLimit.candidates).toHaveLength(0);
    expect(withSmallLimit.filesScanned).toBe(1);
  });

  it('sizes the read buffer to the file, not maxFileBytes (huge maxFileBytes still works)', async () => {
    const result = await scanTree({
      repoDir: dir, files: [file('app/config.ts', null)], signal: new AbortController().signal, maxFileBytes: 16 * 1024 ** 3,
    });
    expect(result.filesScanned).toBe(1);
    expect(result.candidates.length).toBeGreaterThan(0);
  });

  it('stops all workers promptly once the signal aborts mid-scan', async () => {
    let polls = 0;
    const reason = new Error('aborted-mid-scan');
    const signal = {
      get aborted() { polls++; return polls > 5; },
      reason,
    } as unknown as AbortSignal;
    const many = Array.from({ length: 500 }, () => file('app/config.ts', null));
    await expect(scanTree({ repoDir: dir, files: many, signal })).rejects.toThrow('aborted-mid-scan');
    // 5 healthy polls + at most a couple per worker (16) once aborted — not one per remaining file.
    expect(polls).toBeLessThan(5 + 16 * 3);
  });

  it('rejects when the signal is already aborted', async () => {
    const controller = new AbortController();
    const reason = new Error('scan-aborted-for-test');
    controller.abort(reason);
    await expect(scanTree({ repoDir: dir, files: baseFiles(), signal: controller.signal })).rejects.toThrow('scan-aborted-for-test');
  });
});
