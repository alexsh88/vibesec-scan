import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { scanText, scanTree } from '../src/analyzers/secrets/scanText';
import type { IndexedFile } from '../src/index/types';
import { fake } from './fakeSecrets';

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
    dir = await mkdtemp(join(tmpdir(), 'vibesec-secret-scan-'));
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

  it('rejects when the signal is already aborted', async () => {
    const controller = new AbortController();
    const reason = new Error('scan-aborted-for-test');
    controller.abort(reason);
    await expect(scanTree({ repoDir: dir, files: baseFiles(), signal: controller.signal })).rejects.toThrow('scan-aborted-for-test');
  });
});
