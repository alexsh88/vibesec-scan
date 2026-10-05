import { describe, expect, it } from 'vitest';
import { parseGitLogPatch, scanHistory, type TextScanner } from '../src/analyzers/credentials/history';

const header = (path: string) => `diff --git a/${path} b/${path}\nindex 1111111..2222222 100644\n--- a/${path}\n+++ b/${path}\n`;

describe('parseGitLogPatch', () => {
  it('parses commits, files and hunks (incl. @@ -0,0 +1,N @@ and comma-less headers)', () => {
    const shaA = 'a'.repeat(40);
    const shaB = 'b'.repeat(40);
    const text =
      `\0COMMIT ${shaA}\n` + header('file1.txt') +
      '@@ -0,0 +1,2 @@\n+line one\n+line two\n' +
      '@@ -10 +12 @@\n+line twelve\n' +
      header('file2.txt') + '@@ -4 +7 @@\n+seventh line\n' +
      `\0COMMIT ${shaB}\n` + header('file1.txt') +
      '@@ -2 +2,2 @@\n+line two updated\n+line two point five\n';

    expect(parseGitLogPatch(text)).toEqual([
      { commit: shaA, file: 'file1.txt', lines: [{ line: 1, text: 'line one' }, { line: 2, text: 'line two' }, { line: 12, text: 'line twelve' }] },
      { commit: shaA, file: 'file2.txt', lines: [{ line: 7, text: 'seventh line' }] },
      { commit: shaB, file: 'file1.txt', lines: [{ line: 2, text: 'line two updated' }, { line: 3, text: 'line two point five' }] },
    ]);
  });

  it('ignores deleted lines, binary files and /dev/null targets; decodes quoted octal paths', () => {
    const sha = 'c'.repeat(40);
    const text =
      `\0COMMIT ${sha}\n` + header('del.txt') +
      '@@ -1,2 +1,1 @@\n-old line one\n-old line two\n+kept line\n' +
      'diff --git a/image.png b/image.png\nindex 3333333..4444444 100644\nBinary files a/image.png and b/image.png differ\n' +
      'diff --git a/removed.txt b/removed.txt\ndeleted file mode 100644\nindex 5555555..0000000\n--- a/removed.txt\n+++ /dev/null\n' +
      '@@ -1,2 +0,0 @@\n-gone one\n-gone two\n' +
      'diff --git "a/sp\\303\\251cial.txt" "b/sp\\303\\251cial.txt"\nindex 6666666..7777777 100644\n' +
      '--- "a/sp\\303\\251cial.txt"\n+++ "b/sp\\303\\251cial.txt"\n@@ -0,0 +1 @@\n+café value\n';

    expect(parseGitLogPatch(text)).toEqual([
      { commit: sha, file: 'del.txt', lines: [{ line: 1, text: 'kept line' }] },
      { commit: sha, file: 'spécial.txt', lines: [{ line: 1, text: 'café value' }] },
    ]);
  });

  it('does not treat content lines as markers or headers', () => {
    const sha = 'd'.repeat(40);
    const text =
      `\0COMMIT ${sha}\n` + header('notes.txt') +
      '@@ -0,0 +1,4 @@\n+COMMIT deadbeef\n+++ b/evil.txt\n+-- sql comment\n+real content\n';

    expect(parseGitLogPatch(text)).toEqual([
      { commit: sha, file: 'notes.txt', lines: [
        { line: 1, text: 'COMMIT deadbeef' },
        { line: 2, text: '++ b/evil.txt' },
        { line: 3, text: '-- sql comment' },
        { line: 4, text: 'real content' },
      ] },
    ]);
  });

  it('tolerates CRLF output and ignores "no newline" markers', () => {
    const sha = 'e'.repeat(40);
    const text = `\0COMMIT ${sha}\r\n` + header('a.txt').replace(/\n/g, '\r\n') + '@@ -0,0 +1 @@\r\n+only\r\n\\ No newline at end of file\r\n';
    expect(parseGitLogPatch(text)).toEqual([{ commit: sha, file: 'a.txt', lines: [{ line: 1, text: 'only' }] }]);
  });

  it('returns nothing for empty output', () => {
    expect(parseGitLogPatch('')).toEqual([]);
  });
});

describe('scanHistory', () => {
  const shaA = '1'.repeat(40);
  const shaB = '2'.repeat(40);
  const patch =
    `\0COMMIT ${shaA}\n` + header('config.txt') + '@@ -0,0 +10,2 @@\n+normal line\n+API_KEY=HIT123\n' +
    `\0COMMIT ${shaB}\n` + header('other.txt') + '@@ -5 +50 @@\n+TOKEN=HITXYZ\n';

  type Hit = { file: string; commit: string; line: number; text: string };
  const fakeScan: TextScanner<Hit> = (file, text, opts) =>
    text.split('\n').flatMap((t, i) => (t.includes('HIT') ? [{ file, commit: opts.commit, line: opts.lineOffset(i + 1), text: t }] : []));

  it('maps lineOffset back to real file lines and calls touch', async () => {
    let touches = 0;
    const result = await scanHistory({
      logPatch: async () => ({ text: patch, truncated: true }),
      scan: fakeScan,
      signal: new AbortController().signal,
      touch: () => touches++,
    });
    expect(result).toEqual({
      candidates: [
        { file: 'config.txt', commit: shaA, line: 11, text: 'API_KEY=HIT123' },
        { file: 'other.txt', commit: shaB, line: 50, text: 'TOKEN=HITXYZ' },
      ],
      commitsScanned: 2,
      truncated: true,
    });
    expect(touches).toBeGreaterThan(0);
  });

  it('skips chunks above maxChunkBytes', async () => {
    const result = await scanHistory({ logPatch: async () => ({ text: patch, truncated: false }), scan: fakeScan, signal: new AbortController().signal, maxChunkBytes: 20 });
    expect(result.candidates.map((c) => c.file)).toEqual(['other.txt']);
  });

  it('rejects when already aborted without calling logPatch', async () => {
    const ac = new AbortController();
    ac.abort();
    let called = false;
    await expect(scanHistory({
      logPatch: async () => { called = true; return { text: patch, truncated: false }; },
      scan: fakeScan,
      signal: ac.signal,
    })).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(called).toBe(false);
  });

  it('rejects when aborted while git runs', async () => {
    const ac = new AbortController();
    await expect(scanHistory({
      logPatch: async () => { ac.abort(); return { text: patch, truncated: false }; },
      scan: fakeScan,
      signal: ac.signal,
    })).rejects.toMatchObject({ code: 'CANCELLED' });
  });
});
