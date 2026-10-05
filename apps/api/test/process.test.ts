import { describe, expect, it, vi } from 'vitest';
import { ProcessError, runProcess } from '../src/process/runProcess';

const node = process.execPath;
const run = (script: string, opts: Partial<Parameters<typeof runProcess>[2]> = {}) =>
  runProcess(node, ['-e', script], { timeoutMs: 5_000, ...opts });

describe('runProcess', () => {
  it('returns exit code, stdout and stderr without throwing on non-zero exit', async () => {
    const r = await run("process.stdout.write('out'); process.stderr.write('err'); process.exit(3)");
    expect(r).toEqual({ code: 3, stdout: 'out', stderr: 'err' });
  });

  it('splits stderr into lines on \\r, \\n and \\r\\n', async () => {
    const lines: string[] = [];
    await run("process.stderr.write('a 10%\\rb 20%\\r\\nc\\nd')", { onStderrLine: (l) => lines.push(l) });
    expect(lines).toEqual(['a 10%', 'b 20%', 'c', 'd']);
  });

  it('rejects with timeout', async () => {
    const started = Date.now();
    await expect(run('setTimeout(() => {}, 20000)', { timeoutMs: 300 })).rejects.toMatchObject({ reason: 'timeout' });
    expect(Date.now() - started).toBeLessThan(4_000);
  });

  it('rejects with stall when there is no output for stallMs', async () => {
    await expect(run('setInterval(() => {}, 1000)', { stallMs: 300, timeoutMs: 5_000 }))
      .rejects.toMatchObject({ reason: 'stall' });
  });

  it('output resets the stall timer and reports activity', async () => {
    let activity = 0;
    const r = await run(
      "let i = 0; const t = setInterval(() => { process.stderr.write('.'); if (++i === 6) { clearInterval(t); } }, 100)",
      { stallMs: 400, onActivity: () => { activity++; } },
    );
    expect(r.code).toBe(0);
    expect(activity).toBeGreaterThanOrEqual(6);
  });

  it('rejects with aborted when the signal fires', async () => {
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 150);
    await expect(run('setTimeout(() => {}, 20000)', { signal: ac.signal })).rejects.toMatchObject({ reason: 'aborted' });
  });

  it('rejects immediately when already aborted', async () => {
    const ac = new AbortController();
    ac.abort();
    await expect(run('process.exit(0)', { signal: ac.signal })).rejects.toMatchObject({ reason: 'aborted' });
  });

  it('rejects with spawn when the binary does not exist', async () => {
    await expect(runProcess('definitely-not-a-real-binary-xyz', [], { timeoutMs: 2_000 }))
      .rejects.toMatchObject({ reason: 'spawn' });
  });

  it('rejects with output_limit when stdout exceeds maxStdoutBytes', async () => {
    const err = await run("process.stdout.write('x'.repeat(200000))", { maxStdoutBytes: 1_000 }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ProcessError);
    expect((err as ProcessError).reason).toBe('output_limit');
  });

  it('settles via the killGraceMs backup timer when killTree never produces a close event', async () => {
    const killTreeSpy = vi.fn();
    const started = Date.now();
    const err = await run('setTimeout(() => {}, 1500)', {
      timeoutMs: 100,
      killGraceMs: 200,
      _killTree: killTreeSpy,
    }).catch((e: unknown) => e);
    expect(killTreeSpy).toHaveBeenCalledTimes(1);
    expect(err).toBeInstanceOf(ProcessError);
    expect((err as ProcessError).reason).toBe('timeout');
    expect(Date.now() - started).toBeLessThan(2_000);
  });
});
