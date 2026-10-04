import { describe, expect, it, vi } from 'vitest';
import { AppError } from '../src/errors/AppError';
import { computeBackoff, withRetry, type RetryPolicy } from '../src/resilience/retry';

const policy: RetryPolicy = { retries: 3, baseMs: 100, capMs: 1_000 };
const transient = () => new AppError('INTERNAL', 'transient', 'flaky');
const noSleep = { sleep: async () => {} };

describe('computeBackoff', () => {
  it('uses full jitter bounded by cap', () => {
    expect(computeBackoff(0, policy, () => 0.5)).toBe(50);
    expect(computeBackoff(3, policy, () => 0.999)).toBe(799);
    expect(computeBackoff(10, policy, () => 0.999)).toBe(999);
  });
});

describe('withRetry', () => {
  it('returns on first success', async () => {
    const fn = vi.fn(async () => 'ok');
    await expect(withRetry(fn, policy, undefined, noSleep)).resolves.toBe('ok');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('retries transient errors then succeeds', async () => {
    let n = 0;
    const delays: number[] = [];
    const result = await withRetry(async () => {
      if (++n < 3) throw transient();
      return n;
    }, policy, undefined, { sleep: async (ms) => { delays.push(ms); }, random: () => 0.5 });
    expect(result).toBe(3);
    expect(delays).toEqual([50, 100]);
  });

  it('does not retry permanent errors', async () => {
    const fn = vi.fn(async () => { throw new AppError('AUTH_INVALID', 'permanent', 'bad token'); });
    await expect(withRetry(fn, policy, undefined, noSleep)).rejects.toMatchObject({ code: 'AUTH_INVALID' });
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('gives up after policy.retries', async () => {
    const fn = vi.fn(async () => { throw transient(); });
    await expect(withRetry(fn, policy, undefined, noSleep)).rejects.toMatchObject({ kind: 'transient' });
    expect(fn).toHaveBeenCalledTimes(4);
  });

  it('honors retryAfterMs over computed backoff', async () => {
    const delays: number[] = [];
    let n = 0;
    await withRetry(async () => {
      if (n++ === 0) throw new AppError('GITHUB_RATE_LIMITED', 'transient', 'rl', { retryAfterMs: 4_000 });
      return 1;
    }, policy, undefined, { sleep: async (ms) => { delays.push(ms); } });
    expect(delays).toEqual([4_000]);
  });

  it('reports retries through onRetry', async () => {
    const onRetry = vi.fn();
    let n = 0;
    await withRetry(async () => { if (n++ === 0) throw transient(); return 1; }, policy, undefined, { ...noSleep, onRetry });
    expect(onRetry).toHaveBeenCalledWith(expect.objectContaining({ attempt: 1 }));
  });

  it('throws CANCELLED when aborted during backoff', async () => {
    const ac = new AbortController();
    const p = withRetry(async () => { throw transient(); }, { retries: 5, baseMs: 10_000, capMs: 10_000 }, ac.signal, { random: () => 1 });
    setTimeout(() => ac.abort(), 20);
    await expect(p).rejects.toMatchObject({ code: 'CANCELLED' });
  });

  it('throws CANCELLED immediately when already aborted', async () => {
    const ac = new AbortController();
    ac.abort();
    const fn = vi.fn(async () => 1);
    await expect(withRetry(fn, policy, ac.signal, noSleep)).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(fn).not.toHaveBeenCalled();
  });
});
