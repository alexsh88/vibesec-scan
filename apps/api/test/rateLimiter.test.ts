import { describe, expect, it } from 'vitest';
import { RateLimiter, Semaphore } from '../src/llm/rateLimiter';

function clock() {
  let t = 0;
  const sleeps: number[] = [];
  return {
    now: () => t,
    sleep: async (ms: number, signal?: AbortSignal) => {
      if (signal?.aborted) throw Object.assign(new Error('aborted'), { name: 'AbortError' });
      sleeps.push(ms);
      t += ms;
    },
    advance: (ms: number) => { t += ms; },
    sleeps,
  };
}

describe('RateLimiter', () => {
  it('admits immediately while capacity lasts', async () => {
    const c = clock();
    const rl = new RateLimiter({ requestsPerMinute: 2, inputTokensPerMinute: 1_000, now: c.now, sleep: c.sleep });
    await rl.acquire(100);
    await rl.acquire(100);
    expect(c.sleeps).toEqual([]);
  });

  it('waits for the request bucket to refill', async () => {
    const c = clock();
    const rl = new RateLimiter({ requestsPerMinute: 2, inputTokensPerMinute: 1_000_000, now: c.now, sleep: c.sleep });
    await rl.acquire(1);
    await rl.acquire(1);
    await rl.acquire(1);
    expect(c.sleeps.reduce((a, b) => a + b, 0)).toBeGreaterThanOrEqual(30_000 - 1);
  });

  it('waits for the token bucket and lets oversized requests through on a full bucket', async () => {
    const c = clock();
    const rl = new RateLimiter({ requestsPerMinute: 1_000, inputTokensPerMinute: 600, now: c.now, sleep: c.sleep });
    await rl.acquire(600);
    await rl.acquire(300); // needs 300 tokens → 30 s at 10 tokens/s
    expect(c.sleeps.reduce((a, b) => a + b, 0)).toBeGreaterThanOrEqual(30_000 - 1);
    c.sleeps.length = 0;
    await rl.acquire(5_000); // larger than the bucket: waits until full, then proceeds
    expect(c.sleeps.reduce((a, b) => a + b, 0)).toBeGreaterThanOrEqual(60_000 - 1);
  });

  it('penalize halves capacity for a while', async () => {
    const c = clock();
    const rl = new RateLimiter({ requestsPerMinute: 4, inputTokensPerMinute: 1_000_000, now: c.now, sleep: c.sleep });
    rl.penalize(60_000);
    await rl.acquire(1);
    await rl.acquire(1);
    await rl.acquire(1); // capacity is 2 during the penalty
    expect(c.sleeps.length).toBeGreaterThan(0);
  });

  it('throws CANCELLED when aborted while waiting', async () => {
    const c = clock();
    const rl = new RateLimiter({ requestsPerMinute: 1, inputTokensPerMinute: 1_000, now: c.now, sleep: c.sleep });
    await rl.acquire(1);
    const ac = new AbortController();
    ac.abort();
    await expect(rl.acquire(1, ac.signal)).rejects.toMatchObject({ code: 'CANCELLED' });
  });
});

describe('Semaphore', () => {
  it('limits concurrency and releases', async () => {
    const sem = new Semaphore(2);
    let active = 0;
    let peak = 0;
    const work = async () => {
      const release = await sem.acquire();
      active++;
      peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, 10));
      active--;
      release();
    };
    await Promise.all([work(), work(), work(), work(), work()]);
    expect(peak).toBe(2);
  });

  it('release is idempotent and an aborted waiter does not take a slot', async () => {
    const sem = new Semaphore(1);
    const release = await sem.acquire();
    const ac = new AbortController();
    const waiting = sem.acquire(ac.signal);
    ac.abort();
    await expect(waiting).rejects.toMatchObject({ code: 'CANCELLED' });
    release();
    release();
    const again = await sem.acquire();
    again();
  });
});
