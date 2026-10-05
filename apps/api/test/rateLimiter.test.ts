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

  it('treats non-finite or negative estimates as zero instead of hanging forever', async () => {
    const c = clock();
    const rl = new RateLimiter({ requestsPerMinute: 1_000, inputTokensPerMinute: 100, now: c.now, sleep: c.sleep });
    await rl.acquire(NaN);
    await rl.acquire(Infinity);
    await rl.acquire(-50);
    expect(c.sleeps).toEqual([]); // all resolved immediately; no NaN poisoning hung the loop

    // Buckets must not be poisoned with NaN: `tokens` is still a real number, so acquiring
    // the full remaining bucket succeeds immediately (it would hang forever on NaN compares).
    await rl.acquire(100);
    expect(c.sleeps).toEqual([]);

    // ...and once the bucket really is exhausted, a normal acquire correctly waits for refill.
    await rl.acquire(1);
    expect(c.sleeps.length).toBeGreaterThan(0);
  });

  it('rethrows a non-abort sleep failure unchanged instead of relabelling it CANCELLED', async () => {
    const c = clock();
    const boom = new Error('boom');
    const rl = new RateLimiter({
      requestsPerMinute: 1,
      inputTokensPerMinute: 1_000,
      now: c.now,
      sleep: async () => { throw boom; },
    });
    await rl.acquire(1); // consumes the only request slot, so the next acquire must wait (and sleep)
    await expect(rl.acquire(1)).rejects.toThrow('boom');
  });

  it('serializes acquisitions strictly FIFO so a large request is not starved behind small ones', async () => {
    const c = clock();
    const rl = new RateLimiter({ requestsPerMinute: 10_000, inputTokensPerMinute: 1_000, now: c.now, sleep: c.sleep });
    await rl.acquire(1_000); // drain the token bucket completely

    const order: string[] = [];
    const big = rl.acquire(900).then(() => { order.push('big'); });
    const smalls = Array.from({ length: 20 }, (_, i) => rl.acquire(50).then(() => { order.push(`small-${i}`); }));

    await Promise.all([big, ...smalls]);

    expect(order[0]).toBe('big');
    expect(order.slice(1)).toEqual(Array.from({ length: 20 }, (_, i) => `small-${i}`));
  });

  it('rejects an aborted waiter immediately even while the head is indefinitely blocked, and still lets the next waiter proceed right after the head (#M-1)', async () => {
    const c = clock();
    let releaseHead: (() => void) | undefined;
    let sleepCalls = 0;
    // The first sleep() call belongs to the head's wait-for-refill; hold it open indefinitely
    // (instead of the fake clock's near-instant resolution) so we can prove the aborted waiter
    // behind it rejects without waiting for the head to finish. Every later call behaves normally.
    const sleep = async (ms: number, signal?: AbortSignal) => {
      sleepCalls += 1;
      if (sleepCalls === 1) {
        await new Promise<void>((resolve) => { releaseHead = resolve; });
        c.advance(ms);
        return;
      }
      return c.sleep(ms, signal);
    };
    const rl = new RateLimiter({ requestsPerMinute: 1, inputTokensPerMinute: 1_000_000, now: c.now, sleep });
    await rl.acquire(1); // consumes the only request slot

    const order: string[] = [];
    const ac = new AbortController();

    const head = rl.acquire(1).then(() => order.push('head')); // must wait for refill → calls sleep (held open)
    const aborted = rl.acquire(1, ac.signal);
    const w3 = rl.acquire(1).then(() => order.push('w3'));

    ac.abort(); // abort while queued behind the still-blocked head

    await expect(aborted).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(order).toEqual([]); // the head has not completed yet — it is still blocked on sleep

    releaseHead?.();
    await head;
    await w3;
    expect(order).toEqual(['head', 'w3']);
  });

  it('rejects an aborted queued waiter promptly without blocking the rest, which still complete in order', async () => {
    const c = clock();
    const rl = new RateLimiter({ requestsPerMinute: 10_000, inputTokensPerMinute: 100, now: c.now, sleep: c.sleep });
    await rl.acquire(100); // drain

    const order: string[] = [];
    const ac = new AbortController();

    const w0 = rl.acquire(10).then(() => order.push('w0'));
    const w1 = rl.acquire(10, ac.signal).then(() => order.push('w1'));
    const w2 = rl.acquire(10).then(() => order.push('w2'));
    const w3 = rl.acquire(10).then(() => order.push('w3'));

    ac.abort(); // abort w1 while it is still queued behind w0, before its turn arrives

    await expect(w1).rejects.toMatchObject({ code: 'CANCELLED' });
    await Promise.all([w0, w2, w3]);

    expect(order).toEqual(['w0', 'w2', 'w3']);
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
