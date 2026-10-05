import { describe, expect, it } from 'vitest';
import { BudgetTracker } from '../src/llm/budget';

describe('BudgetTracker', () => {
  it('seeds spend from the persisted value and accumulates', () => {
    const b = new BudgetTracker(5, () => 1.5);
    expect(b.spentUsd('s1')).toBe(1.5);
    b.add('s1', 2);
    expect(b.spentUsd('s1')).toBe(3.5);
    expect(b.ratio('s1')).toBeCloseTo(0.7, 9);
  });

  it('throws BUDGET_EXHAUSTED (kind budget) once the cap is reached', () => {
    const b = new BudgetTracker(1, () => 0);
    b.add('s1', 1);
    expect(() => b.ensureAvailable('s1')).toThrow(expect.objectContaining({ code: 'BUDGET_EXHAUSTED', kind: 'budget' }));
    expect(() => b.ensureAvailable('s2')).not.toThrow();
  });

  it('forget drops in-memory state so the next access reloads', () => {
    let persisted = 0.5;
    const b = new BudgetTracker(5, () => persisted);
    b.add('s1', 1);
    persisted = 2;
    b.forget('s1');
    expect(b.spentUsd('s1')).toBe(2);
  });
});

describe('BudgetTracker.reserve', () => {
  const budgetError = expect.objectContaining({ code: 'BUDGET_EXHAUSTED', kind: 'budget' });
  /** Resolves to 'pending' when the promise has not settled after a few macrotask turns. */
  const state = async <T>(p: Promise<T>): Promise<'pending' | 'resolved' | 'rejected'> => {
    let s: 'pending' | 'resolved' | 'rejected' = 'pending';
    p.then(() => { s = 'resolved'; }, () => { s = 'rejected'; });
    await new Promise((r) => setTimeout(r, 5));
    return s;
  };

  it('reserves within the limit without touching committed spend', async () => {
    const b = new BudgetTracker(1, () => 0);
    await b.reserve('s1', 0.4);
    await b.reserve('s1', 0.6);
    expect(b.reservedUsd('s1')).toBeCloseTo(1, 9);
    expect(b.spentUsd('s1')).toBe(0);
    expect(b.ratio('s1')).toBe(0);
  });

  it('throws BUDGET_EXHAUSTED when committed spend alone + estimate would exceed the limit', async () => {
    const spent = new BudgetTracker(1, () => 0.7);
    await expect(spent.reserve('s1', 0.4)).rejects.toEqual(budgetError);
    const full = new BudgetTracker(1, () => 1);
    await expect(full.reserve('s1', 0.0001)).rejects.toEqual(budgetError);
  });

  it('waits (instead of failing) while only in-flight reservations block, then proceeds after a settle', async () => {
    const b = new BudgetTracker(1, () => 0);
    const settleFirst = await b.reserve('s1', 0.7);
    const second = b.reserve('s1', 0.4);
    expect(await state(second)).toBe('pending');
    expect(b.reservedUsd('s1')).toBeCloseTo(0.7, 9);
    await expect(b.reserve('s2', 0.4)).resolves.toBeTypeOf('function'); // other scans unaffected
    settleFirst(0.05);
    const settleSecond = await second;
    expect(b.reservedUsd('s1')).toBeCloseTo(0.4, 9);
    settleSecond(0.05);
    expect(b.spentUsd('s1')).toBeCloseTo(0.1, 9);
  });

  it('a waiter fails with BUDGET_EXHAUSTED when the settled spend leaves no room', async () => {
    const b = new BudgetTracker(1, () => 0);
    const settleFirst = await b.reserve('s1', 0.7);
    const second = b.reserve('s1', 0.4);
    expect(await state(second)).toBe('pending');
    settleFirst(0.7);
    await expect(second).rejects.toEqual(budgetError);
  });

  it('a waiting reservation is abortable (CANCELLED) and leaves no bookkeeping behind', async () => {
    const b = new BudgetTracker(1, () => 0);
    await b.reserve('s1', 0.7);
    const ac = new AbortController();
    const second = b.reserve('s1', 0.4, ac.signal);
    expect(await state(second)).toBe('pending');
    ac.abort();
    await expect(second).rejects.toMatchObject({ code: 'CANCELLED', kind: 'cancelled' });
    expect(b.reservedUsd('s1')).toBeCloseTo(0.7, 9);
    const pre = new AbortController();
    pre.abort();
    await expect(b.reserve('s2', 0.1, pre.signal)).rejects.toMatchObject({ code: 'CANCELLED' });
  });

  it('allows a single oversized reservation on an empty budget; later ones wait for it', async () => {
    const b = new BudgetTracker(0.01, () => 0);
    const settle = await b.reserve('s1', 0.5);
    const next = b.reserve('s1', 0.001);
    expect(await state(next)).toBe('pending');
    settle(0.02); // actual cost overshot the tiny budget → the waiter is refused
    await expect(next).rejects.toEqual(budgetError);
  });

  it('settle frees the reservation and commits the actual cost', async () => {
    const b = new BudgetTracker(1, () => 0);
    const settle = await b.reserve('s1', 0.5);
    settle(0.1);
    expect(b.reservedUsd('s1')).toBe(0);
    expect(b.spentUsd('s1')).toBeCloseTo(0.1, 9);
    await expect(b.reserve('s1', 0.9)).resolves.toBeTypeOf('function');
  });

  it('settle is idempotent', async () => {
    const b = new BudgetTracker(1, () => 0);
    const settle = await b.reserve('s1', 0.5);
    await b.reserve('s1', 0.2);
    settle(0.1);
    settle(0.1);
    settle(0);
    expect(b.spentUsd('s1')).toBeCloseTo(0.1, 9);
    expect(b.reservedUsd('s1')).toBeCloseTo(0.2, 9);
  });

  it('forget drops reservations too', async () => {
    const b = new BudgetTracker(1, () => 0);
    await b.reserve('s1', 0.9);
    b.forget('s1');
    expect(b.reservedUsd('s1')).toBe(0);
    await expect(b.reserve('s1', 0.9)).resolves.toBeTypeOf('function');
  });

  it('a settle after forget does not re-create the forgotten in-memory spend', async () => {
    let loads = 0;
    let persisted = 0;
    const b = new BudgetTracker(1, () => { loads++; return persisted; });
    const settle = await b.reserve('s1', 0.3);
    const before = loads;
    b.forget('s1');
    settle(0.2);
    expect(loads).toBe(before); // no lazy reload triggered by the settle
    persisted = 0.25;
    expect(b.spentUsd('s1')).toBe(0.25); // next access reloads from persistence, not 0.2 + reload
    expect(b.reservedUsd('s1')).toBe(0);
    // A reservation made after forget is unaffected by the stale settle.
    const fresh = await b.reserve('s1', 0.1);
    settle(0.5);
    expect(b.reservedUsd('s1')).toBeCloseTo(0.1, 9);
    fresh(0.05);
    expect(b.spentUsd('s1')).toBeCloseTo(0.3, 9);
  });
});
