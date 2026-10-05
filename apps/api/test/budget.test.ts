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

  it('reserves within the limit without touching committed spend', () => {
    const b = new BudgetTracker(1, () => 0);
    b.reserve('s1', 0.4);
    b.reserve('s1', 0.6);
    expect(b.reservedUsd('s1')).toBeCloseTo(1, 9);
    expect(b.spentUsd('s1')).toBe(0);
    expect(b.ratio('s1')).toBe(0);
  });

  it('throws BUDGET_EXHAUSTED when spend + reservations + estimate would exceed the limit', () => {
    const spent = new BudgetTracker(1, () => 0.7);
    expect(() => spent.reserve('s1', 0.4)).toThrow(budgetError);
    const reserved = new BudgetTracker(1, () => 0);
    reserved.reserve('s1', 0.7);
    expect(() => reserved.reserve('s1', 0.4)).toThrow(budgetError);
    expect(reserved.reservedUsd('s1')).toBeCloseTo(0.7, 9);
    expect(() => reserved.reserve('s2', 0.4)).not.toThrow();
  });

  it('allows a single oversized reservation on an empty budget', () => {
    const b = new BudgetTracker(0.01, () => 0);
    expect(() => b.reserve('s1', 0.5)).not.toThrow();
    expect(() => b.reserve('s1', 0.001)).toThrow(budgetError);
  });

  it('settle frees the reservation and commits the actual cost', () => {
    const b = new BudgetTracker(1, () => 0);
    const settle = b.reserve('s1', 0.5);
    settle(0.1);
    expect(b.reservedUsd('s1')).toBe(0);
    expect(b.spentUsd('s1')).toBeCloseTo(0.1, 9);
    expect(() => b.reserve('s1', 0.9)).not.toThrow();
  });

  it('settle is idempotent', () => {
    const b = new BudgetTracker(1, () => 0);
    const settle = b.reserve('s1', 0.5);
    b.reserve('s1', 0.2);
    settle(0.1);
    settle(0.1);
    settle(0);
    expect(b.spentUsd('s1')).toBeCloseTo(0.1, 9);
    expect(b.reservedUsd('s1')).toBeCloseTo(0.2, 9);
  });

  it('forget drops reservations too', () => {
    const b = new BudgetTracker(1, () => 0);
    b.reserve('s1', 0.9);
    b.forget('s1');
    expect(b.reservedUsd('s1')).toBe(0);
    expect(() => b.reserve('s1', 0.9)).not.toThrow();
  });
});
