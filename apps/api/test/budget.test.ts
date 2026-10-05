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
