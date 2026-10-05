import { describe, expect, it } from 'vitest';
import { capsOf, costUsd, DEGRADE_ROLE, FALLBACK_ROLE, priceOf } from '../src/llm/models';

describe('model pricing', () => {
  it('computes cost from usage including cache reads and writes', () => {
    // sonnet-5: $2 in / $10 out / $2.50 cache write / $0.20 cache read per 1M tokens
    const usd = costUsd('claude-sonnet-5', { inputTokens: 1_000_000, outputTokens: 100_000, cacheReadTokens: 500_000, cacheWriteTokens: 200_000 });
    expect(usd).toBeCloseTo(2 + 1 + 0.1 + 0.5, 6);
  });

  it('prices unknown models conservatively (field-wise max across the PRICING table)', () => {
    // Max of each field independently across all known models (currently Fable 5.1 rates for
    // input/output/cacheWrite, Opus 5's rate for cacheRead) - never under-count spend against budget.
    expect(priceOf('some-future-model')).toEqual({ input: 10, output: 50, cacheWrite: 12.5, cacheRead: 0.5 });
  });
});

describe('model capabilities', () => {
  it('sends adaptive thinking and effort only to models that support them', () => {
    expect(capsOf('claude-haiku-4-5')).toEqual({ adaptiveThinking: false, effort: false });
    expect(capsOf('claude-sonnet-5')).toEqual({ adaptiveThinking: true, effort: true });
    expect(capsOf('claude-opus-5')).toEqual({ adaptiveThinking: true, effort: true });
    expect(capsOf('mystery-model')).toEqual({ adaptiveThinking: false, effort: false });
  });
});

describe('role maps', () => {
  it('falls back on refusal to a different tier and degrades on overload one tier down', () => {
    expect(FALLBACK_ROLE).toEqual({ fast: 'deep', deep: 'synthesis', synthesis: 'deep' });
    expect(DEGRADE_ROLE).toEqual({ synthesis: 'deep', deep: 'fast', fast: null });
  });
});
