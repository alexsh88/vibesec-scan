export type ModelRole = 'fast' | 'deep' | 'synthesis';
export type Effort = 'low' | 'medium' | 'high' | 'xhigh' | 'max';
export type TokenUsage = { inputTokens: number; outputTokens: number; cacheReadTokens: number; cacheWriteTokens: number };

/** USD per 1M tokens. cacheWrite = 1.25× input (5-minute TTL); cacheRead per model. */
type Price = { input: number; output: number; cacheWrite: number; cacheRead: number };

const PRICING: Record<string, Price> = {
  'claude-haiku-4-5': { input: 1, output: 5, cacheWrite: 1.25, cacheRead: 0.1 },
  'claude-sonnet-5': { input: 2, output: 10, cacheWrite: 2.5, cacheRead: 0.2 },
  'claude-opus-5': { input: 5, output: 25, cacheWrite: 6.25, cacheRead: 0.5 },
  'claude-opus-5-5': { input: 4, output: 20, cacheWrite: 5, cacheRead: 0.2 },
  'claude-fable-5-1': { input: 10, output: 50, cacheWrite: 12.5, cacheRead: 0.25 },
};

const KNOWN_PRICES = Object.values(PRICING);
/**
 * Field-wise maximum across every known model's rates, used for unknown models. A single
 * row (e.g. Opus 5) isn't conservative enough: a future model could beat Opus 5 on input/output
 * but not be the row we picked. Taking the max of each field independently guarantees the
 * fallback never under-prices any dimension relative to a known model, so budget tracking never
 * under-counts spend against an unlisted model - the only failure mode worth avoiding here.
 */
const CONSERVATIVE_PRICE: Price = {
  input: Math.max(...KNOWN_PRICES.map((p) => p.input)),
  output: Math.max(...KNOWN_PRICES.map((p) => p.output)),
  cacheWrite: Math.max(...KNOWN_PRICES.map((p) => p.cacheWrite)),
  cacheRead: Math.max(...KNOWN_PRICES.map((p) => p.cacheRead)),
};

export function priceOf(model: string): Price {
  return PRICING[model] ?? CONSERVATIVE_PRICE;
}

export function costUsd(model: string, u: TokenUsage): number {
  const p = priceOf(model);
  return (u.inputTokens * p.input + u.outputTokens * p.output + u.cacheWriteTokens * p.cacheWrite + u.cacheReadTokens * p.cacheRead) / 1_000_000;
}

export type ModelCaps = { adaptiveThinking: boolean; effort: boolean };

/** Adaptive thinking + effort exist on Opus/Sonnet 4.6+ and the 5.x families; never on Haiku 4.5 or unknown ids. */
export function capsOf(model: string): ModelCaps {
  const modern = /^claude-(opus|sonnet|fable|mythos)-(4-[678]|5)(-|$)/.test(model);
  return { adaptiveThinking: modern, effort: modern };
}

/** Refusal: retry once on a different tier. */
export const FALLBACK_ROLE: Record<ModelRole, ModelRole> = { fast: 'deep', deep: 'synthesis', synthesis: 'deep' };
/** Overload after retries: one tier down (findings from a degraded call get lower confidence). */
export const DEGRADE_ROLE: Record<ModelRole, ModelRole | null> = { synthesis: 'deep', deep: 'fast', fast: null };
export const DEFAULT_EFFORT: Record<ModelRole, Effort | undefined> = { fast: undefined, deep: 'medium', synthesis: 'high' };
