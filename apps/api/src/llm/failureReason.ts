// Safe, coarse category of why an LLM call failed — for user-facing warnings. Derived only from the
// AppError's code/kind/details flags, never from provider text or model output, so it can't leak
// repository content, credentials or raw API messages.

import { toAppError } from '../errors/AppError';

export type LlmFailureReason = 'truncated' | 'too-large' | 'validation' | 'refusal' | 'transport' | 'other';

export function llmFailureReason(raw: unknown): LlmFailureReason {
  const err = toAppError(raw);
  const details = (err.details ?? {}) as { truncated?: boolean; contextTooLarge?: boolean };
  if (details.truncated) return 'truncated';
  if (details.contextTooLarge) return 'too-large';
  if (err.code === 'LLM_REFUSAL') return 'refusal';
  if (err.code === 'LLM_OUTPUT_INVALID') return 'validation';
  if (err.code === 'LLM_UNAVAILABLE' || err.kind === 'transient') return 'transport';
  return 'other';
}

/** "2 truncated, 1 transport" — counts per reason, in a stable order. */
export function formatFailureReasons(counts: ReadonlyMap<LlmFailureReason, number>): string {
  const order: LlmFailureReason[] = ['truncated', 'too-large', 'validation', 'refusal', 'transport', 'other'];
  return order.filter((r) => (counts.get(r) ?? 0) > 0).map((r) => `${counts.get(r)} ${r}`).join(', ');
}
