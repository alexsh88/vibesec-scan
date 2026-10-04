import { z } from 'zod';
import { ScanStateSchema } from './enums';
import { FindingSummarySchema } from './finding';

export const ScanEventSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('state'), state: ScanStateSchema, errorCode: z.string().optional(), message: z.string().optional() }),
  z.object({ type: z.literal('progress'), analyzer: z.string(), done: z.number().int(), total: z.number().int() }),
  z.object({ type: z.literal('finding'), finding: FindingSummarySchema }),
  z.object({ type: z.literal('cache'), filesReused: z.number().int(), filesAnalyzed: z.number().int(), savedUsd: z.number() }),
  z.object({ type: z.literal('cost'), inputTokens: z.number().int(), outputTokens: z.number().int(), cacheReadTokens: z.number().int(), usd: z.number() }),
  z.object({ type: z.literal('warning'), code: z.string(), message: z.string(), stage: z.string().optional(), file: z.string().optional() }),
  z.object({ type: z.literal('done'), state: ScanStateSchema }),
]);
export type ScanEvent = z.infer<typeof ScanEventSchema>;

/** Persisted envelope: what SSE clients receive. */
export type StoredScanEvent = { seq: number; scanId: string; at: string; event: ScanEvent };
