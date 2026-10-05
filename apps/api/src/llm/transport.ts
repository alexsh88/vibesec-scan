import { createHash } from 'node:crypto';
import type Anthropic from '@anthropic-ai/sdk';
import { z } from 'zod';
import { canonicalJson } from '../audit/canonicalJson';
import type { Effort } from './models';

/** Provider-neutral request built by LlmClient. */
export type LlmRequest = {
  model: string;
  system: Anthropic.TextBlockParam[];
  messages: Anthropic.MessageParam[];
  maxTokens: number;
  thinking: boolean;
  effort?: Effort;
  schema: z.ZodType;
};

export interface LlmTransport {
  readonly mode: 'live' | 'record' | 'mock';
  send(req: LlmRequest, signal: AbortSignal): Promise<Anthropic.Message>;
}

/** Stable identity of a request (recordings key, llm_calls.input_hash). Never includes secrets or timestamps. */
export function requestHash(req: LlmRequest): string {
  return createHash('sha256').update(canonicalJson({
    model: req.model, system: req.system, messages: req.messages, maxTokens: req.maxTokens,
    thinking: req.thinking, effort: req.effort ?? null, schema: z.toJSONSchema(req.schema),
  })).digest('hex');
}
