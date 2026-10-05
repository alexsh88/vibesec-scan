import { createHash } from 'node:crypto';
import type Anthropic from '@anthropic-ai/sdk';
import { z } from 'zod';
import { canonicalJson } from '../audit/canonicalJson';
import type { Effort } from './models';

/** A client tool offered to the model (agent loops). `input_schema` is a JSON schema of type object. */
export type LlmToolDef = { name: string; description: string; input_schema: Anthropic.Tool.InputSchema };

/** Provider-neutral request built by LlmClient. */
export type LlmRequest = {
  model: string;
  system: Anthropic.TextBlockParam[];
  messages: Anthropic.MessageParam[];
  maxTokens: number;
  thinking: boolean;
  effort?: Effort;
  /** Structured output (JSON schema) — requested only when present. */
  schema?: z.ZodType;
  /** Client tools (agent loops). */
  tools?: LlmToolDef[];
  toolChoice?: Anthropic.ToolChoice;
};

export interface LlmTransport {
  readonly mode: 'live' | 'record' | 'mock';
  send(req: LlmRequest, signal: AbortSignal): Promise<Anthropic.Message>;
}

/**
 * Stable identity of a request (recordings key, llm_calls.input_hash). Never includes secrets or timestamps.
 * `tools` / `toolChoice` only enter the hashed object when present, so the hashes (and recordings) of plain
 * structured requests are unchanged.
 */
export function requestHash(req: LlmRequest): string {
  return createHash('sha256').update(canonicalJson({
    model: req.model, system: req.system, messages: req.messages, maxTokens: req.maxTokens,
    thinking: req.thinking, effort: req.effort ?? null, schema: req.schema ? z.toJSONSchema(req.schema) : null,
    ...(req.tools ? { tools: req.tools } : {}),
    ...(req.toolChoice ? { toolChoice: req.toolChoice } : {}),
  })).digest('hex');
}
