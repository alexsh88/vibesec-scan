import { existsSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type Anthropic from '@anthropic-ai/sdk';
import { z } from 'zod';
import { AppError } from '../errors/AppError';
import { estimateTokens } from './prompt';
import { requestHash, type LlmRequest, type LlmTransport } from './transport';

export type MockResponder = (req: LlmRequest) => unknown | undefined;

type JsonSchema = {
  type?: string | string[]; properties?: Record<string, JsonSchema>; required?: string[]; items?: JsonSchema;
  enum?: unknown[]; const?: unknown; anyOf?: JsonSchema[]; oneOf?: JsonSchema[]; minItems?: number;
  minLength?: number; minimum?: number; exclusiveMinimum?: number; default?: unknown;
};

/**
 * A minimal value that satisfies the schema (enums → first value, mins honored, optional keys omitted).
 *
 * Note on Zod 4's `z.toJSONSchema()`: `.nullable()` is NOT rendered as `anyOf: [{...}, {type:'null'}]`;
 * it collapses into a `type` array, e.g. `{ type: ['string', 'null'] }` (and primitive unions collapse the
 * same way, e.g. `z.union([z.string(), z.number()])` → `{ type: ['string', 'number'] }`). `anyOf`/`oneOf` are
 * reserved for shapes that cannot merge into a single `type` array (object unions, discriminated unions,
 * literals, etc.). `.optional()` leaves the key out of the parent's `required` array rather than marking it
 * on the property schema itself. `.int().min(n)` → `minimum`; `.gt(n)` → `exclusiveMinimum` (a bare number
 * per draft 2020-12, not the draft-04 boolean flag). The top level also carries `$schema` and every object
 * carries `additionalProperties: false` — both are harmless extra keys `fake()` below simply ignores.
 */
export function fakeFromSchema(schema: z.ZodType): unknown {
  return fake(z.toJSONSchema(schema) as JsonSchema);
}

function fake(s: JsonSchema): unknown {
  if (s.const !== undefined) return s.const;
  if (s.enum?.length) return s.enum[0];
  const variant = s.anyOf?.[0] ?? s.oneOf?.[0];
  if (variant) return fake(variant);
  const type = Array.isArray(s.type) ? s.type.find((t) => t !== 'null') ?? 'null' : s.type;
  switch (type) {
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const key of s.required ?? []) out[key] = fake(s.properties?.[key] ?? {});
      return out;
    }
    case 'array':
      return Array.from({ length: s.minItems ?? 0 }, () => fake(s.items ?? {}));
    case 'string':
      return 'x'.repeat(Math.max(s.minLength ?? 0, 4)).replace(/^x{4}$/, 'mock');
    case 'integer':
    case 'number':
      return s.minimum ?? (s.exclusiveMinimum !== undefined ? s.exclusiveMinimum + 1 : 0);
    case 'boolean':
      return false;
    case 'null':
      return null;
    default:
      return null;
  }
}

export class MockTransport implements LlmTransport {
  readonly mode = 'mock' as const;

  constructor(private readonly opts: { recordingsDir?: string; responders?: MockResponder[] } = {}) {}

  async send(req: LlmRequest, signal: AbortSignal): Promise<Anthropic.Message> {
    if (signal.aborted) throw new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');
    const hash = requestHash(req);
    if (this.opts.recordingsDir) {
      const file = join(this.opts.recordingsDir, `${hash}.json`);
      if (existsSync(file)) return JSON.parse(await readFile(file, 'utf8')) as Anthropic.Message;
    }
    let output: unknown;
    for (const responder of this.opts.responders ?? []) {
      output = responder(req);
      if (output !== undefined) break;
    }
    if (output === undefined) output = fakeFromSchema(req.schema);
    const text = JSON.stringify(output);
    return {
      id: `msg_mock_${hash.slice(0, 16)}`,
      type: 'message',
      role: 'assistant',
      model: req.model,
      content: [{ type: 'text', text, citations: null }],
      stop_reason: 'end_turn',
      stop_sequence: null,
      usage: {
        input_tokens: estimateTokens(JSON.stringify(req.system) + JSON.stringify(req.messages)),
        output_tokens: estimateTokens(text),
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
      },
    } as unknown as Anthropic.Message;
  }
}

/** Wraps a live transport and stores every response for later deterministic replay (own fixture repos only). */
export class RecordingTransport implements LlmTransport {
  readonly mode = 'record' as const;

  constructor(private readonly inner: LlmTransport, private readonly recordingsDir: string) {}

  async send(req: LlmRequest, signal: AbortSignal): Promise<Anthropic.Message> {
    const message = await this.inner.send(req, signal);
    await mkdir(this.recordingsDir, { recursive: true });
    await writeFile(join(this.recordingsDir, `${requestHash(req)}.json`), JSON.stringify(message, null, 2));
    return message;
  }
}
