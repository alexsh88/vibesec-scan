import Anthropic from '@anthropic-ai/sdk';
import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { AnthropicTransport, mapAnthropicError } from '../src/llm/anthropicTransport';
import { requestHash, type LlmRequest } from '../src/llm/transport';

const Out = z.object({ verdict: z.enum(['safe', 'vulnerable']), reason: z.string() });

const req = (over: Partial<LlmRequest> = {}): LlmRequest => ({
  model: 'claude-sonnet-5',
  system: [{ type: 'text', text: 'You are a reviewer.', cache_control: { type: 'ephemeral' } }],
  messages: [{ role: 'user', content: [{ type: 'text', text: 'Review this.' }] }],
  maxTokens: 4_000,
  thinking: true,
  effort: 'medium',
  schema: Out,
  ...over,
});

const message = { id: 'msg_1', type: 'message', role: 'assistant', model: 'claude-sonnet-5', content: [], stop_reason: 'end_turn' };

function transport() {
  const create = vi.fn(async () => message);
  const t = new AnthropicTransport({ messages: { create } } as unknown as Anthropic, 120_000);
  return { t, create };
}

describe('AnthropicTransport', () => {
  it('builds a create call with structured output, adaptive thinking, effort and the abort signal', async () => {
    const { t, create } = transport();
    const ac = new AbortController();
    await expect(t.send(req(), ac.signal)).resolves.toBe(message);
    const [params, options] = create.mock.calls[0] as unknown as [Record<string, any>, Record<string, any>];
    expect(params).toMatchObject({
      model: 'claude-sonnet-5', max_tokens: 4_000,
      system: [{ type: 'text', text: 'You are a reviewer.', cache_control: { type: 'ephemeral' } }],
      thinking: { type: 'adaptive' },
      output_config: { effort: 'medium', format: expect.objectContaining({ type: 'json_schema' }) },
    });
    expect(options).toMatchObject({ signal: ac.signal, timeout: 120_000 });
  });

  it('omits thinking and effort when not requested', async () => {
    const { t, create } = transport();
    await t.send(req({ model: 'claude-haiku-4-5', thinking: false, effort: undefined }), new AbortController().signal);
    const [params] = create.mock.calls[0] as unknown as [Record<string, any>];
    expect(params.thinking).toBeUndefined();
    expect(params.output_config.effort).toBeUndefined();
  });

  it('maps SDK errors to AppErrors', async () => {
    const { t, create } = transport();
    create.mockRejectedValueOnce(new Anthropic.RateLimitError(429, {}, 'rate limited', new Headers({ 'retry-after': '7' })));
    await expect(t.send(req(), new AbortController().signal)).rejects.toMatchObject({
      code: 'LLM_UNAVAILABLE', kind: 'transient', retryAfterMs: 7_000, details: { rateLimited: true },
    });
  });
});

describe('mapAnthropicError', () => {
  const h = new Headers();
  it.each([
    [new Anthropic.APIUserAbortError(), 'CANCELLED', 'cancelled'],
    [new Anthropic.APIConnectionTimeoutError(), 'LLM_UNAVAILABLE', 'transient'],
    [new Anthropic.APIConnectionError({ message: 'socket hang up' }), 'LLM_UNAVAILABLE', 'transient'],
    [new Anthropic.InternalServerError(529, {}, 'Overloaded', h), 'LLM_UNAVAILABLE', 'transient'],
    [new Anthropic.AuthenticationError(401, {}, 'invalid x-api-key', h), 'LLM_UNAVAILABLE', 'permanent'],
    [new Anthropic.PermissionDeniedError(403, {}, 'forbidden', h), 'LLM_UNAVAILABLE', 'permanent'],
    // error body omitted (undefined, not {}): APIError.makeMessage in the real SDK falls back to
    // JSON.stringify(error) whenever the error-body arg is a truthy object without a .message field,
    // discarding the `message` argument entirely — so `{}` here would make err.message "400 {}" and
    // the contextTooLarge detection below would never see the "prompt is too long" text.
    [new Anthropic.BadRequestError(400, undefined, 'prompt is too long: 1200000 tokens > 1000000 maximum', h), 'LLM_OUTPUT_INVALID', 'permanent'],
    [new Anthropic.BadRequestError(400, {}, 'max_tokens: must be positive', h), 'INTERNAL', 'permanent'],
    [new Anthropic.NotFoundError(404, {}, 'model not found', h), 'INTERNAL', 'permanent'],
  ])('%s → %s/%s', (err, code, kind) => {
    expect(mapAnthropicError(err)).toMatchObject({ code, kind });
  });

  it('flags context-too-large errors so callers can chunk', () => {
    const err = mapAnthropicError(new Anthropic.BadRequestError(400, undefined, 'prompt is too long', h));
    expect(err.details).toMatchObject({ contextTooLarge: true });
  });

  it('never puts the API key or raw provider text into the user message', () => {
    const err = mapAnthropicError(new Anthropic.AuthenticationError(401, {}, 'invalid x-api-key sk-ant-api03-SECRETSECRETSECRET', h));
    expect(err.userMessage).not.toContain('sk-ant');
  });
});

describe('requestHash', () => {
  it('is stable for equal requests and changes when the prompt text changes', () => {
    const a = requestHash(req());
    const b = requestHash(req());
    expect(a).toBe(b);

    const c = requestHash(req({ messages: [{ role: 'user', content: [{ type: 'text', text: 'Review this differently.' }] }] }));
    expect(c).not.toBe(a);
  });
});
