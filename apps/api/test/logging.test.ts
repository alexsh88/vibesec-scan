import { describe, expect, it } from 'vitest';
import { serializeError } from '../src/http/logSerializers';

const TOKEN = `ghp_${'a'.repeat(36)}`;

describe('serializeError', () => {
  it('scrubs secrets from message and stack', () => {
    const err = new Error(`boom ${TOKEN}`);
    const out = serializeError(err);
    expect(out.message).toContain('[REDACTED]');
    expect(out.message).not.toContain(TOKEN);
    expect(out.stack).not.toContain(TOKEN);
    expect(out.type).toBe('Error');
  });

  it('scrubs secrets from an error cause', () => {
    const cause = new Error(`leaked ${TOKEN}`);
    const err = new Error('wrapped', { cause });
    const out = serializeError(err) as { cause?: string };
    expect(out.cause).toContain('[REDACTED]');
    expect(out.cause).not.toContain(TOKEN);
  });

  it('handles a plain string value', () => {
    const out = serializeError(`oops ${TOKEN}`);
    expect(out.type).toBe('string');
    expect(out.message).toContain('[REDACTED]');
    expect(out.message).not.toContain(TOKEN);
  });
});
