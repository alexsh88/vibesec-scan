import { describe, expect, it } from 'vitest';
import { scrubSecrets, scrubDeep } from '../src/security/scrub';

describe('scrubSecrets', () => {
  it.each([
    'ghp_0123456789abcdefghijABCDEFGHIJ012345',
    'github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP',
    'sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789',
    'AKIAIOSFODNN7EXAMPLE',
    'xoxb-1234567890-0987654321-abcdefghij',
    'sk_' + 'live_51H8abcdefghijklmnopqrstu',
  ])('redacts %s', (secret) => {
    const out = scrubSecrets(`token=${secret} end`);
    expect(out).not.toContain(secret);
    expect(out).toContain('[REDACTED]');
  });

  it('redacts authorization headers', () => {
    expect(scrubSecrets('Authorization: Basic eC1hY2Nlc3MtdG9rZW46Z2hwX3h4eA==')).toBe('Authorization: [REDACTED]');
    expect(scrubSecrets('authorization: Bearer abc.def.ghi')).toBe('authorization: [REDACTED]');
  });

  it('redacts opaque authorization values without a scheme keyword', () => {
    expect(scrubSecrets('Authorization: abc123SuperSecretOpaque')).toBe('Authorization: [REDACTED]');
  });

  it('stops redacting an authorization value at the end of a JSON string or line', () => {
    expect(scrubSecrets('{"authorization":"abc123", "other":"x"}')).toBe('{"authorization":"[REDACTED]", "other":"x"}');
    expect(scrubSecrets('Authorization: abc123\nnext line')).toBe('Authorization: [REDACTED]\nnext line');
    expect(scrubSecrets("authorization='abc123', foo=bar")).toBe("authorization='[REDACTED]', foo=bar");
  });

  it('leaves normal text alone', () => {
    expect(scrubSecrets('scan of acme/app at main')).toBe('scan of acme/app at main');
  });

  it('redacts PEM private key blocks', () => {
    const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END RSA PRIVATE KEY-----';
    expect(scrubSecrets(`before ${pem} after`)).toBe('before [REDACTED] after');
  });

  it('redacts an unterminated BEGIN marker line without scanning the whole document', () => {
    const out = scrubSecrets('-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBg (never closed)');
    expect(out).not.toContain('-----BEGIN RSA PRIVATE KEY-----');
    expect(out.startsWith('[REDACTED]')).toBe(true);
  });

  it('scrubs 2 MB of repeated unterminated BEGIN markers in well under 500ms', () => {
    const chunk = '-----BEGIN RSA PRIVATE KEY-----';
    const big = chunk.repeat(Math.ceil((2 * 1024 * 1024) / chunk.length));
    const start = performance.now();
    const out = scrubSecrets(big);
    const elapsed = performance.now() - start;
    expect(out).not.toContain('-----BEGIN RSA PRIVATE KEY-----');
    expect(elapsed).toBeLessThan(500);
  });
});

describe('scrubDeep', () => {
  it('scrubs nested strings and token-like keys', () => {
    const out = scrubDeep({ a: { token: 'whatever', note: 'key AKIAIOSFODNN7EXAMPLE' }, list: ['ghp_0123456789abcdefghijABCDEFGHIJ012345'] });
    expect(out).toEqual({ a: { token: '[REDACTED]', note: 'key [REDACTED]' }, list: ['[REDACTED]'] });
  });

  it('marks cycles instead of crashing with a RangeError', () => {
    const o: any = { a: 1 };
    o.self = o;
    expect(scrubDeep(o)).toEqual({ a: 1, self: '[Circular]' });
  });

  it('marks cycles reached through an array too', () => {
    const o: any = { a: 1 };
    o.list = [o];
    expect(scrubDeep(o)).toEqual({ a: 1, list: ['[Circular]'] });
  });

  it('converts Date instances to their ISO string instead of {}', () => {
    const d = new Date('2026-01-02T03:04:05.000Z');
    expect(scrubDeep({ at: d })).toEqual({ at: '2026-01-02T03:04:05.000Z' });
  });

  it('converts Error instances to a scrubbed {name, message} without a stack', () => {
    const err = new Error('token=ghp_0123456789abcdefghijABCDEFGHIJ012345');
    const out = scrubDeep({ err }) as any;
    expect(out.err).toEqual({ name: 'Error', message: 'token=[REDACTED]' });
    expect(out.err.stack).toBeUndefined();
  });

  it('converts Buffers and typed arrays to a [binary N bytes] placeholder instead of an index map', () => {
    const buf = Buffer.from('hello');
    expect(scrubDeep({ data: buf })).toEqual({ data: '[binary 5 bytes]' });
    const u8 = new Uint8Array([1, 2, 3]);
    expect(scrubDeep({ data: u8 })).toEqual({ data: '[binary 3 bytes]' });
  });

  it('keeps plain objects and arrays behaving as before', () => {
    expect(scrubDeep({ a: [1, 2, { b: 'c' }] })).toEqual({ a: [1, 2, { b: 'c' }] });
  });

  it('redacts broadened sensitive keys like refreshToken, client_secret and auth_token', () => {
    const out = scrubDeep({ refreshToken: 'x', client_secret: 'y', auth_token: 'z' });
    expect(out).toEqual({ refreshToken: '[REDACTED]', client_secret: '[REDACTED]', auth_token: '[REDACTED]' });
  });

  it('does not redact harmless lookalike keys like tokenType, tokenFingerprint, tokenCount, tokenId', () => {
    const out = scrubDeep({ tokenType: 'bearer', tokenFingerprint: 'abc', tokenCount: '3', tokenId: 'abc-123' });
    expect(out).toEqual({ tokenType: 'bearer', tokenFingerprint: 'abc', tokenCount: '3', tokenId: 'abc-123' });
  });
});
