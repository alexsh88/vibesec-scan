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

  it('leaves normal text alone', () => {
    expect(scrubSecrets('scan of acme/app at main')).toBe('scan of acme/app at main');
  });
});

describe('scrubDeep', () => {
  it('scrubs nested strings and token-like keys', () => {
    const out = scrubDeep({ a: { token: 'whatever', note: 'key AKIAIOSFODNN7EXAMPLE' }, list: ['ghp_0123456789abcdefghijABCDEFGHIJ012345'] });
    expect(out).toEqual({ a: { token: '[REDACTED]', note: 'key [REDACTED]' }, list: ['[REDACTED]'] });
  });
});
