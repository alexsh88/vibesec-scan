import { describe, expect, it } from 'vitest';
import { signV4 } from '../src/analyzers/credentials/sigv4';

describe('signV4', () => {
  // AWS SigV4 test suite "get-vanilla": https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
  it('matches the AWS SigV4 "get-vanilla" test vector', () => {
    const headers = signV4({
      method: 'GET',
      url: 'https://example.amazonaws.com/',
      headers: {},
      body: '',
      region: 'us-east-1',
      service: 'service',
      accessKeyId: 'AKIDEXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
      now: new Date('2015-08-30T12:36:00Z'),
    });

    expect(headers.authorization).toBe(
      'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, ' +
        'SignedHeaders=host;x-amz-date, ' +
        'Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31',
    );
    expect(headers.host).toBe('example.amazonaws.com');
    expect(headers['x-amz-date']).toBe('20150830T123600Z');
  });

  it('is deterministic for the same inputs', () => {
    const req = {
      method: 'POST',
      url: 'https://sts.amazonaws.com/',
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
      body: 'Action=GetCallerIdentity&Version=2011-06-15',
      region: 'us-east-1',
      service: 'sts',
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
      now: new Date('2026-01-02T03:04:05Z'),
    };
    const a = signV4(req);
    const b = signV4(req);
    expect(a).toEqual(b);
  });

  it('never leaks the secret access key into the returned headers', () => {
    const secretAccessKey = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
    const headers = signV4({
      method: 'POST',
      url: 'https://sts.amazonaws.com/',
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
      body: 'Action=GetCallerIdentity&Version=2011-06-15',
      region: 'us-east-1',
      service: 'sts',
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey,
      now: new Date('2026-01-02T03:04:05Z'),
    });
    expect(JSON.stringify(headers)).not.toContain(secretAccessKey);
  });

  it('produces different signatures for different request bodies', () => {
    const base = {
      method: 'POST' as const,
      url: 'https://sts.amazonaws.com/',
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
      region: 'us-east-1',
      service: 'sts',
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
      now: new Date('2026-01-02T03:04:05Z'),
    };
    const a = signV4({ ...base, body: 'Action=GetCallerIdentity&Version=2011-06-15' });
    const b = signV4({ ...base, body: 'Action=Other&Version=2011-06-15' });
    expect(a.authorization).not.toBe(b.authorization);
  });
});
