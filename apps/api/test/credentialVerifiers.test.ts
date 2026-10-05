import { describe, expect, it, vi } from 'vitest';
import type { AuditInput } from '../src/audit/AuditLogger';
import { SecretVerifier, type VerifiableSecret } from '../src/analyzers/credentials/verifiers';

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const text = (status: number, body: string) => new Response(body, { status });

function fakeAudit() {
  const entries: AuditInput[] = [];
  return { entries, append: vi.fn((input: AuditInput) => { entries.push(input); return input; }) };
}

function secret(over: Partial<VerifiableSecret> & { type: string; value: string; hash: string }): VerifiableSecret {
  return { redacted: '****', ...over };
}

describe('SecretVerifier', () => {
  it('verifies a github-token with the right request and maps 200 -> live', async () => {
    const fetchMock = vi.fn(async () => json(200, { login: 'octocat' }));
    const audit = fakeAudit();
    const v = new SecretVerifier({ fetch: fetchMock as unknown as typeof fetch, audit });

    const s = secret({ type: 'github-token', value: 'ghp_abc', hash: 'h'.repeat(64) });
    const result = await v.verify('scan1', s, new AbortController().signal);

    expect(result.liveness).toBe('live');
    expect(result.provider).toBe('github');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://api.github.com/user');
    const h = new Headers(init.headers);
    expect(h.get('authorization')).toBe('Bearer ghp_abc');
    expect(h.get('user-agent')).toBe('vibesec-scan');
    expect(h.get('accept')).toBe('application/vnd.github+json');

    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]).toMatchObject({
      action: 'secret.verification_attempted',
      scanId: 'scan1',
      details: { provider: 'github', secretType: 'github-token', redacted: '****', result: 'live', httpStatus: 200 },
    });
  });

  it('maps github 401 -> revoked', async () => {
    const fetchMock = vi.fn(async () => json(401, {}));
    const v = new SecretVerifier({ fetch: fetchMock as unknown as typeof fetch, audit: fakeAudit() });
    const result = await v.verify('s', secret({ type: 'github-token', value: 'x', hash: 'a'.repeat(64) }), new AbortController().signal);
    expect(result.liveness).toBe('revoked');
  });

  it('stripe: 403 (restricted key without balance scope) still proves live, 401 -> revoked', async () => {
    const live = new SecretVerifier({ fetch: (async () => text(403, '{}')) as unknown as typeof fetch, audit: fakeAudit() });
    const r1 = await live.verify('s', secret({ type: 'stripe-restricted-key', value: 'rk_x', hash: 'b'.repeat(64) }), new AbortController().signal);
    expect(r1.liveness).toBe('live');

    const revoked = new SecretVerifier({ fetch: (async () => json(401, {})) as unknown as typeof fetch, audit: fakeAudit() });
    const r2 = await revoked.verify('s', secret({ type: 'stripe-secret-key', value: 'sk_x', hash: 'c'.repeat(64) }), new AbortController().signal);
    expect(r2.liveness).toBe('revoked');
  });

  it('slack: ok:true -> live, ok:false invalid_auth -> revoked, correct request', async () => {
    const fetchMock = vi.fn(async () => json(200, { ok: true }));
    const v = new SecretVerifier({ fetch: fetchMock as unknown as typeof fetch, audit: fakeAudit() });
    const r1 = await v.verify('s', secret({ type: 'slack-token', value: 'xoxb-x', hash: 'd'.repeat(64) }), new AbortController().signal);
    expect(r1.liveness).toBe('live');
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://slack.com/api/auth.test');
    expect(init.method).toBe('POST');
    expect(new Headers(init.headers).get('authorization')).toBe('Bearer xoxb-x');

    const v2 = new SecretVerifier({ fetch: (async () => json(200, { ok: false, error: 'invalid_auth' })) as unknown as typeof fetch, audit: fakeAudit() });
    const r2 = await v2.verify('s', secret({ type: 'slack-token', value: 'xoxb-y', hash: 'e'.repeat(64) }), new AbortController().signal);
    expect(r2.liveness).toBe('revoked');
  });

  it('aws-access-key: 403 InvalidClientTokenId -> revoked, signed via SigV4', async () => {
    const fetchMock = vi.fn(async () => text(403, '<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>'));
    const v = new SecretVerifier({ fetch: fetchMock as unknown as typeof fetch, audit: fakeAudit() });
    const s = secret({ type: 'aws-access-key', value: 'AKIAIOSFODNN7EXAMPLE', pairedSecret: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', hash: 'f'.repeat(64) });
    const result = await v.verify('s', s, new AbortController().signal);
    expect(result.liveness).toBe('revoked');
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://sts.amazonaws.com/');
    expect(init.method).toBe('POST');
    expect(init.body).toBe('Action=GetCallerIdentity&Version=2011-06-15');
    const h = new Headers(init.headers);
    expect(h.get('authorization')).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE\//);
    expect(JSON.stringify(init.headers)).not.toContain('wJalrXUtnFEMI');
  });

  it('aws-access-key without a pairedSecret resolves unknown with no network call', async () => {
    const fetchMock = vi.fn(async () => json(200, {}));
    const v = new SecretVerifier({ fetch: fetchMock as unknown as typeof fetch, audit: fakeAudit() });
    const result = await v.verify('s', secret({ type: 'aws-access-key', value: 'AKIAIOSFODNN7EXAMPLE', hash: 'g'.repeat(64) }), new AbortController().signal);
    expect(result.liveness).toBe('unknown');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('I3a: ASIA (temporary) access key without a session token resolves unknown with no network call, even with a pairedSecret', async () => {
    const fetchMock = vi.fn(async () => json(200, {}));
    const v = new SecretVerifier({ fetch: fetchMock as unknown as typeof fetch, audit: fakeAudit() });
    const s = secret({
      type: 'aws-access-key', value: 'ASIAIOSFODNN7EXAMPLE',
      pairedSecret: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', hash: 'q1'.padEnd(64, '0'),
    });
    const result = await v.verify('s', s, new AbortController().signal);
    expect(result.liveness).toBe('unknown');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('I3b: aws-access-key 403 SignatureDoesNotMatch (mis-paired secret) -> unknown, never revoked', async () => {
    const fetchMock = vi.fn(async () => text(403, '<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>'));
    const v = new SecretVerifier({ fetch: fetchMock as unknown as typeof fetch, audit: fakeAudit() });
    const s = secret({
      type: 'aws-access-key', value: 'AKIAIOSFODNN7EXAMPLE',
      pairedSecret: 'wrongSecretWrongSecretWrongSecretWrongS', hash: 'r1'.padEnd(64, '0'),
    });
    const result = await v.verify('s', s, new AbortController().signal);
    expect(result.liveness).toBe('unknown');
  });

  it('I3b: a temporary (ASIA) key with a session token that still gets InvalidClientTokenId from STS -> unknown, not revoked', async () => {
    const fetchMock = vi.fn(async () => text(403, '<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>'));
    const v = new SecretVerifier({ fetch: fetchMock as unknown as typeof fetch, audit: fakeAudit() });
    const s = secret({
      type: 'aws-access-key', value: 'ASIAIOSFODNN7EXAMPLE', pairedSecret: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
      sessionToken: 'FQoGZXIvYXdzEBYaDHRlc3Rfc2Vzc2lvbg==', hash: 't1'.padEnd(64, '0'),
    });
    const result = await v.verify('s', s, new AbortController().signal);
    expect(result.liveness).toBe('unknown');
  });

  it.each(['github-token', 'openai-api-key', 'anthropic-api-key', 'sendgrid-api-key'])(
    'I3c: %s 403 -> unknown (rate limit/IP allow-list/permissions), 401 stays revoked',
    async (type) => {
      const revoked = new SecretVerifier({ fetch: (async () => json(401, {})) as unknown as typeof fetch, audit: fakeAudit() });
      const r1 = await revoked.verify('s', secret({ type, value: 'x', hash: 'u'.repeat(64) }), new AbortController().signal);
      expect(r1.liveness).toBe('revoked');

      const unknown = new SecretVerifier({ fetch: (async () => json(403, {})) as unknown as typeof fetch, audit: fakeAudit() });
      const r2 = await unknown.verify('s', secret({ type, value: 'x', hash: 'v'.repeat(64) }), new AbortController().signal);
      expect(r2.liveness).toBe('unknown');
    },
  );

  it('M3: every fetch uses redirect: manual, so a 3xx (opaque-redirect) response resolves unknown', async () => {
    const fetchMock = vi.fn(async () => text(200, ''));
    const v = new SecretVerifier({ fetch: fetchMock as unknown as typeof fetch, audit: fakeAudit() });
    await v.verify('s', secret({ type: 'github-token', value: 'x', hash: 'w'.repeat(64) }), new AbortController().signal);
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.redirect).toBe('manual');
  });

  it('M3: cancels an unread response body (default interpreter never reads it)', async () => {
    const cancel = vi.fn(async () => {});
    const fakeRes = {
      status: 200, bodyUsed: false, body: { cancel }, json: async () => ({}), text: async () => '',
    } as unknown as Response;
    const fetchMock = vi.fn(async () => fakeRes);
    const v = new SecretVerifier({ fetch: fetchMock as unknown as typeof fetch, audit: fakeAudit() });
    await v.verify('s', secret({ type: 'github-token', value: 'x', hash: 'n1'.padEnd(64, '0') }), new AbortController().signal);
    expect(cancel).toHaveBeenCalledTimes(1);
  });

  it('M3: swallows an audit.append failure without failing verification', async () => {
    const fetchMock = vi.fn(async () => json(200, { login: 'x' }));
    const audit = { append: vi.fn(() => { throw new Error('db locked'); }) };
    const v = new SecretVerifier({ fetch: fetchMock as unknown as typeof fetch, audit });
    const result = await v.verify('s', secret({ type: 'github-token', value: 'x', hash: 'o1'.padEnd(64, '0') }), new AbortController().signal);
    expect(result.liveness).toBe('live');
  });

  it('M3: records an aborted audit entry (unknown, aborted) before rethrowing when cancelled mid-flight', async () => {
    let started: (() => void) | undefined;
    const hangingFetch = vi.fn((_url: string, init: RequestInit) => new Promise<Response>((_resolve, reject) => {
      started?.();
      init.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
    }));
    const startedPromise = new Promise<void>((resolve) => { started = resolve; });
    const ac = new AbortController();
    const audit = fakeAudit();
    const v = new SecretVerifier({ fetch: hangingFetch as unknown as typeof fetch, audit });
    const p = v.verify('s', secret({ type: 'anthropic-api-key', value: 'sk-ant-x', hash: 'p1'.padEnd(64, '0') }), ac.signal);
    await startedPromise;
    ac.abort(new Error('scan cancelled'));
    await expect(p).rejects.toThrow('scan cancelled');
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]?.details).toMatchObject({ result: 'unknown', aborted: true });
  });

  it.each(['database-url', 'slack-webhook', 'google', 'generic'])(
    'non-verifiable type %s resolves unknown with zero fetch calls and zero audit entries',
    async (type) => {
      const fetchMock = vi.fn(async () => json(200, {}));
      const audit = fakeAudit();
      const v = new SecretVerifier({ fetch: fetchMock as unknown as typeof fetch, audit });
      const s = secret({ type, value: 'postgres://user:pass@attacker.example.com:5432/db', hash: `${type}`.padEnd(64, '0') });
      const result = await v.verify('s', s, new AbortController().signal);
      expect(result.liveness).toBe('unknown');
      expect(fetchMock).not.toHaveBeenCalled();
      expect(audit.entries).toHaveLength(0);
    },
  );

  it('network error resolves unknown (and still records one audit entry)', async () => {
    const fetchMock = vi.fn(async () => { throw new TypeError('fetch failed'); });
    const audit = fakeAudit();
    const v = new SecretVerifier({ fetch: fetchMock as unknown as typeof fetch, audit });
    const result = await v.verify('s', secret({ type: 'openai-api-key', value: 'sk-x', hash: 'h1'.padEnd(64, '0') }), new AbortController().signal);
    expect(result.liveness).toBe('unknown');
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]?.details?.httpStatus).toBeUndefined();
  });

  it('a timeout (fetch that never resolves) with a short timeoutMs resolves unknown', async () => {
    const hangingFetch = vi.fn((_url: string, init: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
    }));
    const v = new SecretVerifier({ fetch: hangingFetch as unknown as typeof fetch, audit: fakeAudit(), timeoutMs: 20 });
    const result = await v.verify('s', secret({ type: 'anthropic-api-key', value: 'sk-ant-x', hash: 'i1'.padEnd(64, '0') }), new AbortController().signal);
    expect(result.liveness).toBe('unknown');
  });

  it('rejects (does not swallow) when the scan signal is already aborted', async () => {
    const hangingFetch = vi.fn((_url: string, init: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
    }));
    const ac = new AbortController();
    ac.abort(new Error('scan cancelled'));
    const v = new SecretVerifier({ fetch: hangingFetch as unknown as typeof fetch, audit: fakeAudit() });
    await expect(v.verify('s', secret({ type: 'anthropic-api-key', value: 'sk-ant-x', hash: 'j1'.padEnd(64, '0') }), ac.signal)).rejects.toThrow('scan cancelled');
  });

  it('caches by scanId:hash: concurrent callers share one in-flight call, one audit entry; forget clears it', async () => {
    let calls = 0;
    const fetchMock = vi.fn(async () => { calls += 1; return json(200, { login: 'x' }); });
    const audit = fakeAudit();
    const v = new SecretVerifier({ fetch: fetchMock as unknown as typeof fetch, audit });
    const s = secret({ type: 'github-token', value: 'ghp_same', hash: 'k1'.padEnd(64, '0') });
    const sig = new AbortController().signal;

    const [a, b] = await Promise.all([v.verify('scanA', s, sig), v.verify('scanA', s, sig)]);
    expect(a).toEqual(b);
    await v.verify('scanA', s, sig);
    expect(calls).toBe(1);
    expect(audit.entries).toHaveLength(1);

    v.forget('scanA');
    await v.verify('scanA', s, sig);
    expect(calls).toBe(2);
  });

  it('never includes the raw secret value in audit details, and includes redacted + hashPrefix + result', async () => {
    const fetchMock = vi.fn(async () => json(200, { login: 'x' }));
    const audit = fakeAudit();
    const v = new SecretVerifier({ fetch: fetchMock as unknown as typeof fetch, audit });
    const rawValue = 'ghp_SuperSecretRawValue1234567890';
    const s = secret({ type: 'github-token', value: rawValue, redacted: 'ghp_****7890', hash: 'l1'.padEnd(64, '0') });
    await v.verify('s', s, new AbortController().signal);

    const entry = audit.entries[0];
    expect(entry).toBeDefined();
    expect(JSON.stringify(entry)).not.toContain(rawValue);
    expect(entry?.details).toMatchObject({ redacted: 'ghp_****7890', hashPrefix: s.hash.slice(0, 12), result: 'live' });
  });

  it('serializes calls per provider: a second github secret only starts fetching after the first resolves', async () => {
    const order: string[] = [];
    let releaseFirst: (() => void) | undefined;
    const fetchMock = vi.fn(async (_url: string, init: RequestInit) => {
      const token = new Headers(init.headers).get('authorization');
      order.push(`start:${token}`);
      if (!releaseFirst) {
        await new Promise<void>((resolve) => { releaseFirst = resolve; });
      }
      order.push(`end:${token}`);
      return json(200, {});
    });
    const v = new SecretVerifier({ fetch: fetchMock as unknown as typeof fetch, audit: fakeAudit() });
    const sig = new AbortController().signal;

    const p1 = v.verify('s', secret({ type: 'github-token', value: 'tok1', hash: 'm1'.padEnd(64, '0') }), sig);
    const p2 = v.verify('s', secret({ type: 'github-token', value: 'tok2', hash: 'm2'.padEnd(64, '0') }), sig);

    await vi.waitFor(() => expect(order).toEqual(['start:Bearer tok1']));
    releaseFirst?.();
    await Promise.all([p1, p2]);

    expect(order).toEqual(['start:Bearer tok1', 'end:Bearer tok1', 'start:Bearer tok2', 'end:Bearer tok2']);
  });
});
