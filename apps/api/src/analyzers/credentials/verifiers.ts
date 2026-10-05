import type { AuditInput } from '../../audit/AuditLogger';
import { scrubSecrets } from '../../security/scrub';
import { signV4 } from './sigv4';

export type Liveness = 'live' | 'revoked' | 'unknown' | 'not_checked';

export type VerifiableSecret = {
  type: string;
  value: string;
  redacted: string;
  hash: string;
  pairedSecret?: string;
  /** AWS temporary-credential session token (STS `x-amz-security-token`). Not yet populated by the
   *  scanner today (ASIA keys are only ever reported without a paired session token), but the field
   *  exists so that STS is called correctly if/when one is ever captured. */
  sessionToken?: string;
};

export type VerifyResult = {
  liveness: Liveness;
  checkedAt?: string;
  provider?: string;
};

export type SecretVerifierDeps = {
  fetch?: typeof fetch;
  audit: { append(input: AuditInput): unknown };
  timeoutMs?: number;
  now?: () => Date;
};

type Interpreter = (res: Response | null) => Promise<Liveness>;

type ProviderRequest = {
  provider: string;
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
  interpret: Interpreter;
};

const DEFAULT_TIMEOUT_MS = 5_000;

/** Releases a response body we are never going to read, so the underlying connection can be freed. */
async function discardBody(res: Response | null): Promise<void> {
  if (!res || res.bodyUsed || !res.body) return;
  try {
    await res.body.cancel();
  } catch {
    // best-effort; never fail verification because a body couldn't be released
  }
}

/**
 * 401 (bad/revoked credentials) -> revoked. Everything else -> unknown, in particular 403: a 403 can
 * mean a rate limit, an IP allow-list, or a permissions-scoped token, none of which prove the
 * credential itself is dead (I3c). A 3xx is never followed (fetch uses `redirect: 'manual'`), so it
 * also lands here as an opaque, statusless response -> unknown (M3).
 */
function defaultStatusMap(status: number): Liveness {
  if (status === 200) return 'live';
  if (status === 401) return 'revoked';
  return 'unknown';
}

async function interpretDefault(res: Response | null): Promise<Liveness> {
  if (!res) return 'unknown';
  await discardBody(res);
  return defaultStatusMap(res.status);
}

async function interpretStripe(res: Response | null): Promise<Liveness> {
  if (!res) return 'unknown';
  await discardBody(res);
  // A 403 for a restricted key lacking the balance permission still proves the key exists.
  if (res.status === 200 || res.status === 403) return 'live';
  if (res.status === 401) return 'revoked';
  return 'unknown';
}

const SLACK_REVOKED_ERRORS = new Set(['invalid_auth', 'account_inactive', 'token_revoked', 'token_expired']);

async function interpretSlack(res: Response | null): Promise<Liveness> {
  if (!res || res.status !== 200) {
    await discardBody(res);
    return 'unknown';
  }
  let body: unknown;
  try {
    body = await res.json();
  } catch {
    return 'unknown';
  }
  if (typeof body !== 'object' || body === null) return 'unknown';
  const ok = (body as Record<string, unknown>).ok;
  const error = (body as Record<string, unknown>).error;
  if (ok === true) return 'live';
  if (ok === false && typeof error === 'string' && SLACK_REVOKED_ERRORS.has(error)) return 'revoked';
  return 'unknown';
}

/** AWS access key ids starting `ASIA` are temporary (STS-issued) credentials that always require a
 *  session token; `AKIA` ids are permanent/long-lived IAM user keys. */
function isTemporaryAwsAccessKey(accessKeyId: string): boolean {
  return accessKeyId.startsWith('ASIA');
}

/**
 * I3a/b: `isPermanentKey` is true only for an `AKIA` id. `SignatureDoesNotMatch` means the *secret*
 * half of the pair is wrong (a mis-paired access key id + secret access key) — it says nothing about
 * whether the access key id itself is still valid, so it must never be treated as revoked. Only
 * `InvalidClientTokenId` on a permanent key proves the key id itself was rejected -> revoked. A
 * temporary (`ASIA`) key is never dispatched here without a session token (see `dispatch`), but if it
 * ever is and STS still reports `InvalidClientTokenId`, that is unknown too, not revoked.
 */
function interpretAws(isPermanentKey: boolean): Interpreter {
  return async (res: Response | null): Promise<Liveness> => {
    if (!res) return 'unknown';
    if (res.status === 200) {
      await discardBody(res);
      return 'live';
    }
    if (res.status === 403) {
      let text = '';
      try {
        text = await res.text();
      } catch {
        text = '';
      }
      if (isPermanentKey && text.includes('InvalidClientTokenId')) return 'revoked';
      return 'unknown';
    }
    await discardBody(res);
    return 'unknown';
  };
}

function abortReason(signal: AbortSignal, fallback: unknown): unknown {
  return signal.reason ?? fallback;
}

/**
 * Verifies whether a discovered secret is still live, against a small set of FIXED provider
 * hosts only — never a host or URL derived from scanned repo content. Non-verifiable secret
 * types (database URLs, webhooks, generic matches, …) resolve to `unknown` without any
 * network call. Every call that actually reaches a provider is recorded as exactly one
 * `secret.verification_attempted` audit entry; the raw secret value is never included in
 * that entry, in thrown errors, or in the returned VerifyResult.
 */
export class SecretVerifier {
  private readonly fetchFn: typeof fetch;
  private readonly audit: { append(input: AuditInput): unknown };
  private readonly timeoutMs: number;
  private readonly now: () => Date;

  /** scanId:hash -> in-flight/ resolved verification, so concurrent callers share one network call. */
  private readonly cache = new Map<string, Promise<VerifyResult>>();
  /** One tail promise per provider so calls to the same provider never run concurrently. */
  private readonly providerTail = new Map<string, Promise<void>>();

  constructor(deps: SecretVerifierDeps) {
    this.fetchFn = deps.fetch ?? fetch;
    this.audit = deps.audit;
    this.timeoutMs = deps.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.now = deps.now ?? (() => new Date());
  }

  forget(scanId: string): void {
    const prefix = `${scanId}:`;
    for (const key of this.cache.keys()) {
      if (key.startsWith(prefix)) this.cache.delete(key);
    }
  }

  verify(scanId: string, secret: VerifiableSecret, signal: AbortSignal): Promise<VerifyResult> {
    const cacheKey = `${scanId}:${secret.hash}`;
    const existing = this.cache.get(cacheKey);
    if (existing) return existing;

    const promise = this.dispatch(scanId, secret, signal).catch((err: unknown) => {
      // Don't let a failed (e.g. aborted) attempt poison the cache for a later, unrelated call.
      this.cache.delete(cacheKey);
      throw err;
    });
    this.cache.set(cacheKey, promise);
    return promise;
  }

  private dispatch(scanId: string, secret: VerifiableSecret, signal: AbortSignal): Promise<VerifyResult> {
    switch (secret.type) {
      case 'github-token':
        return this.callProvider(scanId, secret, signal, {
          provider: 'github',
          url: 'https://api.github.com/user',
          method: 'GET',
          headers: {
            authorization: `Bearer ${secret.value}`,
            'user-agent': 'vibesec-scan',
            accept: 'application/vnd.github+json',
          },
          interpret: interpretDefault,
        });

      case 'stripe-secret-key':
      case 'stripe-restricted-key':
      case 'stripe-test-key':
        return this.callProvider(scanId, secret, signal, {
          provider: 'stripe',
          url: 'https://api.stripe.com/v1/balance',
          method: 'GET',
          headers: { authorization: `Bearer ${secret.value}` },
          interpret: interpretStripe,
        });

      case 'slack-token':
        return this.callProvider(scanId, secret, signal, {
          provider: 'slack',
          url: 'https://slack.com/api/auth.test',
          method: 'POST',
          headers: { authorization: `Bearer ${secret.value}` },
          interpret: interpretSlack,
        });

      case 'openai-api-key':
        return this.callProvider(scanId, secret, signal, {
          provider: 'openai',
          url: 'https://api.openai.com/v1/models',
          method: 'GET',
          headers: { authorization: `Bearer ${secret.value}` },
          interpret: interpretDefault,
        });

      case 'anthropic-api-key':
        return this.callProvider(scanId, secret, signal, {
          provider: 'anthropic',
          url: 'https://api.anthropic.com/v1/models',
          method: 'GET',
          headers: { 'x-api-key': secret.value, 'anthropic-version': '2023-06-01' },
          interpret: interpretDefault,
        });

      case 'sendgrid-api-key':
        return this.callProvider(scanId, secret, signal, {
          provider: 'sendgrid',
          url: 'https://api.sendgrid.com/v3/scopes',
          method: 'GET',
          headers: { authorization: `Bearer ${secret.value}` },
          interpret: interpretDefault,
        });

      case 'aws-access-key':
        if (!secret.pairedSecret) return Promise.resolve({ liveness: 'unknown' });
        // I3a: a temporary (ASIA) key with no session token will always get InvalidClientTokenId from
        // STS regardless of whether it's actually live — that tells us nothing, so don't even call it.
        if (isTemporaryAwsAccessKey(secret.value) && !secret.sessionToken) return Promise.resolve({ liveness: 'unknown' });
        return this.callAws(scanId, secret, signal);

      default:
        return Promise.resolve({ liveness: 'unknown' });
    }
  }

  private callAws(scanId: string, secret: VerifiableSecret, signal: AbortSignal): Promise<VerifyResult> {
    const body = 'Action=GetCallerIdentity&Version=2011-06-15';
    const url = 'https://sts.amazonaws.com/';
    const headers = signV4({
      method: 'POST',
      url,
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
      body,
      region: 'us-east-1',
      service: 'sts',
      accessKeyId: secret.value,
      // Non-null: callers only reach this branch when pairedSecret is present (checked in dispatch).
      secretAccessKey: secret.pairedSecret as string,
      ...(secret.sessionToken !== undefined ? { sessionToken: secret.sessionToken } : {}),
      now: this.now(),
    });
    const isPermanentKey = !isTemporaryAwsAccessKey(secret.value);
    return this.callProvider(scanId, secret, signal, { provider: 'aws', url, method: 'POST', headers, body, interpret: interpretAws(isPermanentKey) });
  }

  private async callProvider(
    scanId: string,
    secret: VerifiableSecret,
    signal: AbortSignal,
    req: ProviderRequest,
  ): Promise<VerifyResult> {
    return this.runOnProvider(req.provider, async () => {
      let res: Response | null;
      try {
        res = await this.safeFetch(signal, req.url, req.method, req.headers, req.body);
      } catch (err) {
        // M3: an attempt aborted mid-flight (scan cancellation, not our own per-request timeout — see
        // safeFetch) still gets exactly one audit entry, recorded before the error propagates.
        this.appendAudit(scanId, secret, { liveness: 'unknown', provider: req.provider }, undefined, true);
        throw err;
      }
      const checkedAt = this.now().toISOString();
      const liveness = await req.interpret(res);
      const result: VerifyResult = { liveness, checkedAt, provider: req.provider };
      this.appendAudit(scanId, secret, result, res?.status);
      return result;
    });
  }

  /** Serializes calls per provider: the next call only starts once the previous one has settled. */
  private runOnProvider<T>(provider: string, fn: () => Promise<T>): Promise<T> {
    const prevTail = this.providerTail.get(provider) ?? Promise.resolve();
    const result = prevTail.then(fn, fn);
    this.providerTail.set(
      provider,
      result.then(
        () => undefined,
        () => undefined,
      ),
    );
    return result;
  }

  private async safeFetch(
    signal: AbortSignal,
    url: string,
    method: string,
    headers: Record<string, string>,
    body: string | undefined,
  ): Promise<Response | null> {
    if (signal.aborted) throw abortReason(signal, new DOMException('Aborted', 'AbortError'));
    const combined = AbortSignal.any([signal, AbortSignal.timeout(this.timeoutMs)]);
    try {
      // M3: never follow a redirect — a 3xx response resolves to `unknown` rather than letting a
      // provider redirect this request to a host outside the fixed set we intend to call.
      return await this.fetchFn(url, { method, headers, body, signal: combined, redirect: 'manual' });
    } catch (err) {
      // Cancellation of the whole scan must propagate; our own per-request timeout must not.
      if (signal.aborted) throw abortReason(signal, err);
      return null;
    }
  }

  private appendAudit(
    scanId: string,
    secret: VerifiableSecret,
    result: VerifyResult,
    httpStatus?: number,
    aborted = false,
  ): void {
    const details: Record<string, unknown> = {
      provider: result.provider,
      secretType: secret.type,
      redacted: secret.redacted,
      hashPrefix: secret.hash.slice(0, 12),
      result: result.liveness,
    };
    if (httpStatus !== undefined) details.httpStatus = httpStatus;
    if (aborted) details.aborted = true;
    try {
      this.audit.append({
        action: 'secret.verification_attempted',
        targetType: 'secret',
        targetId: secret.hash,
        scanId,
        details,
      });
    } catch (err) {
      // M3: an audit-log failure must never fail (or mask the result of) verification itself. Best-
      // effort console logging, matching the fallback already used for channel-less failures
      // elsewhere (see JobRunner's logInternal) — scrubbed since err may echo request details.
      const detail = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
      console.error(scrubSecrets(`[SecretVerifier] audit.append failed (scanId=${scanId}, provider=${String(result.provider)}): ${detail}`));
    }
  }
}
