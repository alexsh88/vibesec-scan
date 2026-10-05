import { AppError, toAppError } from '../errors/AppError';
import { CircuitBreaker } from '../resilience/circuitBreaker';
import { RETRY_POLICIES, withRetry, type RetryDeps } from '../resilience/retry';

export type RepoMeta = { isPrivate: boolean; defaultBranch: string; sizeBytes: number; htmlUrl: string; archived: boolean };

export type GitHubClientOptions = {
  apiUrl: string;
  /** Optional operator token: raises API rate limits for PUBLIC repos only. */
  serverToken?: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
  retryDeps?: RetryDeps;
  breaker?: CircuitBreaker;
};

type RepoResponse = { private: boolean; default_branch: string; size: number; html_url: string; archived: boolean };

export class GitHubClient {
  private readonly fetchImpl: typeof fetch;
  private readonly breaker: CircuitBreaker;

  constructor(private readonly opts: GitHubClientOptions) {
    this.fetchImpl = opts.fetch ?? fetch;
    this.breaker = opts.breaker ?? new CircuitBreaker('GitHub API', { failureThreshold: 5, resetMs: 30_000, unavailableCode: 'INTERNAL' });
  }

  async getRepo(owner: string, name: string, userToken: string | undefined, signal?: AbortSignal): Promise<RepoMeta> {
    if (signal?.aborted) throw new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');
    const url = `${this.opts.apiUrl}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`;

    let token = userToken ?? this.opts.serverToken;
    const call = () => this.breaker.run(() => withRetry(() => this.request(url, token, signal), RETRY_POLICIES.github, signal, this.opts.retryDeps));

    let body: RepoResponse;
    try {
      body = await call();
    } catch (err) {
      // A broken operator token must not break public scans: retry anonymously.
      if (!userToken && token && err instanceof AppError && err.code === 'AUTH_INVALID') {
        token = undefined;
        body = await call();
      } else {
        throw err;
      }
    }

    if (body.private && !userToken) {
      throw new AppError('AUTH_REQUIRED', 'permanent', 'This repository is private. Provide a token with Contents: read access.');
    }
    return {
      isPrivate: body.private, defaultBranch: body.default_branch, sizeBytes: body.size * 1024,
      htmlUrl: body.html_url, archived: body.archived,
    };
  }

  private async request(url: string, token: string | undefined, signal?: AbortSignal): Promise<RepoResponse> {
    const timeout = AbortSignal.timeout(this.opts.timeoutMs ?? 10_000);
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        headers: {
          accept: 'application/vnd.github+json',
          'x-github-api-version': '2022-11-28',
          'user-agent': 'vibesec-scan',
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
      });
    } catch (err) {
      if (signal?.aborted) throw new AppError('CANCELLED', 'cancelled', 'Operation was cancelled', { cause: err });
      const e = toAppError(err);
      throw e.kind === 'permanent' ? new AppError('INTERNAL', 'transient', 'Network error while talking to GitHub', { cause: err }) : e;
    }

    if (res.ok) return (await res.json()) as RepoResponse;

    const rateLimited = (res.status === 403 || res.status === 429)
      && (res.headers.get('x-ratelimit-remaining') === '0' || res.headers.has('retry-after'));
    if (rateLimited) {
      throw new AppError('GITHUB_RATE_LIMITED', 'transient', 'GitHub API rate limit reached; try again later', {
        retryAfterMs: retryAfterMs(res.headers),
      });
    }
    const hasToken = Boolean(token);
    switch (res.status) {
      case 401:
        throw new AppError('AUTH_INVALID', 'permanent', 'GitHub rejected the token');
      case 403:
        throw hasToken
          ? new AppError('AUTH_INVALID', 'permanent', 'The token lacks access to this repository (or the organization requires SSO authorization for it)')
          : new AppError('AUTH_REQUIRED', 'permanent', 'GitHub denied access. Provide a token with Contents: read access.');
      case 404:
        throw hasToken
          ? new AppError('REPO_NOT_FOUND', 'permanent', 'Repository not found, or the token cannot access it')
          : new AppError('AUTH_REQUIRED', 'permanent', 'Repository not found. If it is private, provide a token with Contents: read access.');
      default:
        if (res.status >= 500) throw new AppError('INTERNAL', 'transient', 'GitHub is temporarily unavailable');
        throw new AppError('INTERNAL', 'permanent', `Unexpected GitHub API response (${res.status})`);
    }
  }
}

function retryAfterMs(headers: Headers): number {
  const retryAfter = Number(headers.get('retry-after'));
  if (Number.isFinite(retryAfter) && retryAfter > 0) return retryAfter * 1000;
  const reset = Number(headers.get('x-ratelimit-reset'));
  if (Number.isFinite(reset) && reset > 0) return Math.max(reset * 1000 - Date.now(), 1_000);
  return 60_000;
}
