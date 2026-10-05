import { describe, expect, it, vi } from 'vitest';
import { GitHubClient } from '../src/github/GitHubClient';

const repoJson = (over: Record<string, unknown> = {}) => ({
  private: false, default_branch: 'main', size: 2048, html_url: 'https://github.com/acme/app', archived: false, ...over,
});
const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

function client(responses: Response[], serverToken?: string) {
  const fetchMock = vi.fn(async () => responses.shift() ?? json(500, {}));
  const sleeps: number[] = [];
  const gh = new GitHubClient({
    apiUrl: 'https://api.github.test', serverToken, fetch: fetchMock as unknown as typeof fetch,
    retryDeps: { sleep: async (ms) => { sleeps.push(ms); } },
  });
  return { gh, fetchMock, sleeps };
}

describe('GitHubClient.getRepo', () => {
  it('maps public repo metadata', async () => {
    const { gh, fetchMock } = client([json(200, repoJson())]);
    await expect(gh.getRepo('acme', 'app', undefined)).resolves.toEqual({
      isPrivate: false, defaultBranch: 'main', sizeBytes: 2048 * 1024, htmlUrl: 'https://github.com/acme/app', archived: false,
    });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://api.github.test/repos/acme/app');
    expect(new Headers(init.headers).get('authorization')).toBeNull();
  });

  it('sends the user token as a bearer token and accepts private repos', async () => {
    const { gh, fetchMock } = client([json(200, repoJson({ private: true }))], 'ghp_server');
    await expect(gh.getRepo('acme', 'app', 'ghp_user')).resolves.toMatchObject({ isPrivate: true });
    const init = (fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect(new Headers(init.headers).get('authorization')).toBe('Bearer ghp_user');
  });

  it('never lets the server token authorize a private repo', async () => {
    const { gh } = client([json(200, repoJson({ private: true }))], 'ghp_server');
    await expect(gh.getRepo('acme', 'app', undefined)).rejects.toMatchObject({ code: 'AUTH_REQUIRED' });
  });

  it('falls back to anonymous when the server token is rejected', async () => {
    const { gh, fetchMock } = client([json(401, {}), json(200, repoJson())], 'ghp_server');
    await expect(gh.getRepo('acme', 'app', undefined)).resolves.toMatchObject({ isPrivate: false });
    const second = (fetchMock.mock.calls[1] as unknown as [string, RequestInit])[1];
    expect(new Headers(second.headers).get('authorization')).toBeNull();
  });

  it.each([
    [401, 'ghp_user', 'AUTH_INVALID'],
    [403, 'ghp_user', 'AUTH_INVALID'],
    [404, 'ghp_user', 'REPO_NOT_FOUND'],
    [404, undefined, 'AUTH_REQUIRED'],
  ])('maps %s (token: %s) to %s', async (status, token, code) => {
    const { gh } = client([json(status, { message: 'x' })]);
    await expect(gh.getRepo('acme', 'app', token)).rejects.toMatchObject({ code });
  });

  it('retries rate limits honoring retry-after', async () => {
    const { gh, sleeps } = client([json(403, {}, { 'x-ratelimit-remaining': '0', 'retry-after': '2' }), json(200, repoJson())]);
    await expect(gh.getRepo('acme', 'app', undefined)).resolves.toBeDefined();
    expect(sleeps).toEqual([2_000]);
  });

  it('fails fast when the rate-limit reset is too far away', async () => {
    const reset = String(Math.floor(Date.now() / 1000) + 3_600);
    const { gh } = client([json(403, {}, { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': reset })]);
    await expect(gh.getRepo('acme', 'app', undefined)).rejects.toMatchObject({ code: 'GITHUB_RATE_LIMITED' });
  });

  it('retries 5xx and succeeds', async () => {
    const { gh, fetchMock } = client([json(502, {}), json(503, {}), json(200, repoJson())]);
    await expect(gh.getRepo('acme', 'app', undefined)).resolves.toBeDefined();
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('url-encodes owner and name', async () => {
    const { gh, fetchMock } = client([json(200, repoJson())]);
    await gh.getRepo('acme', 'my.app', undefined);
    expect((fetchMock.mock.calls[0] as unknown as [string])[0]).toBe('https://api.github.test/repos/acme/my.app');
  });

  it('cancels when the signal is aborted', async () => {
    const ac = new AbortController();
    ac.abort();
    const { gh } = client([json(200, repoJson())]);
    await expect(gh.getRepo('acme', 'app', undefined, ac.signal)).rejects.toMatchObject({ code: 'CANCELLED' });
  });
});
