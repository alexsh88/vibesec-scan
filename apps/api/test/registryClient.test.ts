import { describe, expect, it, vi } from 'vitest';
import { RegistryClient } from '../src/analyzers/dependencies/registry';

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

function client(responses: Response[]) {
  const fetchMock = vi.fn(async () => responses.shift() ?? json(500, {}));
  const sleeps: number[] = [];
  const rc = new RegistryClient({ fetch: fetchMock as unknown as typeof fetch, retryDeps: { sleep: async (ms) => { sleeps.push(ms); } } });
  return { rc, fetchMock, sleeps };
}

const npmDoc = (versions: Record<string, { dependencies?: Record<string, string> }>) => ({ versions });

describe('RegistryClient.versions (npm)', () => {
  it('fetches abbreviated metadata and returns the version list', async () => {
    const { rc, fetchMock } = client([json(200, npmDoc({ '1.0.0': {}, '1.2.0': { dependencies: { foo: '^2.0.0' } } }))]);
    await expect(rc.versions('npm', 'lodash', new AbortController().signal)).resolves.toEqual(['1.0.0', '1.2.0']);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://registry.npmjs.org/lodash');
    expect(new Headers(init.headers).get('accept')).toBe('application/vnd.npm.install-v1+json');
  });

  it('percent-encodes the slash in a scoped package name', async () => {
    const { rc, fetchMock } = client([json(200, npmDoc({ '1.0.0': {} }))]);
    await rc.versions('npm', '@scope/pkg', new AbortController().signal);
    expect((fetchMock.mock.calls[0] as unknown as [string])[0]).toBe('https://registry.npmjs.org/@scope%2fpkg');
  });

  it('rejects an invalid npm name without ever calling fetch', async () => {
    const { rc, fetchMock } = client([]);
    await expect(rc.versions('npm', '../etc/passwd', new AbortController().signal)).rejects.toMatchObject({ code: 'VALIDATION' });
    await expect(rc.versions('npm', '.hidden', new AbortController().signal)).rejects.toMatchObject({ code: 'VALIDATION' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('caches the parsed document: a second call for the same package makes no network request', async () => {
    const { rc, fetchMock } = client([json(200, npmDoc({ '1.0.0': {} }))]);
    await rc.versions('npm', 'lodash', new AbortController().signal);
    await rc.versions('npm', 'lodash', new AbortController().signal);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('retries a 5xx response and then succeeds', async () => {
    const { rc, fetchMock } = client([json(502, {}), json(200, npmDoc({ '1.0.0': {} }))]);
    await expect(rc.versions('npm', 'lodash', new AbortController().signal)).resolves.toEqual(['1.0.0']);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('retries a 429 honoring Retry-After', async () => {
    const { rc, sleeps } = client([json(429, {}, { 'retry-after': '3' }), json(200, npmDoc({ '1.0.0': {} }))]);
    await expect(rc.versions('npm', 'lodash', new AbortController().signal)).resolves.toEqual(['1.0.0']);
    expect(sleeps).toEqual([3_000]);
  });
});

describe('RegistryClient.dependencyRange (npm)', () => {
  it('returns the declared range for a version that depends on `child`', async () => {
    const { rc } = client([json(200, npmDoc({ '1.2.0': { dependencies: { foo: '^2.0.0' } } }))]);
    await expect(rc.dependencyRange('npm', 'lodash', '1.2.0', 'foo', new AbortController().signal)).resolves.toBe('^2.0.0');
  });

  it('returns null when the version has no such dependency', async () => {
    const { rc } = client([json(200, npmDoc({ '1.2.0': { dependencies: { foo: '^2.0.0' } } }))]);
    await expect(rc.dependencyRange('npm', 'lodash', '1.2.0', 'bar', new AbortController().signal)).resolves.toBeNull();
  });
});

const pypiProject = (releases: Record<string, unknown[]>) => ({ releases });
const pypiVersion = (requiresDist: string[] | null) => ({ info: { requires_dist: requiresDist } });

describe('RegistryClient.versions (PyPI)', () => {
  it('fetches the project JSON and returns the release list', async () => {
    const { rc, fetchMock } = client([json(200, pypiProject({ '1.0.0': [], '1.1.0': [] }))]);
    await expect(rc.versions('PyPI', 'requests', new AbortController().signal)).resolves.toEqual(['1.0.0', '1.1.0']);
    expect((fetchMock.mock.calls[0] as unknown as [string])[0]).toBe('https://pypi.org/pypi/requests/json');
  });

  it('rejects an invalid PyPI name without ever calling fetch', async () => {
    const { rc, fetchMock } = client([]);
    await expect(rc.versions('PyPI', 'not a name', new AbortController().signal)).rejects.toMatchObject({ code: 'VALIDATION' });
    await expect(rc.versions('PyPI', 'bad/name', new AbortController().signal)).rejects.toMatchObject({ code: 'VALIDATION' });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('RegistryClient.dependencyRange (PyPI)', () => {
  it('parses requires_dist and matches by normalized name', async () => {
    const { rc, fetchMock } = client([json(200, pypiVersion(['Foo-Bar (>=1.0,<2.0)', 'baz>=2.0', "qux ; extra == 'dev'"]))]);
    await expect(rc.dependencyRange('PyPI', 'django', '4.0.0', 'foo_bar', new AbortController().signal)).resolves.toBe('>=1.0,<2.0');
    expect((fetchMock.mock.calls[0] as unknown as [string])[0]).toBe('https://pypi.org/pypi/django/4.0.0/json');
  });

  it('matches a dependency with no parentheses around the specifier', async () => {
    const { rc } = client([json(200, pypiVersion(['baz>=2.0']))]);
    await expect(rc.dependencyRange('PyPI', 'django', '4.0.0', 'baz', new AbortController().signal)).resolves.toBe('>=2.0');
  });

  it('returns null for a dependency that is not declared', async () => {
    const { rc } = client([json(200, pypiVersion(['baz>=2.0']))]);
    await expect(rc.dependencyRange('PyPI', 'django', '4.0.0', 'nope', new AbortController().signal)).resolves.toBeNull();
  });

  it('returns null (not an error) when the per-version doc 404s', async () => {
    const { rc } = client([json(404, {})]);
    await expect(rc.dependencyRange('PyPI', 'django', '0.0.1', 'baz', new AbortController().signal)).resolves.toBeNull();
  });

  it('treats a null requires_dist as no dependencies', async () => {
    const { rc } = client([json(200, pypiVersion(null))]);
    await expect(rc.dependencyRange('PyPI', 'django', '4.0.0', 'baz', new AbortController().signal)).resolves.toBeNull();
  });
});

describe('RegistryClient — bounded memory (projections, byte cap, TTL, capacity)', () => {
  const sig = () => new AbortController().signal;

  it('accepts legacy uppercase npm names but still refuses path injection', async () => {
    const { rc, fetchMock } = client([json(200, npmDoc({ '1.0.0': {} })), json(200, npmDoc({ '1.0.0': {} }))]);
    await expect(rc.versions('npm', 'JSONStream', sig())).resolves.toEqual(['1.0.0']);
    expect((fetchMock.mock.calls[0] as unknown as [string])[0]).toBe('https://registry.npmjs.org/JSONStream');
    await expect(rc.versions('npm', '@Scope/Pkg', sig())).resolves.toEqual(['1.0.0']);
    for (const bad of ['../x', 'a/b', '@s/../x', '@s/a/b', 'x?y', 'x#y', 'x%2f', ' x', '.x', '_x', '@/x']) {
      await expect(rc.versions('npm', bad, sig()), bad).rejects.toMatchObject({ code: 'VALIDATION' });
    }
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('refuses a response body over the byte cap (streamed, not buffered whole)', async () => {
    let pulled = 0;
    const big = new ReadableStream<Uint8Array>({
      pull(ctrl) {
        pulled++;
        if (pulled > 1000) { ctrl.close(); return; }
        ctrl.enqueue(new Uint8Array(1024).fill(0x20));
      },
    });
    const fetchMock = vi.fn(async () => new Response(big, { status: 200 }));
    const rc = new RegistryClient({ fetch: fetchMock as unknown as typeof fetch, maxResponseBytes: 8 * 1024, retryDeps: { sleep: async () => {} } });
    await expect(rc.versions('npm', 'huge', sig())).rejects.toMatchObject({ message: expect.stringMatching(/exceeds/) });
    expect(pulled).toBeLessThan(50);
  });

  it('refuses up front when content-length announces more than the cap', async () => {
    const fetchMock = vi.fn(async () => new Response('{}', { status: 200, headers: { 'content-length': String(100 * 1024 * 1024) } }));
    const rc = new RegistryClient({ fetch: fetchMock as unknown as typeof fetch, retryDeps: { sleep: async () => {} } });
    await expect(rc.versions('npm', 'huge', sig())).rejects.toMatchObject({ message: expect.stringMatching(/exceeds/) });
  });

  it('one fetch serves both versions() and dependencyRange() (the cache keeps projections, not the document)', async () => {
    const { rc, fetchMock } = client([json(200, npmDoc({ '1.0.0': { dependencies: { qs: '^6.0.0' } }, '1.1.0': {} }))]);
    expect(await rc.versions('npm', 'express', sig())).toEqual(['1.0.0', '1.1.0']);
    expect(await rc.dependencyRange('npm', 'express', '1.0.0', 'qs', sig())).toBe('^6.0.0');
    expect(await rc.dependencyRange('npm', 'express', '1.1.0', 'qs', sig())).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('entries expire after 1 h', async () => {
    let now = new Date('2026-01-01T00:00:00Z');
    const responses = [json(200, npmDoc({ '1.0.0': {} })), json(200, npmDoc({ '1.0.0': {}, '2.0.0': {} }))];
    const fetchMock = vi.fn(async () => responses.shift() ?? json(500, {}));
    const rc = new RegistryClient({ fetch: fetchMock as unknown as typeof fetch, now: () => now });
    expect(await rc.versions('npm', 'x', sig())).toEqual(['1.0.0']);
    now = new Date(now.getTime() + 59 * 60_000);
    expect(await rc.versions('npm', 'x', sig())).toEqual(['1.0.0']);
    now = new Date(now.getTime() + 2 * 60_000);
    expect(await rc.versions('npm', 'x', sig())).toEqual(['1.0.0', '2.0.0']);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('is capacity-bounded (LRU)', async () => {
    const fetchMock = vi.fn(async () => json(200, npmDoc({ '1.0.0': {} })));
    const rc = new RegistryClient({ fetch: fetchMock as unknown as typeof fetch, cacheCapacity: 2 });
    for (const n of ['a', 'b', 'c', 'a']) await rc.versions('npm', n, sig());
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });
});
