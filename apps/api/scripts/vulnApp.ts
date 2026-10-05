// In-process harness for scanning fixtures/vuln-app with the REAL pipeline and container wiring
// (createContainer: every analyzer, mock responder, budget lane and cache), shared by the e2e test
// (test/codeAnalyzersPipeline.test.ts) and the eval script (scripts/evalVulnApp.ts).
//
// The fixture is committed into a throwaway local git repo (expected.json — the ground truth — is left
// out, it is not part of the app) and "cloned" through GitService's file-protocol support; GitHub repo
// metadata is faked. OSV + npm/PyPI registries: `vulnAppFakeFetch` serves fixture advisories offline
// (mock mode); live mode passes no fetch override, so the real services are queried.

import { randomUUID } from 'node:crypto';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { FastifyInstance } from 'fastify';
import type { Finding, ScanOptions } from '@vibesec/shared';
import { loadConfig } from '../src/config';
import { createContainer, type Container, type ContainerOverrides } from '../src/container';
import type { GitHubClient, RepoMeta } from '../src/github/GitHubClient';
import { buildApp } from '../src/http/app';
import { createFixtureRepo, type FixtureCommit, type FixtureRepo } from '../test/fixtures/gitRepo';

// apps/api/scripts -> apps/api -> apps -> <repo root>
export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
export const VULN_APP_ROOT = resolve(REPO_ROOT, 'fixtures', 'vuln-app');
const GROUND_TRUTH = 'expected.json';

/** Every fixture file (repo-relative, forward slashes) except the ground truth. */
export async function readVulnAppFiles(root = VULN_APP_ROOT): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  const walk = async (dir: string): Promise<void> => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const abs = join(dir, entry.name);
      if (entry.isDirectory()) await walk(abs);
      else {
        const rel = relative(root, abs).split('\\').join('/');
        if (rel !== GROUND_TRUTH) out[rel] = await readFile(abs, 'utf8');
      }
    }
  };
  await walk(root);
  return out;
}

// --- offline OSV / registry fixtures (mock mode) ----------------------------------------------

const CVSS = {
  critical: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  high: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
  medium: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
};

function osvRecord(id: string, eco: 'npm' | 'PyPI', name: string, fixed: string, vector: string, summary: string, cwe: string) {
  return {
    id, summary, details: `${summary}. (fixture advisory)`, aliases: [], modified: '2024-01-01T00:00:00Z', published: '2023-01-01T00:00:00Z',
    severity: [{ type: 'CVSS_V3', score: vector }],
    affected: [{ package: { ecosystem: eco, name }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed }] }] }],
    references: [{ type: 'ADVISORY', url: `https://github.com/advisories/${id}` }],
    database_specific: { cwe_ids: [cwe] },
  };
}

const ADVISORIES = [
  osvRecord('GHSA-fx01-lodash', 'npm', 'lodash', '4.17.21', CVSS.critical, 'Prototype pollution in lodash', 'CWE-1321'),
  osvRecord('GHSA-fx02-jsonwebtoken', 'npm', 'jsonwebtoken', '9.0.0', CVSS.high, 'jsonwebtoken insecure key handling', 'CWE-327'),
  osvRecord('GHSA-fx03-axios', 'npm', 'axios', '0.21.2', CVSS.high, 'axios ReDoS in trim', 'CWE-1333'),
  osvRecord('GHSA-fx04-pyyaml', 'PyPI', 'PyYAML', '5.4', CVSS.critical, 'Arbitrary code execution in PyYAML full_load', 'CWE-502'),
  osvRecord('GHSA-fx05-requests', 'PyPI', 'requests', '2.20.0', CVSS.medium, 'requests leaks Authorization header on redirect', 'CWE-200'),
];
const ADVISORY_BY_ID = new Map(ADVISORIES.map((a) => [a.id, a]));
const ADVISORY_IDS: Record<string, string[]> = {
  'npm:lodash@4.17.15': ['GHSA-fx01-lodash'],
  'npm:jsonwebtoken@8.5.1': ['GHSA-fx02-jsonwebtoken'],
  'npm:axios@0.21.1': ['GHSA-fx03-axios'],
  'PyPI:pyyaml@5.3': ['GHSA-fx04-pyyaml'],
  'PyPI:requests@2.19.0': ['GHSA-fx05-requests'],
};
const NPM_VERSIONS: Record<string, string[]> = {
  lodash: ['4.17.15', '4.17.21'], jsonwebtoken: ['8.5.1', '9.0.0', '9.0.2'], axios: ['0.21.1', '0.21.2', '1.7.0'],
};
const PYPI_RELEASES: Record<string, string[]> = { pyyaml: ['5.3', '5.4', '6.0'], requests: ['2.19.0', '2.20.0', '2.32.0'] };

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

/** Offline stand-in for OSV and the npm/PyPI registries (fixture data); anything else → 404. */
export const vulnAppFakeFetch: typeof fetch = async (input, init) => {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
  if (url === 'https://api.osv.dev/v1/querybatch' && init?.method === 'POST') {
    const body = JSON.parse(String(init.body)) as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> };
    return json({
      results: body.queries.map((q) => {
        const ids = ADVISORY_IDS[`${q.package.ecosystem}:${q.package.name.toLowerCase()}@${q.version}`] ?? [];
        return ids.length > 0 ? { vulns: ids.map((id) => ({ id, modified: '2024-01-01T00:00:00Z' })) } : {};
      }),
    });
  }
  const vuln = /^https:\/\/api\.osv\.dev\/v1\/vulns\/(.+)$/.exec(url);
  if (vuln) {
    const rec = ADVISORY_BY_ID.get(decodeURIComponent(vuln[1]!));
    return rec ? json(rec) : json({}, 404);
  }
  const npm = /^https:\/\/registry\.npmjs\.org\/(.+)$/.exec(url);
  if (npm) {
    const versions = NPM_VERSIONS[decodeURIComponent(npm[1]!)];
    return versions ? json({ name: npm[1], versions: Object.fromEntries(versions.map((v) => [v, {}])) }) : json({}, 404);
  }
  const pypi = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/json$/.exec(url);
  if (pypi) {
    const rel = PYPI_RELEASES[decodeURIComponent(pypi[1]!).toLowerCase()];
    return rel ? json({ releases: Object.fromEntries(rel.map((v) => [v, []])) }) : json({}, 404);
  }
  return new Response('', { status: 404 });
};

// --- harness ------------------------------------------------------------------------------------

export type VulnAppHarness = {
  container: Container;
  app: FastifyInstance;
  repo: FixtureRepo;
  /** Starts a scan of the fixture (default branch, or `ref`) over HTTP and waits until the runner is idle. */
  scan(options?: Partial<ScanOptions>, ref?: string): Promise<{ scanId: string; durationMs: number }>;
  close(): Promise<void>;
};

export type VulnAppHarnessOptions = {
  /** Environment for loadConfig (defaults to an empty env → mock mode). DB/work dir/sandbox are forced. */
  env?: Record<string, string | undefined>;
  /** OSV/registry fetch; omit for the real network (live mode). */
  fetch?: typeof fetch;
  wrapTransport?: ContainerOverrides['wrapTransport'];
  /** The fixture repo's history, built from the vuln-app files (default: one commit with all of them). */
  commits?: (files: Record<string, string>) => FixtureCommit[];
};

export async function startVulnAppHarness(opts: VulnAppHarnessOptions = {}): Promise<VulnAppHarness> {
  const files = await readVulnAppFiles();
  const repo = await createFixtureRepo(opts.commits ? opts.commits(files) : [{ files }]);
  const workDir = await mkdtemp(join(tmpdir(), 'vibesec-vuln-app-'));
  const config = loadConfig({
    ...(opts.env ?? {}),
    DB_PATH: ':memory:', ALLOW_LOCAL_REPOS: 'true', SANDBOX_ENABLED: 'false', WORK_DIR: workDir,
  });
  const github = {
    getRepo: async (): Promise<RepoMeta> => ({ isPrivate: false, defaultBranch: 'main', sizeBytes: 50_000, htmlUrl: '', archived: false }),
  } as unknown as GitHubClient;
  const container = createContainer(config, {
    sandbox: null, github, remoteUrlFor: () => repo.url,
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
    ...(opts.wrapTransport ? { wrapTransport: opts.wrapTransport } : {}),
  });
  container.gitVersion = await container.git.init();
  const app = await buildApp(container, { logger: false });

  return {
    container, app, repo,
    async scan(options = {}, ref) {
      const started = Date.now();
      const res = await app.inject({
        method: 'POST', url: '/api/scans', headers: { 'idempotency-key': randomUUID() },
        payload: { repoUrl: 'https://github.com/acme/vuln-app', options, ...(ref ? { ref } : {}) },
      });
      if (res.statusCode !== 202) throw new Error(`scan was not accepted (${res.statusCode}): ${res.body}`);
      const scanId = (res.json() as { scanId: string }).scanId;
      await container.runner.whenIdle();
      return { scanId, durationMs: Date.now() - started };
    },
    async close() {
      await container.runner.shutdown(0);
      await app.close();
      container.db.close();
      await repo.cleanup();
      await rm(workDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    },
  };
}

/** Every persisted finding of a scan, with the analyzer that produced it. */
export function findingsOf(container: Container, scanId: string): Array<Finding & { analyzer: string }> {
  const rows = container.db.prepare('SELECT analyzer, data_json FROM findings WHERE scan_id = ? ORDER BY file, start_line').all(scanId) as Array<{ analyzer: string; data_json: string }>;
  return rows.map((r) => ({ ...(JSON.parse(r.data_json) as Finding), analyzer: r.analyzer }));
}
