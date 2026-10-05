import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import type { Finding, Severity } from '@vibesec/shared';
import { loadConfig } from '../src/config';
import { createContainer, type Container } from '../src/container';
import { purlFor } from '../src/export/cyclonedx';
import { buildApp } from '../src/http/app';
import { createStubPipeline } from '../src/pipeline/stubPipeline';

let app: FastifyInstance;
let c: Container;

async function start() {
  const config = loadConfig({ DB_PATH: ':memory:' });
  c = createContainer(config, { pipeline: createStubPipeline(1) });
  app = await buildApp(c, { logger: false });
  return app;
}

afterEach(async () => {
  await c.runner.shutdown(0);
  await app.close();
  c.db.close();
});

async function scanReady(repoUrl = 'https://github.com/acme/app') {
  const { scanId } = (await app.inject({ method: 'POST', url: '/api/scans', payload: { repoUrl } })).json();
  await c.runner.whenIdle();
  // The stub pipeline only records commitSha on the in-memory checkpoint, not the `scans` row (only
  // the real pipeline does that, via scans.setCommitSha) — set it explicitly for exports that need one.
  c.scans.setCommitSha(scanId, '0'.repeat(40));
  return scanId as string;
}

let n = 0;
const secretFinding = (scanId: string, over: Partial<Finding> = {}): Finding => ({
  id: `sec-${++n}`, scanId, fingerprint: `sec-fp-${n}`, category: 'secret', ruleId: 'secret/github-pat', title: 'Hardcoded GitHub token',
  baseSeverity: 'critical', riskScore: 95, severity: 'critical', riskFactors: [], confidence: 'high',
  location: { file: 'src/config.ts', startLine: 5, endLine: 5, snippet: 'const TOKEN = "ghp_****REDACTED****"', permalink: 'https://github.com/acme/app/blob/sha/src/config.ts#L5' },
  secret: { type: 'github_pat', redacted: 'ghp_****REDACTED****', liveness: 'unknown', inHistoryOnly: false },
  explanation: 'A GitHub personal access token is hardcoded in source.', impact: 'Full account compromise.',
  remediation: { summary: 'Rotate the token and move it to a secret manager.' }, scanStatus: 'new', ...over,
});

const sastFinding = (scanId: string, over: Partial<Finding> = {}): Finding => ({
  id: `sast-${++n}`, scanId, fingerprint: `sast-fp-${n}`, category: 'taint', ruleId: 'taint/sql-injection', title: 'SQL injection',
  baseSeverity: 'high', riskScore: 70, severity: 'high', riskFactors: [], confidence: 'high', cwe: 'CWE-89',
  location: { file: 'src/db.ts', startLine: 20, endLine: 20, snippet: 'db.query(sql)', permalink: 'https://github.com/acme/app/blob/sha/src/db.ts#L20' },
  taintTrace: [
    { kind: 'source', file: 'src/http.ts', line: 3, code: 'const q = req.query.q', note: 'user-controlled input' },
    { kind: 'sink', file: 'src/db.ts', line: 20, code: 'db.query(sql)', note: 'executed as a SQL query' },
  ],
  explanation: 'User input reaches a SQL sink unsanitized.', impact: 'SQL injection.',
  remediation: { summary: 'Use parameterized queries.' }, scanStatus: 'new', ...over,
});

const depFinding = (scanId: string, over: Partial<Finding> = {}): Finding => ({
  id: `dep-${++n}`, scanId, fingerprint: `dep-fp-${n}`, category: 'dependency', ruleId: 'dependency/vulnerable-package',
  title: 'lodash@4.17.20 has 1 known vulnerability (high)', baseSeverity: 'high', riskScore: 70, severity: 'high',
  riskFactors: [], confidence: 'high', cwe: 'CWE-1321',
  location: { file: 'package-lock.json', startLine: 10, endLine: 10, snippet: '"lodash": "4.17.20"', permalink: 'https://github.com/acme/app/blob/sha/package-lock.json#L10' },
  dependency: {
    ecosystem: 'npm', name: 'lodash', version: '4.17.20', scope: 'prod', direct: true, paths: [],
    advisories: [{ id: 'GHSA-1', aliases: [], summary: 'prototype pollution', severity: 'high', cvss: 7.5, fixedIn: '4.17.21', url: null }],
    reachability: 'reachable',
  },
  explanation: 'Known vulnerability.', impact: 'Prototype pollution.', remediation: { summary: 'Upgrade to 4.17.21.' }, scanStatus: 'new', ...over,
});

describe('SARIF export', () => {
  it('404s for an unknown scan', async () => {
    await start();
    expect((await app.inject({ method: 'GET', url: '/api/scans/nope/export/sarif' })).statusCode).toBe(404);
  });

  it('serves a SARIF 2.1.0 document with an attachment Content-Disposition', async () => {
    await start();
    const scanId = await scanReady();
    c.findings.replaceForAnalyzer(scanId, 'secrets', [secretFinding(scanId)]);
    const res = await app.inject({ method: 'GET', url: `/api/scans/${scanId}/export/sarif` });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('application/sarif+json');
    expect(res.headers['content-disposition']).toBe('attachment; filename="vibesec-acme-app-0000000.sarif"');
    const body = res.json();
    expect(body.version).toBe('2.1.0');
    expect(body.runs).toHaveLength(1);
    expect(body.runs[0].tool.driver.name).toBe('VibeSec');
    expect(body.runs[0].versionControlProvenance).toEqual([
      { repositoryUri: 'https://github.com/acme/app', revisionId: '0'.repeat(40) },
    ]);
  });

  it('maps severities to SARIF levels (critical/high→error, medium→warning, low/info→note)', async () => {
    await start();
    const scanId = await scanReady();
    const bySeverity = (sev: Severity) => secretFinding(scanId, { severity: sev, id: `sev-${sev}`, fingerprint: `sev-fp-${sev}` });
    c.findings.replaceForAnalyzer(scanId, 'secrets', [
      bySeverity('critical'), bySeverity('high'), bySeverity('medium'), bySeverity('low'), bySeverity('info'),
    ]);
    const res = await app.inject({ method: 'GET', url: `/api/scans/${scanId}/export/sarif` });
    const levels = Object.fromEntries(res.json().runs[0].results.map((r: { ruleId: string; level: string; partialFingerprints: Record<string, string> }) =>
      [r.partialFingerprints['vibesecFingerprint/v1'], r.level]));
    expect(levels['sev-fp-critical']).toBe('error');
    expect(levels['sev-fp-high']).toBe('error');
    expect(levels['sev-fp-medium']).toBe('warning');
    expect(levels['sev-fp-low']).toBe('note');
    expect(levels['sev-fp-info']).toBe('note');
  });

  it('builds codeFlows from taintTrace', async () => {
    await start();
    const scanId = await scanReady();
    c.findings.replaceForAnalyzer(scanId, 'taint', [sastFinding(scanId)]);
    const res = await app.inject({ method: 'GET', url: `/api/scans/${scanId}/export/sarif` });
    const [result] = res.json().runs[0].results;
    expect(result.codeFlows).toHaveLength(1);
    const locations = result.codeFlows[0].threadFlows[0].locations;
    expect(locations).toHaveLength(2);
    expect(locations[0].location.physicalLocation.artifactLocation.uri).toBe('src/http.ts');
    expect(locations[0].location.message.text).toContain('user-controlled input');
    expect(locations[1].location.physicalLocation.artifactLocation.uri).toBe('src/db.ts');
  });

  it('includes a suppressions entry for a triaged finding, and none for an open one', async () => {
    await start();
    const scanId = await scanReady();
    const triagedAt = new Date().toISOString();
    c.findings.replaceForAnalyzer(scanId, 'secrets', [
      secretFinding(scanId, { id: 'open-1', fingerprint: 'open-fp' }),
      secretFinding(scanId, { id: 'triaged-1', fingerprint: 'triaged-fp', triage: { status: 'accepted_risk', reason: 'Internal tool only', at: triagedAt } }),
    ]);
    const res = await app.inject({ method: 'GET', url: `/api/scans/${scanId}/export/sarif` });
    const results = res.json().runs[0].results as Array<{ partialFingerprints: Record<string, string>; suppressions?: unknown[] }>;
    const open = results.find((r) => r.partialFingerprints['vibesecFingerprint/v1'] === 'open-fp')!;
    const triaged = results.find((r) => r.partialFingerprints['vibesecFingerprint/v1'] === 'triaged-fp')!;
    expect(open.suppressions).toBeUndefined();
    expect(triaged.suppressions).toEqual([{ kind: 'external', status: 'accepted', justification: 'Internal tool only' }]);
  });

  it('dedupes rules by ruleId', async () => {
    await start();
    const scanId = await scanReady();
    c.findings.replaceForAnalyzer(scanId, 'taint', [
      sastFinding(scanId, { id: 't1', fingerprint: 'fp-t1', location: { file: 'a.ts', startLine: 1, endLine: 1, snippet: 's', permalink: 'p' } }),
      sastFinding(scanId, { id: 't2', fingerprint: 'fp-t2', location: { file: 'b.ts', startLine: 2, endLine: 2, snippet: 's', permalink: 'p' } }),
    ]);
    const res = await app.inject({ method: 'GET', url: `/api/scans/${scanId}/export/sarif` });
    const rules = res.json().runs[0].tool.driver.rules;
    expect(rules.filter((r: { id: string }) => r.id === 'taint/sql-injection')).toHaveLength(1);
    expect(rules[0].helpUri).toBe('https://cwe.mitre.org/data/definitions/89.html');
    expect(rules[0].properties.tags).toEqual(['taint', 'CWE-89']);
  });

  it('never leaks a raw secret value; the SARIF snippet is exactly the already-redacted one', async () => {
    await start();
    const scanId = await scanReady();
    const f = secretFinding(scanId);
    c.findings.replaceForAnalyzer(scanId, 'secrets', [f]);
    const res = await app.inject({ method: 'GET', url: `/api/scans/${scanId}/export/sarif` });
    const [result] = res.json().runs[0].results;
    const snippet = result.locations[0].physicalLocation.region.snippet.text;
    expect(snippet).toBe(f.location.snippet);
    expect(snippet).not.toMatch(/ghp_[A-Za-z0-9]{30,}/);
  });
});

describe('CycloneDX export', () => {
  it('404s for an unknown scan', async () => {
    await start();
    expect((await app.inject({ method: 'GET', url: '/api/scans/nope/export/cyclonedx' })).statusCode).toBe(404);
  });

  it('serves a CycloneDX 1.6 BOM with an attachment Content-Disposition', async () => {
    await start();
    const scanId = await scanReady();
    c.findings.replaceForAnalyzer(scanId, 'dependencies', [depFinding(scanId)]);
    const res = await app.inject({ method: 'GET', url: `/api/scans/${scanId}/export/cyclonedx` });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('application/json');
    expect(res.headers['content-disposition']).toBe('attachment; filename="vibesec-acme-app-0000000.cyclonedx.json"');
    const bom = res.json();
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.6');
    expect(bom.metadata.properties[0].value).toMatch(/not a full SBOM/);
  });

  it('builds npm (incl. scoped) and PyPI purls, and dev scope → optional', async () => {
    await start();
    const scanId = await scanReady();
    c.findings.replaceForAnalyzer(scanId, 'dependencies', [
      depFinding(scanId, { id: 'd1', fingerprint: 'fp-d1' }),
      depFinding(scanId, {
        id: 'd2', fingerprint: 'fp-d2',
        dependency: { ecosystem: 'npm', name: '@babel/core', version: '7.0.0', scope: 'dev', direct: true, paths: [], advisories: [{ id: 'GHSA-2', aliases: [], summary: 's', severity: 'medium', cvss: null, fixedIn: null, url: null }], reachability: 'unknown' },
      }),
      depFinding(scanId, {
        id: 'd3', fingerprint: 'fp-d3',
        dependency: { ecosystem: 'PyPI', name: 'Django', version: '3.0.0', scope: 'prod', direct: true, paths: [], advisories: [{ id: 'GHSA-3', aliases: [], summary: 's', severity: 'critical', cvss: 9.1, fixedIn: '3.0.1', url: 'https://example.test/advisory' }], reachability: 'unreachable' },
      }),
    ]);
    const res = await app.inject({ method: 'GET', url: `/api/scans/${scanId}/export/cyclonedx` });
    const bom = res.json();
    const purls = bom.components.map((c: { purl: string }) => c.purl).sort();
    expect(purls).toEqual([purlFor('PyPI', 'Django', '3.0.0'), purlFor('npm', '@babel/core', '7.0.0'), purlFor('npm', 'lodash', '4.17.20')].sort());
    expect(purlFor('npm', '@babel/core', '7.0.0')).toBe('pkg:npm/%40babel/core@7.0.0');
    expect(purlFor('PyPI', 'Django', '3.0.0')).toBe('pkg:pypi/django@3.0.0');
    const babel = bom.components.find((c: { name: string }) => c.name === '@babel/core');
    expect(babel.scope).toBe('optional');
    const lodash = bom.components.find((c: { name: string }) => c.name === 'lodash');
    expect(lodash.scope).toBe('required');
  });

  it('maps reachability to VEX analysis states (reachable→exploitable, unreachable→not_affected+justification, else→in_triage)', async () => {
    await start();
    const scanId = await scanReady();
    c.findings.replaceForAnalyzer(scanId, 'dependencies', [
      depFinding(scanId, { id: 'd1', fingerprint: 'fp-d1', dependency: { ...depFinding(scanId).dependency!, reachability: 'reachable' } }),
      depFinding(scanId, {
        id: 'd2', fingerprint: 'fp-d2',
        dependency: { ecosystem: 'npm', name: 'left-pad', version: '1.0.0', scope: 'prod', direct: true, paths: [], advisories: [{ id: 'GHSA-4', aliases: [], summary: 's', severity: 'high', cvss: null, fixedIn: null, url: null }], reachability: 'unreachable' },
      }),
      depFinding(scanId, {
        id: 'd3', fingerprint: 'fp-d3',
        dependency: { ecosystem: 'npm', name: 'is-odd', version: '1.0.0', scope: 'prod', direct: true, paths: [], advisories: [{ id: 'GHSA-5', aliases: [], summary: 's', severity: 'low', cvss: null, fixedIn: null, url: null }], reachability: 'imported' },
      }),
    ]);
    const res = await app.inject({ method: 'GET', url: `/api/scans/${scanId}/export/cyclonedx` });
    const vulns = res.json().vulnerabilities as Array<{ id: string; analysis: { state: string; justification?: string } }>;
    const byId = Object.fromEntries(vulns.map((v) => [v.id, v.analysis]));
    expect(byId['GHSA-1']).toEqual({ state: 'exploitable' });
    expect(byId['GHSA-4']).toEqual({ state: 'not_affected', justification: 'code_not_reachable' });
    expect(byId['GHSA-5']).toEqual({ state: 'in_triage' });
  });

  it('uses the OSV source and falls back to an osv.dev URL when the advisory has none', async () => {
    await start();
    const scanId = await scanReady();
    c.findings.replaceForAnalyzer(scanId, 'dependencies', [depFinding(scanId)]);
    const res = await app.inject({ method: 'GET', url: `/api/scans/${scanId}/export/cyclonedx` });
    const [vuln] = res.json().vulnerabilities;
    expect(vuln.source).toEqual({ name: 'OSV', url: 'https://osv.dev/vulnerability/GHSA-1' });
    expect(vuln.ratings[0]).toEqual({ severity: 'high', method: 'CVSSv31', score: 7.5 });
  });
});
