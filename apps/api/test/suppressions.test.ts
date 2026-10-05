import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import type { Finding } from '@vibesec/shared';
import { loadConfig } from '../src/config';
import { createContainer, type Container } from '../src/container';
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

const createScan = (repoUrl = 'https://github.com/acme/app') =>
  app.inject({ method: 'POST', url: '/api/scans', payload: { repoUrl } });

let n = 0;
const finding = (scanId: string, over: Partial<Finding> = {}): Finding => ({
  id: `f-${++n}`, scanId, fingerprint: `fp-${n}`, category: 'secret', ruleId: 'secret/github-pat', title: 'Hardcoded GitHub token',
  baseSeverity: 'high', riskScore: 70, severity: 'high', riskFactors: [], confidence: 'high',
  location: { file: 'src/a.ts', startLine: 3, endLine: 3, snippet: 'const t = "ghp_***"', permalink: 'https://github.com/acme/app/blob/sha/src/a.ts#L3' },
  explanation: 'e', impact: 'i', remediation: { summary: 'rotate' }, scanStatus: 'new', ...over,
});

describe('Finding triage / suppression', () => {
  it('sets triage on a finding (200) and persists it on the finding JSON', async () => {
    await start();
    const { scanId } = (await createScan()).json();
    await c.runner.whenIdle();
    const f = finding(scanId);
    c.findings.replaceForAnalyzer(scanId, 'secrets', [f]);

    const res = await app.inject({
      method: 'PUT', url: `/api/scans/${scanId}/findings/${f.id}/triage`,
      payload: { status: 'false_positive', reason: 'Test fixture, not a real secret' },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().triage).toMatchObject({ status: 'false_positive', reason: 'Test fixture, not a real secret' });
    expect(res.json().triage.at).toBeTypeOf('string');

    const get = await app.inject({ method: 'GET', url: `/api/scans/${scanId}/findings/${f.id}` });
    expect(get.json().triage.status).toBe('false_positive');
  });

  it('clears triage (200) and removes it from the finding', async () => {
    await start();
    const { scanId } = (await createScan()).json();
    await c.runner.whenIdle();
    const f = finding(scanId);
    c.findings.replaceForAnalyzer(scanId, 'secrets', [f]);
    await app.inject({
      method: 'PUT', url: `/api/scans/${scanId}/findings/${f.id}/triage`,
      payload: { status: 'accepted_risk', reason: 'Known, risk accepted' },
    });

    const res = await app.inject({ method: 'DELETE', url: `/api/scans/${scanId}/findings/${f.id}/triage` });
    expect(res.statusCode).toBe(200);
    expect(res.json().triage).toBeUndefined();

    const get = await app.inject({ method: 'GET', url: `/api/scans/${scanId}/findings/${f.id}` });
    expect(get.json().triage).toBeUndefined();
  });

  it('filters the findings list by triage state (open|suppressed|all, default all)', async () => {
    await start();
    const { scanId } = (await createScan()).json();
    await c.runner.whenIdle();
    const open = finding(scanId, { title: 'open one' });
    const suppressed = finding(scanId, { title: 'suppressed one' });
    c.findings.replaceForAnalyzer(scanId, 'secrets', [open, suppressed]);
    await app.inject({
      method: 'PUT', url: `/api/scans/${scanId}/findings/${suppressed.id}/triage`,
      payload: { status: 'wont_fix', reason: 'accepted' },
    });

    const all = (await app.inject({ method: 'GET', url: `/api/scans/${scanId}/findings` })).json();
    expect(all.items).toHaveLength(2);
    const openOnly = (await app.inject({ method: 'GET', url: `/api/scans/${scanId}/findings?triage=open` })).json();
    expect(openOnly.items.map((x: Finding) => x.id)).toEqual([open.id]);
    const suppressedOnly = (await app.inject({ method: 'GET', url: `/api/scans/${scanId}/findings?triage=suppressed` })).json();
    expect(suppressedOnly.items.map((x: Finding) => x.id)).toEqual([suppressed.id]);
  });

  it('persists triage across a later scan of the same repo by fingerprint, via applySuppressions', async () => {
    await start();
    const scan1 = (await createScan()).json();
    await c.runner.whenIdle();
    const sharedFingerprint = 'shared-fp-1';
    const f1 = finding(scan1.scanId, { fingerprint: sharedFingerprint });
    c.findings.replaceForAnalyzer(scan1.scanId, 'secrets', [f1]);
    await app.inject({
      method: 'PUT', url: `/api/scans/${scan1.scanId}/findings/${f1.id}/triage`,
      payload: { status: 'false_positive', reason: 'fp' },
    });

    // scan1 is terminal now, so creating another scan for the same repo is a brand new scan, not a dedupe.
    const scan2 = (await createScan()).json();
    expect(scan2.scanId).not.toBe(scan1.scanId);
    await c.runner.whenIdle();
    const f2 = finding(scan2.scanId, { id: 'f2-same-fp', fingerprint: sharedFingerprint });
    c.findings.replaceForAnalyzer(scan2.scanId, 'secrets', [f2]);

    c.suppressions.applySuppressions(scan2.scanId);
    const got = (await app.inject({ method: 'GET', url: `/api/scans/${scan2.scanId}/findings/${f2.id}` })).json();
    expect(got.triage).toMatchObject({ status: 'false_positive', reason: 'fp' });
  });

  it('carries triage across a cross-analyzer merge in either direction (mergedFingerprints)', async () => {
    await start();
    const scan1 = (await createScan()).json();
    await c.runner.whenIdle();
    // Scan 1: the taint finding won the merge and absorbed the SAST one; the user triages the winner.
    const winner = finding(scan1.scanId, { fingerprint: 'taint-fp', mergedFingerprints: ['sast-fp'] });
    const plain = finding(scan1.scanId, { fingerprint: 'plain-fp' });
    c.findings.replaceForAnalyzer(scan1.scanId, 'secrets', [winner, plain]);
    for (const f of [winner, plain]) {
      await app.inject({ method: 'PUT', url: `/api/scans/${scan1.scanId}/findings/${f.id}/triage`, payload: { status: 'false_positive', reason: 'fp' } });
    }

    const scan2 = (await createScan()).json();
    await c.runner.whenIdle();
    // Scan 2: only the SAST finding is reported (no merge), and the plain one became a merge winner.
    const alone = finding(scan2.scanId, { id: 'alone', fingerprint: 'sast-fp' });
    const newWinner = finding(scan2.scanId, { id: 'new-winner', fingerprint: 'other-fp', mergedFingerprints: ['plain-fp'] });
    c.findings.replaceForAnalyzer(scan2.scanId, 'secrets', [alone, newWinner]);
    c.suppressions.applySuppressions(scan2.scanId);
    expect(c.findings.get(scan2.scanId, 'alone')?.triage?.status).toBe('false_positive');
    expect(c.findings.get(scan2.scanId, 'new-winner')?.triage?.status).toBe('false_positive');

    // Clearing the triage clears every fingerprint it was recorded under.
    await app.inject({ method: 'DELETE', url: `/api/scans/${scan1.scanId}/findings/${winner.id}/triage` });
    expect(c.suppressions.listByRepo(c.scans.getDto(scan1.scanId)!.repo.id).map((x) => x.fingerprint)).toEqual(['plain-fp']);
  });

  it('does not re-apply an expired suppression to a later scan', async () => {
    await start();
    const scan1 = (await createScan()).json();
    await c.runner.whenIdle();
    const fp = 'expiring-fp';
    const f1 = finding(scan1.scanId, { fingerprint: fp });
    c.findings.replaceForAnalyzer(scan1.scanId, 'secrets', [f1]);
    // A decision that has since lapsed (the API rejects a past expiresAt, so set it via the service).
    c.suppressions.setTriage(scan1.scanId, f1.id, { status: 'accepted_risk', reason: 'temporary', expiresAt: '2000-01-01T00:00:00.000Z' }, { ip: null, userAgent: null });

    const scan2 = (await createScan()).json();
    await c.runner.whenIdle();
    const f2 = finding(scan2.scanId, { id: 'f2-expired', fingerprint: fp });
    c.findings.replaceForAnalyzer(scan2.scanId, 'secrets', [f2]);
    c.suppressions.applySuppressions(scan2.scanId);

    const got = (await app.inject({ method: 'GET', url: `/api/scans/${scan2.scanId}/findings/${f2.id}` })).json();
    expect(got.triage).toBeUndefined();
  });

  it('writes audit entries for triage/untriage with a fingerprint prefix + status, never finding text', async () => {
    await start();
    const { scanId } = (await createScan()).json();
    await c.runner.whenIdle();
    const f = finding(scanId, { fingerprint: 'abcdefghijklmnop', title: 'SECRET_TITLE_MARKER' });
    c.findings.replaceForAnalyzer(scanId, 'secrets', [f]);
    await app.inject({
      method: 'PUT', url: `/api/scans/${scanId}/findings/${f.id}/triage`,
      payload: { status: 'false_positive', reason: 'definitely a fixture, reason text XYZ' },
    });
    await app.inject({ method: 'DELETE', url: `/api/scans/${scanId}/findings/${f.id}/triage` });

    const list = (await app.inject({ method: 'GET', url: `/api/audit?targetId=${f.id}` })).json().items;
    expect(list.map((e: { action: string }) => e.action).sort()).toEqual(['finding.triaged', 'finding.untriaged']);
    for (const entry of list) {
      const serialized = JSON.stringify(entry.details);
      expect(serialized).not.toContain('XYZ');
      expect(serialized).not.toContain('SECRET_TITLE_MARKER');
      expect(entry.details.fingerprint).toBe('abcdefghijkl'); // 12-char prefix, never the full fingerprint
    }
  });

  it('returns 404 for an unknown scan or finding', async () => {
    await start();
    const resScan = await app.inject({
      method: 'PUT', url: '/api/scans/nope/findings/f1/triage', payload: { status: 'false_positive', reason: 'x' },
    });
    expect(resScan.statusCode).toBe(404);
    const { scanId } = (await createScan()).json();
    await c.runner.whenIdle();
    const resFinding = await app.inject({
      method: 'PUT', url: `/api/scans/${scanId}/findings/nope/triage`, payload: { status: 'false_positive', reason: 'x' },
    });
    expect(resFinding.statusCode).toBe(404);
    expect((await app.inject({ method: 'DELETE', url: `/api/scans/${scanId}/findings/nope/triage` })).statusCode).toBe(404);
  });

  it('rejects an expiresAt in the past (400)', async () => {
    await start();
    const { scanId } = (await createScan()).json();
    await c.runner.whenIdle();
    const f = finding(scanId);
    c.findings.replaceForAnalyzer(scanId, 'secrets', [f]);
    const res = await app.inject({
      method: 'PUT', url: `/api/scans/${scanId}/findings/${f.id}/triage`,
      payload: { status: 'accepted_risk', reason: 'temporary', expiresAt: '2000-01-01T00:00:00.000Z' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('lists a finding whose triage expired as open, not suppressed', async () => {
    await start();
    const { scanId } = (await createScan()).json();
    await c.runner.whenIdle();
    const lapsed = finding(scanId, { triage: { status: 'wont_fix', reason: 'until the migration', at: '2000-01-01T00:00:00.000Z', expiresAt: '2001-01-01T00:00:00.000Z' } });
    const active = finding(scanId, { triage: { status: 'wont_fix', reason: 'forever', at: '2000-01-01T00:00:00.000Z' } });
    c.findings.replaceForAnalyzer(scanId, 'secrets', [lapsed, active]);
    const ids = async (q: string) => (await app.inject({ method: 'GET', url: `/api/scans/${scanId}/findings?triage=${q}` })).json().items.map((x: Finding) => x.id);
    expect(await ids('open')).toEqual([lapsed.id]);
    expect(await ids('suppressed')).toEqual([active.id]);
  });

  it('rejects a too-long reason and an invalid status (400)', async () => {
    await start();
    const { scanId } = (await createScan()).json();
    await c.runner.whenIdle();
    const f = finding(scanId);
    c.findings.replaceForAnalyzer(scanId, 'secrets', [f]);
    const tooLong = await app.inject({
      method: 'PUT', url: `/api/scans/${scanId}/findings/${f.id}/triage`, payload: { status: 'false_positive', reason: 'x'.repeat(1001) },
    });
    expect(tooLong.statusCode).toBe(400);
    const badStatus = await app.inject({
      method: 'PUT', url: `/api/scans/${scanId}/findings/${f.id}/triage`, payload: { status: 'nope', reason: 'x' },
    });
    expect(badStatus.statusCode).toBe(400);
  });
});
