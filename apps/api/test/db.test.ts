import { describe, expect, it } from 'vitest';
import { ScanRepo } from '../src/db/scanRepo';
import { EventRepo } from '../src/db/eventRepo';
import { memoryDb } from './helpers';

const options = { verifySecrets: false, historyDepth: 50, categories: ['secret' as const] };

function seed() {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const scan = scans.insertScan({ repoId: repo.id, ref: 'main', options, optionsHash: 'h1', idempotencyKey: null, hasAuth: false });
  return { db, scans, repo, scan };
}

describe('migrations', () => {
  it('sets user_version to latest', () => {
    const db = memoryDb();
    expect(db.pragma('user_version', { simple: true })).toBe(4);
  });
});

describe('ScanRepo', () => {
  it('upserts repos idempotently', () => {
    const { scans, repo } = seed();
    expect(scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: true }).id).toBe(repo.id);
    expect(scans.getRepo(repo.id)?.isPrivate).toBe(true);
  });

  it('findRepo looks a repo up without creating or updating it', () => {
    const { scans, repo } = seed();
    expect(scans.findRepo('acme', 'app')).toEqual(repo);
    expect(scans.findRepo('acme', 'missing')).toBeUndefined();
    expect(scans.listRepos()).toHaveLength(1);
  });

  it('inserts a QUEUED scan and maps it to a DTO', () => {
    const { scans, scan } = seed();
    const dto = scans.getDto(scan.id);
    expect(dto?.state).toBe('QUEUED');
    expect(dto?.repo.owner).toBe('acme');
    expect(dto?.options).toEqual(options);
    expect(dto?.warnings).toEqual([]);
  });

  it('finds an active duplicate by repo/ref/options', () => {
    const { scans, repo, scan } = seed();
    expect(scans.findActiveDuplicate(repo.id, 'main', 'h1')?.id).toBe(scan.id);
    expect(scans.findActiveDuplicate(repo.id, 'dev', 'h1')).toBeUndefined();
    scans.updateState(scan.id, 'COMPLETED');
    expect(scans.findActiveDuplicate(repo.id, 'main', 'h1')).toBeUndefined();
  });

  it('sets startedAt on first non-queued state and finishedAt on terminal state', () => {
    const { scans, scan } = seed();
    scans.updateState(scan.id, 'RESOLVING');
    expect(scans.getDto(scan.id)?.startedAt).not.toBeNull();
    scans.updateState(scan.id, 'FAILED', { errorCode: 'AUTH_INVALID', errorMessage: 'bad token' });
    const dto = scans.getDto(scan.id);
    expect(dto?.finishedAt).not.toBeNull();
    expect(dto?.errorCode).toBe('AUTH_INVALID');
  });

  it('stores warnings, checkpoints and heartbeats', () => {
    const { scans, scan } = seed();
    scans.addWarning(scan.id, { code: 'OSV_UNAVAILABLE', message: 'osv down', stage: 'ANALYZING' });
    scans.setCheckpoint(scan.id, { completedStages: ['RESOLVING'], data: { commitSha: 'abc' } });
    scans.heartbeat(scan.id);
    const row = scans.getRow(scan.id);
    expect(scans.getDto(scan.id)?.warnings).toHaveLength(1);
    expect(scans.getCheckpoint(scan.id)).toEqual({ completedStages: ['RESOLVING'], data: { commitSha: 'abc' } });
    expect(row?.heartbeat_at).not.toBeNull();
  });

  it('error fields track state: set on FAILED, cleared on transition to non-FAILED state', () => {
    const { scans, scan } = seed();
    scans.updateState(scan.id, 'FAILED', { errorCode: 'AUTH_INVALID', errorMessage: 'bad token' });
    expect(scans.getDto(scan.id)?.errorCode).toBe('AUTH_INVALID');
    expect(scans.getDto(scan.id)?.errorMessage).toBe('bad token');
    scans.updateState(scan.id, 'RESOLVING');
    expect(scans.getDto(scan.id)?.errorCode).toBeNull();
    expect(scans.getDto(scan.id)?.errorMessage).toBeNull();
  });

  it('transitionState is terminal-once and reports whether the row changed', () => {
    const { scans, scan } = seed();
    expect(scans.transitionState(scan.id, 'RESOLVING')).toBe(true);
    expect(scans.transitionState(scan.id, 'COMPLETED')).toBe(true);
    const finishedAt = scans.getDto(scan.id)?.finishedAt;
    expect(scans.transitionState(scan.id, 'FAILED', { errorCode: 'INTERNAL', errorMessage: 'x' })).toBe(false);
    expect(scans.transitionState(scan.id, 'ANALYZING')).toBe(false);
    expect(scans.getDto(scan.id)).toMatchObject({ state: 'COMPLETED', errorCode: null, finishedAt });
    expect(scans.transitionState('missing', 'RESOLVING')).toBe(false);
  });

  it('removes warnings for the given stages, keeping order and stage-less warnings', () => {
    const { scans, scan } = seed();
    scans.addWarning(scan.id, { code: 'A', message: 'a', stage: 'ANALYZING' });
    scans.addWarning(scan.id, { code: 'B', message: 'b', stage: 'VERIFYING' });
    scans.addWarning(scan.id, { code: 'C', message: 'c' });
    scans.addWarning(scan.id, { code: 'D', message: 'd', stage: 'SYNTHESIZING' });
    scans.removeWarningsForStages(scan.id, ['VERIFYING', 'SYNTHESIZING']);
    expect(scans.getDto(scan.id)?.warnings).toEqual([
      { code: 'A', message: 'a', stage: 'ANALYZING' },
      { code: 'C', message: 'c' },
    ]);
  });

  it('lists non-terminal scans for recovery', () => {
    const { scans, scan } = seed();
    expect(scans.listNonTerminal().map((s) => s.id)).toEqual([scan.id]);
  });

  it('finds by idempotency key', () => {
    const { scans, repo } = seed();
    const s = scans.insertScan({ repoId: repo.id, ref: null, options, optionsHash: 'h2', idempotencyKey: 'k-1', hasAuth: false });
    expect(scans.findByIdempotencyKey('k-1')?.id).toBe(s.id);
  });
});

describe('EventRepo', () => {
  it('assigns monotonically increasing seq per scan and lists after a seq', () => {
    const { db, scan } = seed();
    const events = new EventRepo(db);
    const a = events.append(scan.id, { type: 'state', state: 'RESOLVING' });
    const b = events.append(scan.id, { type: 'progress', analyzer: 'x', done: 1, total: 2 });
    expect([a.seq, b.seq]).toEqual([1, 2]);
    expect(events.listAfter(scan.id, 1).map((e) => e.seq)).toEqual([2]);
    expect(events.listAfter(scan.id, 0)[0]?.event).toEqual({ type: 'state', state: 'RESOLVING' });
  });
});
