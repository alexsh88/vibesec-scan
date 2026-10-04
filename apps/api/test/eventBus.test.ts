import { describe, expect, it, vi } from 'vitest';
import { ScanOptionsSchema, type StoredScanEvent } from '@vibesec/shared';
import { EventRepo } from '../src/db/eventRepo';
import { ScanRepo } from '../src/db/scanRepo';
import { EventBus } from '../src/events/EventBus';
import { ScanLifecycle } from '../src/scans/ScanLifecycle';
import { memoryDb } from './helpers';

function setup() {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const bus = new EventBus(new EventRepo(db));
  const lifecycle = new ScanLifecycle(scans, bus, db);
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const id = scans.insertScan({
    repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: 'h', idempotencyKey: null, hasAuth: false,
  }).id;
  return { scans, bus, lifecycle, id };
}

describe('EventBus', () => {
  it('persists and delivers events to subscribers of that scan only', () => {
    const { bus, id } = setup();
    const seen: StoredScanEvent[] = [];
    const other = vi.fn();
    bus.subscribe(id, (e) => seen.push(e));
    bus.subscribe('other-scan', other);
    bus.publish(id, { type: 'progress', analyzer: 'a', done: 1, total: 2 });
    expect(seen.map((e) => e.seq)).toEqual([1]);
    expect(other).not.toHaveBeenCalled();
    expect(bus.replay(id, 0)).toHaveLength(1);
  });

  it('unsubscribes', () => {
    const { bus, id } = setup();
    const fn = vi.fn();
    const off = bus.subscribe(id, fn);
    off();
    bus.publish(id, { type: 'progress', analyzer: 'a', done: 1, total: 2 });
    expect(fn).not.toHaveBeenCalled();
    expect(bus.listenerCount(id)).toBe(0);
  });

  it('isolates a throwing listener', () => {
    const { bus, id } = setup();
    const good = vi.fn();
    bus.subscribe(id, () => { throw new Error('boom'); });
    bus.subscribe(id, good);
    bus.publish(id, { type: 'progress', analyzer: 'a', done: 1, total: 2 });
    expect(good).toHaveBeenCalledOnce();
  });

  it('I-6: a repeated unsubscribe does not remove a later subscriber', () => {
    const { bus, id } = setup();
    const off = bus.subscribe(id, vi.fn());
    off();
    const later = vi.fn();
    bus.subscribe(id, later);
    off();
    bus.publish(id, { type: 'progress', analyzer: 'a', done: 1, total: 2 });
    expect(later).toHaveBeenCalledOnce();
    expect(bus.listenerCount(id)).toBe(1);
  });
});

describe('ScanLifecycle', () => {
  it('updates state and publishes state + done on terminal', () => {
    const { scans, bus, lifecycle, id } = setup();
    lifecycle.transition(id, 'RESOLVING');
    lifecycle.transition(id, 'FAILED', { code: 'AUTH_INVALID', message: 'bad token' });
    expect(scans.getDto(id)?.state).toBe('FAILED');
    expect(bus.replay(id, 0).map((e) => e.event)).toEqual([
      { type: 'state', state: 'RESOLVING' },
      { type: 'state', state: 'FAILED', errorCode: 'AUTH_INVALID', message: 'bad token' },
      { type: 'done', state: 'FAILED' },
    ]);
  });

  it('C-1: is terminal-once — a second terminal transition is a no-op and publishes nothing', () => {
    const { scans, bus, lifecycle, id } = setup();
    expect(lifecycle.transition(id, 'COMPLETED')).toBe(true);
    expect(lifecycle.transition(id, 'FAILED', { code: 'INTERNAL', message: 'x' })).toBe(false);
    expect(lifecycle.transition(id, 'ANALYZING')).toBe(false);
    expect(scans.getDto(id)).toMatchObject({ state: 'COMPLETED', errorCode: null });
    expect(bus.replay(id, 0).map((e) => e.event)).toEqual([
      { type: 'state', state: 'COMPLETED' },
      { type: 'done', state: 'COMPLETED' },
    ]);
  });

  it('C-1: the row update and the published events commit atomically', () => {
    const { scans, bus, lifecycle, id } = setup();
    const original = bus.publish.bind(bus);
    vi.spyOn(bus, 'publish').mockImplementation((scanId, event) => {
      if (event.type === 'done') throw new Error('event store down');
      return original(scanId, event);
    });
    expect(() => lifecycle.transition(id, 'COMPLETED')).toThrow('event store down');
    expect(scans.getDto(id)!.state).toBe('QUEUED');
    expect(bus.replay(id, 0)).toEqual([]);
  });

  it('records and publishes warnings', () => {
    const { scans, bus, lifecycle, id } = setup();
    lifecycle.warn(id, { code: 'OSV_UNAVAILABLE', message: 'osv down', stage: 'ANALYZING' });
    expect(scans.getDto(id)?.warnings).toEqual([{ code: 'OSV_UNAVAILABLE', message: 'osv down', stage: 'ANALYZING' }]);
    expect(bus.replay(id, 0)[0]?.event).toEqual({ type: 'warning', code: 'OSV_UNAVAILABLE', message: 'osv down', stage: 'ANALYZING' });
  });
});
