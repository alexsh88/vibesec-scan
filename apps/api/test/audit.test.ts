import { describe, expect, it } from 'vitest';
import { AuditLogger, GENESIS_HASH } from '../src/audit/AuditLogger';
import { canonicalJson } from '../src/audit/canonicalJson';
import { memoryDb } from './helpers';

function setup() {
  const db = memoryDb();
  let t = 0;
  const audit = new AuditLogger(db, () => new Date(Date.UTC(2026, 9, 4, 0, 0, t++)).toISOString());
  return { db, audit };
}

describe('canonicalJson', () => {
  it('sorts keys recursively', () => {
    expect(canonicalJson({ b: 1, a: { d: [2, { z: 1, y: 2 }], c: null } })).toBe('{"a":{"c":null,"d":[2,{"y":2,"z":1}]},"b":1}');
  });
});

describe('AuditLogger', () => {
  it('starts the chain at the genesis hash and links entries', () => {
    const { audit } = setup();
    const a = audit.append({ action: 'scan.created', targetType: 'scan', targetId: 's1', scanId: 's1', details: { repo: 'acme/app' } });
    const b = audit.append({ action: 'scan.cancelled', targetType: 'scan', targetId: 's1', scanId: 's1' });
    expect(a.prevHash).toBe(GENESIS_HASH);
    expect(b.prevHash).toBe(a.hash);
    expect(a.actor).toBe('local-user');
  });

  it('verifies an intact chain', () => {
    const { audit } = setup();
    for (let i = 0; i < 5; i++) audit.append({ action: 'scan.created', targetType: 'scan', targetId: `s${i}` });
    expect(audit.verify()).toEqual({ ok: true, checked: 5 });
  });

  it('rejects UPDATE and DELETE via triggers', () => {
    const { db, audit } = setup();
    audit.append({ action: 'scan.created', targetType: 'scan', targetId: 's1' });
    expect(() => db.prepare(`UPDATE audit_log SET action = 'x'`).run()).toThrow(/append-only/);
    expect(() => db.prepare(`DELETE FROM audit_log`).run()).toThrow(/append-only/);
  });

  it('detects a tampered row', () => {
    const { db, audit } = setup();
    for (let i = 0; i < 3; i++) audit.append({ action: 'finding.triaged', targetType: 'finding', targetId: `f${i}`, details: { status: 'open' } });
    db.prepare(`DROP TRIGGER audit_log_no_update`).run();
    db.prepare(`UPDATE audit_log SET details_json = '{"status":"false_positive"}' WHERE seq = 2`).run();
    expect(audit.verify()).toEqual({ ok: false, checked: 1, firstBrokenSeq: 2 });
  });

  it('scrubs secrets from details', () => {
    const { audit } = setup();
    const e = audit.append({
      action: 'secret.verification_attempted', targetType: 'finding', targetId: 'f1',
      details: { provider: 'aws', note: 'AKIAIOSFODNN7EXAMPLE', token: 'abc' },
    });
    expect(e.details).toEqual({ provider: 'aws', note: '[REDACTED]', token: '[REDACTED]' });
  });

  it('rolls back with the surrounding transaction', () => {
    const { db, audit } = setup();
    expect(() => db.transaction(() => {
      audit.append({ action: 'scan.created', targetType: 'scan', targetId: 's1' });
      throw new Error('action failed');
    })()).toThrow('action failed');
    expect(audit.list({}).items).toHaveLength(0);
  });

  it('lists with filters and cursor pagination, newest first', () => {
    const { audit } = setup();
    audit.append({ action: 'scan.created', targetType: 'scan', targetId: 's1' });
    audit.append({ action: 'export.downloaded', targetType: 'scan', targetId: 's1', details: { format: 'sarif' } });
    audit.append({ action: 'scan.created', targetType: 'scan', targetId: 's2' });
    const page1 = audit.list({ action: 'scan.created', limit: 1 });
    expect(page1.items.map((e) => e.targetId)).toEqual(['s2']);
    const page2 = audit.list({ action: 'scan.created', limit: 1, beforeSeq: page1.nextCursor! });
    expect(page2.items.map((e) => e.targetId)).toEqual(['s1']);
    expect(page2.nextCursor).toBeNull();
  });
});
