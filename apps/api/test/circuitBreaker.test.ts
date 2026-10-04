import { describe, expect, it } from 'vitest';
import { AppError } from '../src/errors/AppError';
import { CircuitBreaker } from '../src/resilience/circuitBreaker';

const transient = () => Promise.reject(new AppError('OSV_UNAVAILABLE', 'transient', 'down'));
const permanent = () => Promise.reject(new AppError('NOT_FOUND', 'permanent', 'nope'));
const ok = () => Promise.resolve('ok');

function makeBreaker() {
  let now = 0;
  const b = new CircuitBreaker('osv', { failureThreshold: 3, resetMs: 1_000, unavailableCode: 'OSV_UNAVAILABLE' }, () => now);
  return { b, advance: (ms: number) => { now += ms; } };
}

describe('CircuitBreaker', () => {
  it('opens after consecutive transient failures and fails fast', async () => {
    const { b } = makeBreaker();
    for (let i = 0; i < 3; i++) await expect(b.run(transient)).rejects.toBeInstanceOf(AppError);
    expect(b.getState()).toBe('open');
    let called = false;
    await expect(b.run(async () => { called = true; return 1; })).rejects.toMatchObject({ code: 'OSV_UNAVAILABLE' });
    expect(called).toBe(false);
    expect(b.trips).toBe(1);
  });

  it('does not count permanent errors', async () => {
    const { b } = makeBreaker();
    for (let i = 0; i < 5; i++) await expect(b.run(permanent)).rejects.toBeInstanceOf(AppError);
    expect(b.getState()).toBe('closed');
  });

  it('resets the failure count on success', async () => {
    const { b } = makeBreaker();
    await expect(b.run(transient)).rejects.toBeDefined();
    await expect(b.run(transient)).rejects.toBeDefined();
    await b.run(ok);
    await expect(b.run(transient)).rejects.toBeDefined();
    expect(b.getState()).toBe('closed');
  });

  it('half-opens after resetMs and closes on a successful probe', async () => {
    const { b, advance } = makeBreaker();
    for (let i = 0; i < 3; i++) await expect(b.run(transient)).rejects.toBeDefined();
    advance(1_000);
    expect(b.getState()).toBe('half_open');
    await expect(b.run(ok)).resolves.toBe('ok');
    expect(b.getState()).toBe('closed');
  });

  it('re-opens when the half-open probe fails', async () => {
    const { b, advance } = makeBreaker();
    for (let i = 0; i < 3; i++) await expect(b.run(transient)).rejects.toBeDefined();
    advance(1_000);
    await expect(b.run(transient)).rejects.toBeDefined();
    expect(b.getState()).toBe('open');
  });

  it('normalizes a raw Error into an AppError (code INTERNAL) instead of rethrowing it as-is', async () => {
    const { b } = makeBreaker();
    const result = b.run(async () => { throw new Error('x'); });
    await expect(result).rejects.toBeInstanceOf(AppError);
    await expect(result).rejects.toMatchObject({ code: 'INTERNAL' });
  });

  it('allows only one probe while half-open', async () => {
    const { b, advance } = makeBreaker();
    for (let i = 0; i < 3; i++) await expect(b.run(transient)).rejects.toBeDefined();
    advance(1_000);
    let release!: () => void;
    const probe = b.run(() => new Promise<string>((r) => { release = () => r('ok'); }));
    await expect(b.run(ok)).rejects.toMatchObject({ code: 'OSV_UNAVAILABLE' });
    release();
    await expect(probe).resolves.toBe('ok');
  });
});
