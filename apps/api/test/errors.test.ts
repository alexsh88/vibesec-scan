import { describe, expect, it } from 'vitest';
import { AppError, toAppError } from '../src/errors/AppError';

describe('AppError', () => {
  it('maps codes to http status', () => {
    expect(new AppError('VALIDATION', 'permanent', 'bad').httpStatus).toBe(400);
    expect(new AppError('AUTH_INVALID', 'permanent', 'x').httpStatus).toBe(403);
    expect(new AppError('QUEUE_FULL', 'transient', 'x').httpStatus).toBe(503);
    expect(new AppError('LLM_UNAVAILABLE', 'transient', 'x').httpStatus).toBe(500);
  });

  it('is retryable only when transient', () => {
    expect(new AppError('INTERNAL', 'transient', 'x').retryable).toBe(true);
    expect(new AppError('INTERNAL', 'permanent', 'x').retryable).toBe(false);
  });
});

describe('toAppError', () => {
  it('passes AppError through', () => {
    const e = new AppError('NOT_FOUND', 'permanent', 'nope');
    expect(toAppError(e)).toBe(e);
  });

  it('maps AbortError to cancelled', () => {
    const e = toAppError(Object.assign(new Error('aborted'), { name: 'AbortError' }));
    expect(e.code).toBe('CANCELLED');
    expect(e.kind).toBe('cancelled');
  });

  it('maps TimeoutError to transient', () => {
    const e = toAppError(Object.assign(new Error('t'), { name: 'TimeoutError' }));
    expect(e.kind).toBe('transient');
  });

  it('maps unknown errors to permanent INTERNAL without leaking the message', () => {
    const e = toAppError(new Error('db password=hunter2 exploded'));
    expect(e.code).toBe('INTERNAL');
    expect(e.userMessage).not.toContain('hunter2');
  });
});
