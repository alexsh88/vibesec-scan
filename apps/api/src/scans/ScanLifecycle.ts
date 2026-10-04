import { isTerminalState, type ScanEvent, type ScanState, type StoredScanEvent } from '@vibesec/shared';
import type { AuditInput, AuditLogger } from '../audit/AuditLogger';
import type { Db } from '../db/database';
import type { ScanRepo, ScanWarning } from '../db/scanRepo';
import type { EventBus } from '../events/EventBus';

/**
 * The only writer of scan state: keeps the row, the event stream and the audit log consistent.
 *
 * Events are appended inside the transaction but only fanned out to live listeners after the outermost
 * `atomically` scope commits, so a subscriber never sees an event whose transaction rolled back (and the
 * SSE stream never skips the real event that later reuses that seq).
 */
export class ScanLifecycle {
  /** Events appended in the current (outermost) atomic scope, awaiting commit. null = no scope open. */
  private pending: StoredScanEvent[] | null = null;

  constructor(
    private readonly scans: ScanRepo,
    private readonly bus: EventBus,
    private readonly db: Db,
    private readonly audit: AuditLogger,
  ) {}

  /**
   * Runs `fn` in one DB transaction (a savepoint when nested). Events appended through this lifecycle
   * inside it are notified after the outermost scope commits; a rolled-back scope's events are dropped.
   */
  atomically<T>(fn: () => T): T {
    const outermost = this.pending === null;
    if (outermost) this.pending = [];
    const mark = this.pending!.length;
    let result: T;
    try {
      result = this.db.transaction(fn)();
    } catch (err) {
      if (outermost) this.pending = null;
      else this.pending!.length = mark;
      throw err;
    }
    if (outermost) {
      const committed = this.pending!;
      this.pending = null;
      for (const stored of committed) this.bus.notify(stored);
    }
    return result;
  }

  /**
   * Moves the scan to `state`, appends the matching events and (optionally) the audit entry, atomically.
   * Terminal-once: once a scan is terminal every further transition is a no-op that publishes and audits
   * nothing. Returns whether it applied.
   */
  transition(scanId: string, state: ScanState, error?: { code: string; message: string }, audit?: AuditInput): boolean {
    return this.atomically(() => {
      if (!this.scans.transitionState(scanId, state, { errorCode: error?.code, errorMessage: error?.message })) return false;
      this.append(scanId, error
        ? { type: 'state', state, errorCode: error.code, message: error.message }
        : { type: 'state', state });
      if (isTerminalState(state)) this.append(scanId, { type: 'done', state });
      if (audit) this.audit.append(audit);
      return true;
    });
  }

  warn(scanId: string, warning: ScanWarning & { file?: string }): void {
    const { file, ...stored } = warning;
    this.atomically(() => {
      this.scans.addWarning(scanId, stored);
      this.append(scanId, { type: 'warning', ...stored, ...(file ? { file } : {}) });
    });
  }

  /** Publishes a non-state event, deferring the fan-out if an atomic scope is open. */
  emit(scanId: string, event: ScanEvent): void {
    this.atomically(() => this.append(scanId, event));
  }

  private append(scanId: string, event: ScanEvent): void {
    this.pending!.push(this.bus.append(scanId, event));
  }
}
