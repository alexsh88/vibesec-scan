import { isTerminalState, type ScanState } from '@vibesec/shared';
import type { Db } from '../db/database';
import type { ScanRepo, ScanWarning } from '../db/scanRepo';
import type { EventBus } from '../events/EventBus';

/** The only writer of scan state: keeps the row and the event stream consistent. */
export class ScanLifecycle {
  constructor(private readonly scans: ScanRepo, private readonly bus: EventBus, private readonly db: Db) {}

  /**
   * Moves the scan to `state` and publishes the matching events, atomically. Terminal-once: once a scan
   * is terminal every further transition is a no-op that publishes nothing. Returns whether it applied.
   */
  transition(scanId: string, state: ScanState, error?: { code: string; message: string }): boolean {
    return this.db.transaction(() => {
      if (!this.scans.transitionState(scanId, state, { errorCode: error?.code, errorMessage: error?.message })) return false;
      this.bus.publish(scanId, error
        ? { type: 'state', state, errorCode: error.code, message: error.message }
        : { type: 'state', state });
      if (isTerminalState(state)) this.bus.publish(scanId, { type: 'done', state });
      return true;
    })();
  }

  warn(scanId: string, warning: ScanWarning & { file?: string }): void {
    const { file, ...stored } = warning;
    this.db.transaction(() => {
      this.scans.addWarning(scanId, stored);
      this.bus.publish(scanId, { type: 'warning', ...stored, ...(file ? { file } : {}) });
    })();
  }
}
