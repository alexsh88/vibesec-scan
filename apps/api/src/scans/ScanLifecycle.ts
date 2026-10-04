import { isTerminalState, type ScanState } from '@vibesec/shared';
import type { ScanRepo, ScanWarning } from '../db/scanRepo';
import type { EventBus } from '../events/EventBus';

/** The only writer of scan state: keeps the row and the event stream consistent. */
export class ScanLifecycle {
  constructor(private readonly scans: ScanRepo, private readonly bus: EventBus) {}

  transition(scanId: string, state: ScanState, error?: { code: string; message: string }): void {
    this.scans.updateState(scanId, state, { errorCode: error?.code, errorMessage: error?.message });
    this.bus.publish(scanId, error
      ? { type: 'state', state, errorCode: error.code, message: error.message }
      : { type: 'state', state });
    if (isTerminalState(state)) this.bus.publish(scanId, { type: 'done', state });
  }

  warn(scanId: string, warning: ScanWarning & { file?: string }): void {
    const { file, ...stored } = warning;
    this.scans.addWarning(scanId, stored);
    this.bus.publish(scanId, { type: 'warning', ...stored, ...(file ? { file } : {}) });
  }
}
