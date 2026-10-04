import type { ScanEvent, StoredScanEvent } from '@vibesec/shared';
import type { EventRepo } from '../db/eventRepo';

export type EventListener = (event: StoredScanEvent) => void;

export class EventBus {
  private readonly listeners = new Map<string, Set<EventListener>>();

  constructor(private readonly events: EventRepo) {}

  /** Persist + fan out. Only for callers outside a transaction; transactional callers use append/notify. */
  publish(scanId: string, event: ScanEvent): StoredScanEvent {
    const stored = this.append(scanId, event);
    this.notify(stored);
    return stored;
  }

  /** Persist only. Inside a transaction, call notify() for the result only after the transaction commits. */
  append(scanId: string, event: ScanEvent): StoredScanEvent {
    return this.events.append(scanId, event);
  }

  /** Fan an already-committed event out to the scan's live subscribers. */
  notify(stored: StoredScanEvent): void {
    for (const listener of this.listeners.get(stored.scanId) ?? []) {
      try {
        listener(stored);
      } catch {
        // A broken subscriber (e.g. closed socket) must never break the scan.
      }
    }
  }

  subscribe(scanId: string, listener: EventListener): () => void {
    let set = this.listeners.get(scanId);
    if (!set) {
      set = new Set();
      this.listeners.set(scanId, set);
    }
    set.add(listener);
    return () => {
      set.delete(listener);
      // Only drop the map entry if it is still *this* set: a repeated unsubscribe must not remove a
      // newer set created by a later subscriber.
      if (set.size === 0 && this.listeners.get(scanId) === set) this.listeners.delete(scanId);
    };
  }

  replay(scanId: string, afterSeq: number): StoredScanEvent[] {
    return this.events.listAfter(scanId, afterSeq);
  }

  listenerCount(scanId: string): number {
    return this.listeners.get(scanId)?.size ?? 0;
  }
}
