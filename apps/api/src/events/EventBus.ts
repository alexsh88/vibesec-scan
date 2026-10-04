import type { ScanEvent, StoredScanEvent } from '@vibesec/shared';
import type { EventRepo } from '../db/eventRepo';

export type EventListener = (event: StoredScanEvent) => void;

export class EventBus {
  private readonly listeners = new Map<string, Set<EventListener>>();

  constructor(private readonly events: EventRepo) {}

  publish(scanId: string, event: ScanEvent): StoredScanEvent {
    const stored = this.events.append(scanId, event);
    for (const listener of this.listeners.get(scanId) ?? []) {
      try {
        listener(stored);
      } catch {
        // A broken subscriber (e.g. closed socket) must never break the scan.
      }
    }
    return stored;
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
      if (set.size === 0) this.listeners.delete(scanId);
    };
  }

  replay(scanId: string, afterSeq: number): StoredScanEvent[] {
    return this.events.listAfter(scanId, afterSeq);
  }

  listenerCount(scanId: string): number {
    return this.listeners.get(scanId)?.size ?? 0;
  }
}
