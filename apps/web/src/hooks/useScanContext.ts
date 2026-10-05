import type { ScanDto } from '@vibesec/shared';
import { createContext, useContext } from 'react';
import type { UseScanEventsResult } from './useScanEvents';

export type ScanContextValue = {
  scanId: string;
  /** Always loaded (ScanLayout renders skeleton/error until it is). Kept fresh by the SSE stream. */
  scan: ScanDto;
  /**
   * The single SSE connection for this scan (owned by ScanLayout). Connected while the scan runs and
   * on the live page (where a finished scan's event log is replayed). Do NOT call useScanEvents again
   * inside scan pages — read it from here.
   */
  events: UseScanEventsResult;
};

export const ScanContext = createContext<ScanContextValue | null>(null);

/** For pages under /scans/:id/* — the scan, its live event state and the scan id. */
export function useScanContext(): ScanContextValue {
  const ctx = useContext(ScanContext);
  if (!ctx) throw new Error('useScanContext must be used inside <ScanLayout>');
  return ctx;
}
