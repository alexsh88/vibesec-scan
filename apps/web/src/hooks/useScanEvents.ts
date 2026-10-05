/**
 * Live scan events over SSE with client resilience (spec "Client resilience"):
 *
 *  - Connects to GET /api/scans/:id/events. The server replays every stored event with seq > `after`
 *    and then streams live ones; each SSE message carries `id: <seq>`.
 *  - On a dropped connection it reconnects itself with `?after=<last seq>` — the query-string twin of
 *    the Last-Event-ID header (EventSource can't set headers on a fresh connection) — so nothing is
 *    replayed twice or lost. Backoff 1s → 2s → 4s.
 *  - After 3 consecutive failed reconnects it falls back to polling GET /api/scans/:id every 3 s and
 *    raises `interrupted` so the UI can show the "Live updates interrupted" banner. `retryLive()`
 *    tries SSE again.
 *  - On `done` (or when the scan is already terminal) the stream is closed and scan-scoped queries
 *    are invalidated so result pages load fresh data.
 *
 * The hook also writes `state` changes into the ['scans', id] query cache, so any `useScan(id)` stays
 * current without its own polling.
 */
import { useQueryClient } from '@tanstack/react-query';
import {
  isTerminalState,
  type FindingSummary,
  type ScanDto,
  type ScanEvent,
  type ScanState,
} from '@vibesec/shared';
import { useCallback, useEffect, useReducer, useRef } from 'react';
import { api, eventsUrl } from '@/lib/api';
import { invalidateScanResults, qk } from './queries';

export type LiveEvent = ScanEvent & { seq: number; at: string };

export type ConnectionStatus = 'idle' | 'connecting' | 'open' | 'reconnecting' | 'polling' | 'closed';

export type ScanEventsState = {
  connection: ConnectionStatus;
  /** True while live updates are degraded to polling — show the banner. */
  interrupted: boolean;
  /** Every event received, in seq order (deduplicated by seq). */
  events: LiveEvent[];
  lastSeq: number;
  /** Latest known state (from events or polling). */
  state: ScanState | null;
  /** Error code / message from the latest failing state event. */
  errorCode: string | null;
  errorMessage: string | null;
  /** analyzer → progress. */
  progress: Record<string, { done: number; total: number }>;
  /** Findings streamed so far (summaries; fetch details via useFinding). */
  findings: FindingSummary[];
  /** Latest cumulative cost event. */
  cost: Extract<ScanEvent, { type: 'cost' }> | null;
  /** Reuse stats when results come from cache / an incremental rescan. */
  cache: Extract<ScanEvent, { type: 'cache' }> | null;
  warnings: Array<Extract<ScanEvent, { type: 'warning' }>>;
  summary: Extract<ScanEvent, { type: 'summary' }> | null;
  done: boolean;
};

const INITIAL: ScanEventsState = {
  connection: 'idle', interrupted: false, events: [], lastSeq: 0, state: null, errorCode: null, errorMessage: null,
  progress: {}, findings: [], cost: null, cache: null, warnings: [], summary: null, done: false,
};

type Action =
  | { type: 'reset' }
  | { type: 'connection'; connection: ConnectionStatus; interrupted?: boolean }
  | { type: 'event'; event: LiveEvent }
  | { type: 'polled'; scan: ScanDto };

function reducer(s: ScanEventsState, a: Action): ScanEventsState {
  switch (a.type) {
    case 'reset':
      return INITIAL;
    case 'connection':
      return { ...s, connection: a.connection, interrupted: a.interrupted ?? s.interrupted };
    case 'polled': {
      const terminal = isTerminalState(a.scan.state);
      return {
        ...s, state: a.scan.state, errorCode: a.scan.errorCode, errorMessage: a.scan.errorMessage,
        done: s.done || terminal, connection: terminal ? 'closed' : s.connection,
      };
    }
    case 'event': {
      const e = a.event;
      if (e.seq <= s.lastSeq) return s; // replay overlap
      const next: ScanEventsState = { ...s, events: [...s.events, e], lastSeq: e.seq };
      switch (e.type) {
        case 'state':
          next.state = e.state;
          if (e.errorCode) next.errorCode = e.errorCode;
          if (e.message) next.errorMessage = e.message;
          break;
        case 'progress':
          next.progress = { ...s.progress, [e.analyzer]: { done: e.done, total: e.total } };
          break;
        case 'finding':
          next.findings = [...s.findings, e.finding];
          break;
        case 'cost':
          next.cost = e;
          break;
        case 'cache':
          next.cache = e;
          break;
        case 'warning':
          next.warnings = [...s.warnings, e];
          break;
        case 'summary':
          next.summary = e;
          break;
        case 'done':
          next.state = e.state;
          next.done = true;
          break;
      }
      return next;
    }
  }
}

const EVENT_TYPES: ReadonlyArray<ScanEvent['type']> = ['state', 'progress', 'finding', 'cache', 'cost', 'warning', 'summary', 'done'];
const MAX_FAILED_RECONNECTS = 3;
const POLL_MS = 3_000;
const backoffMs = (attempt: number) => Math.min(1_000 * 2 ** attempt, 8_000);

export type UseScanEventsResult = ScanEventsState & {
  /** Leave polling mode and try the live stream again. */
  retryLive: () => void;
};

export function useScanEvents(scanId: string | undefined, opts: { enabled?: boolean } = {}): UseScanEventsResult {
  const enabled = (opts.enabled ?? true) && !!scanId;
  const qc = useQueryClient();
  const [state, dispatch] = useReducer(reducer, INITIAL);
  const [generation, bump] = useReducer((n: number) => n + 1, 0);

  // Mutable connection bookkeeping (survives re-renders, reset per scan/generation).
  const lastSeqRef = useRef(0);
  const doneRef = useRef(false);

  useEffect(() => {
    dispatch({ type: 'reset' });
    lastSeqRef.current = 0;
    doneRef.current = false;
  }, [scanId]);

  useEffect(() => {
    if (!enabled || !scanId) return;
    let disposed = false;
    let es: EventSource | null = null;
    let failures = 0;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;

    const finish = () => {
      if (doneRef.current) return;
      doneRef.current = true;
      es?.close();
      if (pollTimer) clearInterval(pollTimer);
      dispatch({ type: 'connection', connection: 'closed', interrupted: false });
      void invalidateScanResults(qc, scanId);
      void qc.invalidateQueries({ queryKey: qk.repos });
    };

    const applyState = (next: ScanState) => {
      qc.setQueryData<ScanDto>(qk.scan(scanId), (old) => (old ? { ...old, state: next } : old));
    };

    // ScanDto only carries a running total (`costUsd`), no token breakdown, so only that is mirrored
    // here; the header's cost readout then tracks the live meter instead of waiting for a re-fetch.
    const applyCost = (e: Extract<ScanEvent, { type: 'cost' }>) => {
      qc.setQueryData<ScanDto>(qk.scan(scanId), (old) => (old ? { ...old, costUsd: e.usd } : old));
    };

    const onMessage = (ev: MessageEvent<string>) => {
      let data: LiveEvent;
      try {
        data = JSON.parse(ev.data) as LiveEvent;
      } catch {
        return;
      }
      const seq = Number(ev.lastEventId) || data.seq;
      if (!seq || seq <= lastSeqRef.current) return;
      lastSeqRef.current = seq;
      dispatch({ type: 'event', event: { ...data, seq } });
      if (data.type === 'state') applyState(data.state);
      if (data.type === 'cost') applyCost(data);
      if (data.type === 'summary') void qc.invalidateQueries({ queryKey: qk.summary(scanId) });
      if (data.type === 'done') {
        applyState(data.state);
        finish();
      }
    };

    const startPolling = () => {
      es?.close();
      es = null;
      dispatch({ type: 'connection', connection: 'polling', interrupted: true });
      const poll = async () => {
        try {
          const scan = await api.getScan(scanId);
          if (disposed) return;
          qc.setQueryData(qk.scan(scanId), scan);
          dispatch({ type: 'polled', scan });
          if (isTerminalState(scan.state)) finish();
        } catch {
          /* keep polling; the banner already says updates are degraded */
        }
      };
      void poll();
      pollTimer = setInterval(() => void poll(), POLL_MS);
    };

    const connect = () => {
      if (disposed || doneRef.current) return;
      dispatch({ type: 'connection', connection: failures === 0 && lastSeqRef.current === 0 ? 'connecting' : 'reconnecting' });
      const source = new EventSource(eventsUrl(scanId, lastSeqRef.current));
      es = source;
      source.onopen = () => {
        failures = 0;
        dispatch({ type: 'connection', connection: 'open', interrupted: false });
      };
      for (const t of EVENT_TYPES) source.addEventListener(t, onMessage as EventListener);
      // Server is restarting: reconnect right away (not a failure).
      source.addEventListener('reconnect', () => {
        source.close();
        timer = setTimeout(connect, 500);
      });
      source.onerror = () => {
        // We drive reconnects ourselves so we control backoff, `after=` and the failure budget.
        source.close();
        if (disposed || doneRef.current) return;
        void (async () => {
          // The stream also closes when a finished scan's replay ends — that's not a failure.
          try {
            const scan = await api.getScan(scanId);
            if (disposed) return;
            qc.setQueryData(qk.scan(scanId), scan);
            if (isTerminalState(scan.state)) {
              dispatch({ type: 'polled', scan });
              finish();
              return;
            }
          } catch {
            /* API unreachable: counts as a failed attempt below */
          }
          if (disposed) return;
          if (failures >= MAX_FAILED_RECONNECTS) {
            startPolling();
            return;
          }
          const delay = backoffMs(failures);
          failures += 1;
          dispatch({ type: 'connection', connection: 'reconnecting' });
          timer = setTimeout(connect, delay);
        })();
      };
    };

    connect();

    return () => {
      disposed = true;
      es?.close();
      if (timer) clearTimeout(timer);
      if (pollTimer) clearInterval(pollTimer);
    };
  }, [enabled, scanId, qc, generation]);

  const retryLive = useCallback(() => {
    if (doneRef.current) return;
    bump();
  }, []);

  return { ...state, retryLive };
}
