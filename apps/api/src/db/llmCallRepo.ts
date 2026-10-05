import { randomUUID } from 'node:crypto';
import type { Db } from './database';

export type LlmCallInput = {
  scanId: string | null; analyzer: string; purpose: string; model: string; promptVersion: string; inputHash: string;
  inputTokens: number; outputTokens: number; cacheReadTokens: number; cacheWriteTokens: number; costUsd: number;
  latencyMs: number; stopReason: string | null; attempt: number; errorCode: string | null;
};

export type LlmTotals = {
  calls: number; failedCalls: number; inputTokens: number; outputTokens: number;
  cacheReadTokens: number; cacheWriteTokens: number; costUsd: number;
};

const SUMS = `COUNT(*) AS calls, COALESCE(SUM(error_code IS NOT NULL), 0) AS failedCalls,
  COALESCE(SUM(input_tokens), 0) AS inputTokens, COALESCE(SUM(output_tokens), 0) AS outputTokens,
  COALESCE(SUM(cache_read_tokens), 0) AS cacheReadTokens, COALESCE(SUM(cache_write_tokens), 0) AS cacheWriteTokens,
  COALESCE(SUM(cost_usd), 0) AS costUsd`;

const round = (t: LlmTotals): LlmTotals => ({ ...t, costUsd: Math.round(t.costUsd * 1e9) / 1e9 });

export class LlmCallRepo {
  constructor(private readonly db: Db, private readonly now: () => string = () => new Date().toISOString()) {}

  insert(c: LlmCallInput): string {
    const id = randomUUID();
    this.db.prepare(
      `INSERT INTO llm_calls (id, scan_id, analyzer, purpose, model, prompt_version, input_hash, input_tokens, output_tokens,
         cache_read_tokens, cache_write_tokens, cost_usd, latency_ms, stop_reason, attempt, error_code, at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, c.scanId, c.analyzer, c.purpose, c.model, c.promptVersion, c.inputHash, c.inputTokens, c.outputTokens,
      c.cacheReadTokens, c.cacheWriteTokens, c.costUsd, c.latencyMs, c.stopReason, c.attempt, c.errorCode, this.now());
    return id;
  }

  totals(scanId: string): LlmTotals {
    return round(this.db.prepare(`SELECT ${SUMS} FROM llm_calls WHERE scan_id = ?`).get(scanId) as LlmTotals);
  }

  byAnalyzer(scanId: string): Array<LlmTotals & { analyzer: string }> {
    const rows = this.db.prepare(`SELECT analyzer, ${SUMS} FROM llm_calls WHERE scan_id = ? GROUP BY analyzer ORDER BY analyzer`)
      .all(scanId) as Array<LlmTotals & { analyzer: string }>;
    return rows.map((r) => ({ ...r, ...round(r) }));
  }
}
