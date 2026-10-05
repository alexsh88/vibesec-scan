import { describe, expect, it } from 'vitest';
import { ScanOptionsSchema } from '@vibesec/shared';
import { LlmCallRepo, type LlmCallInput } from '../src/db/llmCallRepo';
import { ScanRepo } from '../src/db/scanRepo';
import { memoryDb } from './helpers';

function setup() {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const scanId = scans.insertScan({
    repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: 'h', idempotencyKey: null, hasAuth: false,
  }).id;
  return { scans, scanId, calls: new LlmCallRepo(db) };
}

const call = (over: Partial<LlmCallInput> = {}): LlmCallInput => ({
  scanId: null, analyzer: 'sast', purpose: 'review-file', model: 'claude-sonnet-5', promptVersion: 'v1', inputHash: 'abc',
  inputTokens: 100, outputTokens: 20, cacheReadTokens: 50, cacheWriteTokens: 0, costUsd: 0.001,
  latencyMs: 1200, stopReason: 'end_turn', attempt: 0, errorCode: null, ...over,
});

describe('LlmCallRepo', () => {
  it('inserts calls and aggregates totals per scan and per analyzer', () => {
    const { calls, scanId } = setup();
    const id = calls.insert(call({ scanId }));
    expect(id).toMatch(/[0-9a-f-]{36}/);
    calls.insert(call({ scanId, analyzer: 'triage', model: 'claude-haiku-4-5', costUsd: 0.0002 }));
    calls.insert(call({ scanId, errorCode: 'LLM_UNAVAILABLE', inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, costUsd: 0, stopReason: null }));
    calls.insert(call({ scanId: null }));

    expect(calls.totals(scanId)).toEqual({
      calls: 3, failedCalls: 1, inputTokens: 200, outputTokens: 40, cacheReadTokens: 100, cacheWriteTokens: 0, costUsd: 0.0012,
    });
    expect(calls.byAnalyzer(scanId)).toEqual([
      { analyzer: 'sast', calls: 2, failedCalls: 1, inputTokens: 100, outputTokens: 20, cacheReadTokens: 50, cacheWriteTokens: 0, costUsd: 0.001 },
      { analyzer: 'triage', calls: 1, failedCalls: 0, inputTokens: 100, outputTokens: 20, cacheReadTokens: 50, cacheWriteTokens: 0, costUsd: 0.0002 },
    ]);
  });

  it('returns zero totals for a scan without calls', () => {
    const { calls, scanId } = setup();
    expect(calls.totals(scanId)).toEqual({ calls: 0, failedCalls: 0, inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0, costUsd: 0 });
  });
});

describe('ScanRepo.addCost', () => {
  it('accumulates cost atomically', () => {
    const { scans, scanId } = setup();
    scans.addCost(scanId, 0.25);
    scans.addCost(scanId, 0.5);
    expect(scans.getDto(scanId)?.costUsd).toBeCloseTo(0.75, 9);
  });
});
