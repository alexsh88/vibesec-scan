// Test helper: the post-ANALYZING dependencies of createScanPipeline (VERIFYING, SCORING, SYNTHESIZING),
// for tests that wire a pipeline by hand. No cacheKeys: the full-scan cache / incremental rescans stay off
// unless a test passes its own.
import type { AuditLogger } from '../src/audit/AuditLogger';
import { CoverageRepo } from '../src/db/coverageRepo';
import type { Db } from '../src/db/database';
import type { FindingRepo } from '../src/db/findingRepo';
import { FixPlanRepo } from '../src/db/fixPlanRepo';
import { LlmCallRepo } from '../src/db/llmCallRepo';
import type { ScanRepo } from '../src/db/scanRepo';
import { SummaryRepo } from '../src/db/summaryRepo';
import type { LlmClient } from '../src/llm/LlmClient';
import { SuppressionRepo } from '../src/suppressions/suppressionRepo';
import { SuppressionService } from '../src/suppressions/suppressionService';

export function pipelineDeps(input: {
  db: Db; scans: ScanRepo; findings: FindingRepo; audit: AuditLogger; llm: Pick<LlmClient, 'structured'>;
  fixPlans?: FixPlanRepo; summaries?: SummaryRepo; llmCalls?: LlmCallRepo;
}) {
  return {
    coverage: new CoverageRepo(input.db),
    fixPlans: input.fixPlans ?? new FixPlanRepo(input.db),
    summaries: input.summaries ?? new SummaryRepo(input.db),
    llmCalls: input.llmCalls ?? new LlmCallRepo(input.db),
    llm: input.llm,
    suppressions: new SuppressionService(new SuppressionRepo(input.db), input.findings, input.scans, input.audit),
    atomically: <T>(fn: () => T): T => input.db.transaction(fn)(),
  };
}
