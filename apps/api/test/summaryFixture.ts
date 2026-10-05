import type { ScanSummary } from '@vibesec/shared';

/** A valid ScanSummary for repo/route tests. */
export const sampleSummary = (scanId: string, grade: ScanSummary['riskGrade'] = 'C'): ScanSummary => ({
  scanId, riskGrade: grade, headline: 'One high-risk issue needs attention', overview: 'The scan found one issue. Fix it first.',
  topRisks: [{ title: 'SQL injection', whyItMatters: 'Attackers can read the database.', findingIds: ['f1'], severity: 'high' }],
  nextActions: [{ title: 'Parameterize the query', detail: 'Use bound parameters.', effort: 'hours', findingIds: ['f1'] }],
  positiveObservations: ['No hard-coded credentials were found.'],
  stats: {
    bySeverity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    byCategory: { secret: 0, sast: 1, taint: 0, quality: 0, dependency: 0, config: 0 },
    total: 1,
  },
  generatedBy: 'llm', model: 'claude-opus-5',
});
