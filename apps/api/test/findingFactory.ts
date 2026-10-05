import type { Finding } from '@vibesec/shared';

let seq = 0;

/** Minimal valid Finding for VERIFYING tests; `file`/`line(s)` shortcuts set the location. */
export function mkFinding(o: Partial<Finding> & { file?: string; line?: number; endLine?: number } = {}): Finding {
  seq += 1;
  const { file, line, endLine, ...rest } = o;
  const start = line ?? 10;
  return {
    id: `f-${String(seq).padStart(4, '0')}`,
    scanId: 'scan-1',
    fingerprint: `fp-${seq}`,
    category: 'sast',
    ruleId: 'sast/sql-injection',
    cwe: 'CWE-89',
    title: 'SQL injection',
    baseSeverity: 'high',
    riskScore: 70,
    severity: 'high',
    riskFactors: [],
    confidence: 'high',
    location: { file: file ?? 'src/a.ts', startLine: start, endLine: endLine ?? start, snippet: 'db.query(x)', permalink: 'https://example.com' },
    explanation: 'The query is built from request input.',
    impact: 'Data theft.',
    remediation: { summary: 'Use parameters.' },
    scanStatus: 'new',
    producedBy: ['sast:llm'],
    ...rest,
  };
}
