/**
 * Shared contracts for the Claude-driven code analyzers (P6): triage → SAST / taint agent /
 * credential hunter, plus deterministic quality and config checks.
 */

/** Haiku triage verdict for one source file. */
export type FileTriage = {
  path: string;
  /** 0 = irrelevant (types, constants), 1 = low, 2 = handles input/data, 3 = security-critical (auth, DB, exec, crypto, HTTP handlers). */
  relevance: 0 | 1 | 2 | 3;
  /** Untrusted-input sources seen in the file, e.g. "req.query.id (line 12)". */
  sources: string[];
  /** Dangerous sinks seen in the file, e.g. "db.query with string concat (line 30)". */
  sinks: string[];
  /** Short topic tags: auth, sql, exec, ssrf, crypto, llm, file-io, deserialization, cors, redirect, config, secrets… */
  securityTopics: string[];
  /** True when the file plausibly contains credentials the regex scanner could miss (feeds the credential hunter). */
  credentialRisk: boolean;
};

export type TriageResult = {
  files: Map<string, FileTriage>;
  /** Files that were not triaged (budget, failures) — downstream analyzers treat them conservatively. */
  skipped: string[];
  warnings: string[];
};

/** A trace step as produced by the taint agent (mirrors the shared TaintStepSchema). */
export type TraceStep = {
  kind: 'source' | 'propagator' | 'sanitizer' | 'sink';
  file: string;
  line: number;
  code: string;
  note: string;
};

/** Raw model-reported issue before verification/relocation and scoring. */
export type RawCodeIssue = {
  ruleId: string;          // e.g. 'sast/sql-injection', 'vibesec/missing-authz'
  title: string;
  cwe?: string;            // 'CWE-89'
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'high' | 'medium' | 'low';
  file: string;
  startLine: number;
  endLine: number;
  /** Code the model claims is at that location — verified against the real file (fuzzy) before use. */
  snippet: string;
  explanation: string;
  impact: string;
  remediation: string;
  /** Optional unified diff suggested as a fix. */
  patch?: string;
  taintTrace?: TraceStep[];
};
