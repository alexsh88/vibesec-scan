// Deterministic env-exposure security rules. Pure, synchronous, no network/LLM.

import { isPlaceholder } from '../../credentials/rules';
import type { RawCodeIssue } from '../types';

const MAX_LINE = 16 * 1024;
const SNIPPET_LIMIT = 300;

export function isEnvFile(path: string): boolean {
  const base = path.split('/').pop() ?? path;
  return base === '.env' || base.startsWith('.env.');
}

const TEMPLATE_SUFFIX_RE = /\.(example|sample|template)$/i;

export function isEnvTemplateFile(path: string): boolean {
  return TEMPLATE_SUFFIX_RE.test(path);
}

const CODE_FILE_RE = /\.(?:mjs|cjs|jsx?|tsx?)$/i;

function isCodeFile(path: string): boolean {
  return CODE_FILE_RE.test(path);
}

function clamp(line: string): string {
  return line.length > MAX_LINE ? line.slice(0, MAX_LINE) : line;
}

function snippetOf(line: string | undefined): string {
  const l = (line ?? '').trim();
  return l.length > SNIPPET_LIMIT ? l.slice(0, SNIPPET_LIMIT) : l;
}

function makeIssue(opts: {
  ruleId: string;
  title: string;
  severity: RawCodeIssue['severity'];
  cwe?: string;
  file: string;
  line: number;
  snippet: string;
  explanation: string;
  impact: string;
  remediation: string;
}): RawCodeIssue {
  const issue: RawCodeIssue = {
    ruleId: opts.ruleId,
    title: opts.title,
    severity: opts.severity,
    confidence: 'high',
    file: opts.file,
    startLine: opts.line,
    endLine: opts.line,
    snippet: opts.snippet,
    explanation: opts.explanation,
    impact: opts.impact,
    remediation: opts.remediation,
  };
  if (opts.cwe) issue.cwe = opts.cwe;
  return issue;
}

function stripQuotes(value: string): string {
  const v = value.trim();
  if (v.length >= 2 && ((v[0] === '"' && v[v.length - 1] === '"') || (v[0] === "'" && v[v.length - 1] === "'"))) {
    return v.slice(1, -1);
  }
  return v;
}

function redactLine(rawLine: string, value: string): string {
  if (value === '' || !rawLine.includes(value)) return snippetOf(rawLine);
  const redacted = value.length <= 2 ? '…' : value.slice(0, 2) + '…';
  return snippetOf(rawLine.replace(value, redacted));
}

type EnvAssignment = { name: string; value: string; line: number; rawLine: string };

const ENV_LINE_RE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/;

function parseEnvAssignments(text: string): EnvAssignment[] {
  const out: EnvAssignment[] = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const rawLine = clamp((lines[i] ?? '').replace(/\r$/, ''));
    const trimmed = rawLine.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;
    const m = ENV_LINE_RE.exec(rawLine);
    if (!m) continue;
    out.push({ name: m[1]!, value: stripQuotes(m[2] ?? ''), line: i + 1, rawLine });
  }
  return out;
}

// --- rule: config/env-file-committed ----------------------------------------------------------

export function envFileCommittedIssues(files: readonly { path: string; text: string }[]): RawCodeIssue[] {
  const issues: RawCodeIssue[] = [];
  for (const file of files) {
    if (!isEnvFile(file.path) || isEnvTemplateFile(file.path)) continue;
    const assignments = parseEnvAssignments(file.text);
    const real = assignments.filter((a) => a.value !== '' && !isPlaceholder(a.value));
    if (real.length === 0) continue;
    const first = real[0]!;
    issues.push(
      makeIssue({
        ruleId: 'config/env-file-committed',
        title: 'Committed .env file with real-looking values',
        severity: 'high',
        cwe: 'CWE-798',
        file: file.path,
        line: first.line,
        snippet: redactLine(first.rawLine, first.value),
        explanation: `This tracked env file has ${real.length} non-empty, non-placeholder assignment${real.length === 1 ? '' : 's'} (e.g. '${first.name}').`,
        impact: 'Credentials committed to version control stay in history forever and are visible to anyone with repo access.',
        remediation: 'Remove this file from version control, rotate any real credentials it held, and commit a .env.example with placeholders instead.',
      }),
    );
  }
  return issues;
}

// --- rule: config/client-exposed-credential -----------------------------------------------------

const PUBLIC_PREFIX_RE = /^(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|PUBLIC_)/;
const CRED_NAME_RE = /SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|TOKEN|API_KEY/i;
const SAFE_SUFFIX_RE = /(?:ANON_KEY|PUBLISHABLE_KEY|SITE_KEY|MEASUREMENT_ID)$/i;

export function isClientExposedCredentialName(name: string): boolean {
  if (!PUBLIC_PREFIX_RE.test(name)) return false;
  if (SAFE_SUFFIX_RE.test(name)) return false;
  return CRED_NAME_RE.test(name);
}

function clientExposedIssue(file: string, line: number, name: string, rawLine: string): RawCodeIssue {
  return makeIssue({
    ruleId: 'config/client-exposed-credential',
    title: 'Credential-shaped name exposed to the client bundle',
    severity: 'high',
    cwe: 'CWE-200',
    file,
    line,
    snippet: snippetOf(rawLine),
    explanation: `'${name}' uses a public/client-exposed prefix but its name suggests a real credential.`,
    impact: 'Client-exposed env vars are inlined into the browser bundle at build time — anyone can read them from the shipped JS.',
    remediation: 'Rename it without the public prefix and read it only on the server, or confirm the value is safe to expose publicly.',
  });
}

const PROCESS_ENV_RE = /\bprocess\.env\.([A-Za-z0-9_]{1,128})\b/g;
const IMPORT_META_ENV_RE = /\bimport\.meta\.env\.([A-Za-z0-9_]{1,128})\b/g;

export function clientExposedCredentialIssues(files: readonly { path: string; text: string }[]): RawCodeIssue[] {
  const issues: RawCodeIssue[] = [];
  for (const file of files) {
    if (isEnvFile(file.path)) {
      for (const a of parseEnvAssignments(file.text)) {
        if (isClientExposedCredentialName(a.name)) issues.push(clientExposedIssue(file.path, a.line, a.name, a.rawLine));
      }
      continue;
    }
    if (!isCodeFile(file.path)) continue;
    const lines = file.text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const rawLine = clamp((lines[i] ?? '').replace(/\r$/, ''));
      for (const re of [PROCESS_ENV_RE, IMPORT_META_ENV_RE]) {
        re.lastIndex = 0;
        let match = re.exec(rawLine);
        while (match !== null) {
          const name = match[1]!;
          if (isClientExposedCredentialName(name)) issues.push(clientExposedIssue(file.path, i + 1, name, rawLine));
          match = re.exec(rawLine);
        }
      }
    }
  }
  return issues;
}

export function envExposureIssues(files: readonly { path: string; text: string }[]): RawCodeIssue[] {
  return [...envFileCommittedIssues(files), ...clientExposedCredentialIssues(files)];
}
