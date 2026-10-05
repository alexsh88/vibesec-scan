// Secret detection rules: pure, synchronous, no network/LLM. `detectSecrets` scans a chunk of
// text and returns every credential-looking match it finds, alongside enough metadata
// (position, redacted form, paired AWS secret, JWT role) for the caller to build a finding.
//
// SECURITY: `SecretMatch.value` (and `pairedSecret`) carry the *raw* secret. They exist only so
// an in-process verifier can make a live API call to confirm validity; callers must never log,
// persist, or put them in an error message. Only `redact(value)` / `secretHash(value)` may leave
// this layer (see scanText.ts, which builds the public `SecretCandidate` from a `SecretMatch`).

import { createHash } from 'node:crypto';

export type SecretType =
  | 'github-token' | 'aws-access-key' | 'stripe-secret-key' | 'stripe-restricted-key' | 'stripe-test-key'
  | 'slack-token' | 'slack-webhook' | 'openai-api-key' | 'anthropic-api-key' | 'google-api-key'
  | 'sendgrid-api-key' | 'twilio-api-key' | 'private-key' | 'jwt' | 'supabase-service-role'
  | 'database-url' | 'generic-secret';

export type SecretMatch = {
  type: SecretType;
  /** Raw secret value — in-memory only, never logged/persisted. See file header. */
  value: string;
  line: number;
  endLine: number;
  startCol: number;
  /** AWS only: a 40-char secret access key found within +/-5 lines (paired for STS verification). */
  pairedSecret?: string;
  /** JWT only: decoded payload `role` claim (e.g. Supabase anon/service_role). */
  jwtRole?: string;
};

const PLACEHOLDER_SUBSTRINGS = [
  'your_', 'your-', '<', '>', 'xxx', 'changeme', 'change_me', 'example', 'placeholder', 'dummy', 'sample',
  'redacted', 'todo', 'fixme', 'insert', 'replace', '${', '{{', '%s', 'process.env', 'os.environ',
  'import.meta.env', 'getenv',
];

const KNOWN_DOC_KEYS = new Set(['AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY']);

/** True when a run of the same character covers most of the string (e.g. `xxxxxxxx`, `00000000`). */
function hasDominantRepeatedRun(value: string): boolean {
  if (value.length === 0) return false;
  let runChar = value.charAt(0);
  let runLen = 1;
  let maxRun = 1;
  for (let i = 1; i < value.length; i++) {
    const ch = value.charAt(i);
    if (ch === runChar) {
      runLen++;
    } else {
      runChar = ch;
      runLen = 1;
    }
    if (runLen > maxRun) maxRun = runLen;
  }
  return maxRun >= 6 && maxRun >= value.length * 0.5;
}

export function isPlaceholder(value: string): boolean {
  if (KNOWN_DOC_KEYS.has(value)) return true;
  const lower = value.toLowerCase();
  for (const needle of PLACEHOLDER_SUBSTRINGS) {
    if (lower.includes(needle.toLowerCase())) return true;
  }
  return hasDominantRepeatedRun(value);
}

export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const PEM_REDACTED = '-----BEGIN … PRIVATE KEY-----';

export function redact(value: string): string {
  if (value.startsWith('-----BEGIN')) return PEM_REDACTED;
  if (value.length < 12) return value.length <= 2 ? value : value.slice(0, 2) + '…';
  return value.slice(0, 4) + '…' + value.slice(-4);
}

export function secretHash(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

const CLIENT_EXPOSED_PREFIXES = ['NEXT_PUBLIC_', 'VITE_', 'REACT_APP_', 'EXPO_PUBLIC_', 'PUBLIC_', 'NUXT_PUBLIC_'];

export function isClientExposed(file: string, lineText: string): boolean {
  if (CLIENT_EXPOSED_PREFIXES.some((p) => lineText.includes(p))) return true;
  const segments = file.split('/');
  if (segments.includes('public') || segments.includes('static')) return true;
  if (/\.html?$/i.test(file)) return true;
  return false;
}

// --- line/column bookkeeping --------------------------------------------------------------

/** Start offset of every line in `text` (index 0 => line 1). */
function buildLineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charAt(i) === '\n') starts.push(i + 1);
  }
  return starts;
}

function locate(starts: readonly number[], offset: number): { line: number; col: number } {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid]! <= offset) lo = mid; else hi = mid - 1;
  }
  return { line: lo + 1, col: offset - starts[lo]! + 1 };
}

// --- raw, offset-based matches (before line/col projection) --------------------------------

type RawMatch = { type: SecretType; start: number; value: string; jwtRole?: string };

function matchGithub(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(/\b(gh[pousr]_[A-Za-z0-9]{36,255})\b/g)) {
    if (!isPlaceholder(m[0])) out.push({ type: 'github-token', start: m.index!, value: m[0] });
  }
  for (const m of text.matchAll(/\bgithub_pat_[A-Za-z0-9_]{60,255}\b/g)) {
    if (!isPlaceholder(m[0])) out.push({ type: 'github-token', start: m.index!, value: m[0] });
  }
  return out;
}

function matchAwsAccessKeys(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(/\b((?:AKIA|ASIA)[A-Z0-9]{16})\b/g)) {
    if (!isPlaceholder(m[0])) out.push({ type: 'aws-access-key', start: m.index!, value: m[0] });
  }
  return out;
}

function matchStripe(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  const rules: Array<[RegExp, SecretType]> = [
    [/\bsk_live_[A-Za-z0-9]{24,}\b/g, 'stripe-secret-key'],
    [/\brk_live_[A-Za-z0-9]{24,}\b/g, 'stripe-restricted-key'],
    [/\bsk_test_[A-Za-z0-9]{24,}\b/g, 'stripe-test-key'],
  ];
  for (const [re, type] of rules) {
    for (const m of text.matchAll(re)) {
      if (!isPlaceholder(m[0])) out.push({ type, start: m.index!, value: m[0] });
    }
  }
  return out;
}

function matchSlack(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g)) {
    if (!isPlaceholder(m[0])) out.push({ type: 'slack-token', start: m.index!, value: m[0] });
  }
  for (const m of text.matchAll(/https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g)) {
    if (!isPlaceholder(m[0])) out.push({ type: 'slack-webhook', start: m.index!, value: m[0] });
  }
  return out;
}

function matchOpenAiAndAnthropic(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  const seenOpenAi = new Set<number>();
  for (const m of text.matchAll(/\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b/g)) {
    if (isPlaceholder(m[0])) continue;
    seenOpenAi.add(m.index!);
    out.push({ type: 'openai-api-key', start: m.index!, value: m[0] });
  }
  for (const m of text.matchAll(/\bsk-proj-[A-Za-z0-9_-]{40,}\b/g)) {
    if (isPlaceholder(m[0]) || seenOpenAi.has(m.index!)) continue;
    out.push({ type: 'openai-api-key', start: m.index!, value: m[0] });
  }
  for (const m of text.matchAll(/\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b/g)) {
    if (!isPlaceholder(m[0])) out.push({ type: 'anthropic-api-key', start: m.index!, value: m[0] });
  }
  return out;
}

function matchGoogle(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(/\bAIza[0-9A-Za-z_-]{35}\b/g)) {
    if (!isPlaceholder(m[0])) out.push({ type: 'google-api-key', start: m.index!, value: m[0] });
  }
  return out;
}

function matchSendgrid(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(/\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g)) {
    if (!isPlaceholder(m[0])) out.push({ type: 'sendgrid-api-key', start: m.index!, value: m[0] });
  }
  return out;
}

function matchTwilio(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(/\bSK[0-9a-fA-F]{32}\b/g)) {
    if (!isPlaceholder(m[0])) out.push({ type: 'twilio-api-key', start: m.index!, value: m[0] });
  }
  return out;
}

const PEM_BEGIN_RE = /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/g;
const PEM_END_RE = /-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/g;

function matchPrivateKey(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  const ends = [...text.matchAll(PEM_END_RE)].map((m) => ({ start: m.index!, end: m.index! + m[0].length }));
  let endIdx = 0;
  for (const begin of text.matchAll(PEM_BEGIN_RE)) {
    const beginStart = begin.index!;
    const beginEnd = beginStart + begin[0].length;
    while (endIdx < ends.length && ends[endIdx]!.start < beginEnd) endIdx++;
    const candidate = ends[endIdx];
    if (!candidate) continue; // unterminated block — skip, nothing clean to report
    const value = text.slice(beginStart, candidate.end);
    const body = text.slice(beginEnd, candidate.start).trim();
    endIdx++;
    if (body.length < 40) continue; // docs/examples
    if (isPlaceholder(value)) continue;
    out.push({ type: 'private-key', start: beginStart, value });
  }
  return out;
}

function decodeJwtRole(token: string): string | undefined {
  const payloadPart = token.split('.')[1];
  if (!payloadPart) return undefined;
  try {
    const padded = payloadPart.replace(/-/g, '+').replace(/_/g, '/');
    const pad = padded.length % 4 === 0 ? '' : '='.repeat(4 - (padded.length % 4));
    const json = Buffer.from(padded + pad, 'base64').toString('utf8');
    const obj = JSON.parse(json) as Record<string, unknown>;
    return typeof obj['role'] === 'string' ? obj['role'] : undefined;
  } catch {
    return undefined;
  }
}

function matchJwt(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  // No trailing \b: the signature alphabet includes '-', a non-word char, so a trailing \b
  // would force the match to backtrack off trailing dashes and silently truncate the token.
  for (const m of text.matchAll(/\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g)) {
    const value = m[0];
    if (isPlaceholder(value)) continue;
    const role = decodeJwtRole(value);
    if (role === 'anon' || role === 'authenticated') continue; // public by design
    if (role === 'service_role') {
      out.push({ type: 'supabase-service-role', start: m.index!, value, jwtRole: role });
    } else if (role !== undefined) {
      out.push({ type: 'jwt', start: m.index!, value, jwtRole: role });
    } else {
      out.push({ type: 'jwt', start: m.index!, value });
    }
  }
  return out;
}

const DB_PLACEHOLDER_PASSWORDS = new Set(['password', 'pass', 'postgres', 'root', 'admin', 'mysql', 'guest', 'changeme']);

function isDbPlaceholderPassword(password: string): boolean {
  if (isPlaceholder(password)) return true;
  if (DB_PLACEHOLDER_PASSWORDS.has(password.toLowerCase())) return true;
  if (/^\*+$/.test(password)) return true;
  return false;
}

function matchDatabaseUrl(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  const re = /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps):\/\/[^\s:'"@/]+:([^\s'"@/]+)@[^\s'"]+/g;
  for (const m of text.matchAll(re)) {
    const password = m[1]!;
    if (isDbPlaceholderPassword(password)) continue;
    out.push({ type: 'database-url', start: m.index!, value: m[0] });
  }
  return out;
}

function passGenericChecks(value: string): boolean {
  return !isPlaceholder(value) && shannonEntropy(value) >= 3.5;
}

const GENERIC_QUOTED_RE =
  /\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*(['"])([^'"\s]{8,})\1/gi;
const GENERIC_ENV_RE = /^[ \t]*[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|APIKEY)[A-Z0-9_]*[ \t]*=[ \t]*([^\s#'"]{8,})/gm;

function matchGenericSecret(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(GENERIC_QUOTED_RE)) {
    const value = m[2]!;
    if (!passGenericChecks(value)) continue;
    out.push({ type: 'generic-secret', start: m.index! + m[0].length - 1 - value.length, value });
  }
  for (const m of text.matchAll(GENERIC_ENV_RE)) {
    const value = m[1]!;
    if (!passGenericChecks(value)) continue;
    out.push({ type: 'generic-secret', start: m.index! + m[0].length - value.length, value });
  }
  return out;
}

// --- AWS access-key / secret-key pairing ----------------------------------------------------

const AWS_CANDIDATE_SECRET_RE = /(?:['"]([A-Za-z0-9/+]{40})['"]|[:=]\s*([A-Za-z0-9/+]{40})(?=\s|$))/g;

function pairAwsSecrets(text: string, lineStarts: readonly number[], matches: readonly RawMatch[]): Map<RawMatch, string> {
  const result = new Map<RawMatch, string>();
  const awsMatches = matches.filter((m) => m.type === 'aws-access-key');
  if (awsMatches.length === 0) return result;

  const lines = text.split('\n');
  const candidates: { line: number; value: string }[] = [];
  for (const m of text.matchAll(AWS_CANDIDATE_SECRET_RE)) {
    const value = m[1] ?? m[2];
    if (!value) continue;
    candidates.push({ line: locate(lineStarts, m.index!).line, value });
  }

  for (const aws of awsMatches) {
    const awsLine = locate(lineStarts, aws.start).line;
    for (const c of candidates) {
      if (Math.abs(c.line - awsLine) > 5) continue;
      const lineText = lines[c.line - 1] ?? '';
      if (/secret|aws/i.test(lineText)) {
        result.set(aws, c.value);
        break;
      }
    }
  }
  return result;
}

// --- public entry point ----------------------------------------------------------------------

function spansOverlap(aStart: number, aEnd: number, bStart: number, bEnd: number): boolean {
  return aStart < bEnd && bStart < aEnd;
}

export function detectSecrets(text: string): SecretMatch[] {
  const lineStarts = buildLineStarts(text);

  const primary: RawMatch[] = [
    ...matchGithub(text),
    ...matchAwsAccessKeys(text),
    ...matchStripe(text),
    ...matchSlack(text),
    ...matchOpenAiAndAnthropic(text),
    ...matchGoogle(text),
    ...matchSendgrid(text),
    ...matchTwilio(text),
    ...matchPrivateKey(text),
    ...matchJwt(text),
    ...matchDatabaseUrl(text),
  ];

  const generic = matchGenericSecret(text).filter((g) => {
    const gEnd = g.start + g.value.length;
    return !primary.some((p) => spansOverlap(g.start, gEnd, p.start, p.start + p.value.length));
  });

  const all = [...primary, ...generic];
  const pairs = pairAwsSecrets(text, lineStarts, all);

  const result: SecretMatch[] = all.map((m) => {
    const startLoc = locate(lineStarts, m.start);
    const endLoc = locate(lineStarts, m.start + m.value.length - 1);
    const match: SecretMatch = {
      type: m.type,
      value: m.value,
      line: startLoc.line,
      endLine: endLoc.line,
      startCol: startLoc.col,
    };
    if (m.jwtRole !== undefined) match.jwtRole = m.jwtRole;
    const paired = pairs.get(m);
    if (paired !== undefined) match.pairedSecret = paired;
    return match;
  });

  return result.sort((a, b) => a.line - b.line || a.startCol - b.startCol);
}
