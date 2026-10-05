// Credential detection rules: pure, synchronous, no network/LLM. `detectSecrets` scans a chunk of
// text and returns every credential-looking match it finds, alongside enough metadata
// (position, redacted form, paired AWS secret, JWT role) for the caller to build a finding.
//
// SECURITY: `SecretMatch.value` (and `pairedSecret`) carry the *raw* credential. They exist only so
// an in-process verifier can make a live API call to confirm validity; callers must never log,
// persist, or put them in an error message. Only `redact(value)` / `secretHash(value)` may leave
// this layer (see scanText.ts, which builds the public `SecretCandidate` from a `SecretMatch`).
//
// PERFORMANCE / ReDoS: scanned repos are attacker-controlled and files can be up to 2 MiB, so every
// rule here must run in (near-)linear time on any input:
//   - every regex quantifier that follows a literal prefix is bounded, and no rule has a prefix that
//     can recur *inside* the run its own quantifier consumes (that shape — e.g. `\beyJ[\w-]{10,}\.`
//     on "-eyJ-eyJ-eyJ…" — rescans the rest of the run from every start: quadratic);
//   - JWT and OpenAI/Anthropic keys, whose prefixes ARE inside their own alphabet, are found by
//     first taking maximal character runs with a linear regex and then parsing each run by hand;
//   - the line-oriented generic rule tests one anchored, bounded regex per line;
//   - lines longer than MAX_SCAN_LINE (16 KiB) are matched in overlapping 16 KiB windows (overlap
//     WINDOW_OVERLAP = 4 KiB) as defense in depth, so even a rule that is slower than expected is
//     bounded per window. Consequence: a single-line token longer than 4 KiB that sits on a >16 KiB
//     line may be missed (no supported token type is anywhere near that long). PEM blocks (multi-line
//     by nature) and AWS secret-candidate collection run on the whole text; both are linear.

import { createHash } from 'node:crypto';

export type SecretType =
  | 'github-token' | 'aws-access-key' | 'stripe-secret-key' | 'stripe-restricted-key' | 'stripe-test-key'
  | 'slack-token' | 'slack-webhook' | 'openai-api-key' | 'anthropic-api-key' | 'google-api-key'
  | 'sendgrid-api-key' | 'twilio-api-key' | 'private-key' | 'jwt' | 'supabase-service-role'
  | 'database-url' | 'generic-secret';

export type SecretMatch = {
  type: SecretType;
  /** Raw credential value — in-memory only, never logged/persisted. See file header. */
  value: string;
  line: number;
  endLine: number;
  startCol: number;
  /** AWS only: a 40-char secret access key found within +/-5 lines (paired for STS verification). */
  pairedSecret?: string;
  /** JWT only: decoded payload `role` claim (e.g. Supabase anon/service_role). */
  jwtRole?: string;
  /**
   * True for token-shaped values that are public by design (Supabase `anon`/`authenticated` JWTs):
   * never a finding, but still redacted from snippets. Only returned with `includeRedactOnly`.
   */
  redactOnly?: true;
};

export type DetectSecretsOptions = {
  /** Also return `redactOnly` matches (used by snippet building). Default false. */
  includeRedactOnly?: boolean;
};

// --- placeholders ------------------------------------------------------------------------------

/** Needles for *generic* values (generic-secret, database-url passwords): free-form text where a
 *  substring like "your_" or "todo" is a strong placeholder signal. Never applied to PEM bodies,
 *  JWT segments, or the random part of prefixed tokens (see isTokenPlaceholder). */
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

/** Placeholder check for free-form/generic values (generic-secret, database passwords). */
export function isPlaceholder(value: string): boolean {
  if (KNOWN_DOC_KEYS.has(value)) return true;
  const lower = value.toLowerCase();
  for (const needle of PLACEHOLDER_SUBSTRINGS) {
    if (lower.includes(needle.toLowerCase())) return true;
  }
  return hasDominantRepeatedRun(value);
}

/** Clear placeholder fills inside a token's random part: xxxxxx / XXXXXX, ****, 000000, `...`. Runs of
 *  6 (not 4): a random 36-char alnum token contains some 4-run of x/X about once in ~28k tokens. */
const TOKEN_PLACEHOLDER_RUN_RE = /[xX]{6}|\*{4}|0{6}|\.{3}/;
/** Distinctive words (>= 5 chars, so a random alphabet hits one with negligible probability). */
const TOKEN_PLACEHOLDER_WORDS = [
  'example', 'placeholder', 'changeme', 'change_me', 'redacted', 'dummy', 'sample', 'insert', 'replace',
  'your_', 'your-',
];
/** The letters of the random part are nothing but filler words ("YourGithubTokenGoesHere"). The words
 *  are chosen so that no concatenation is ambiguous (no catastrophic backtracking), and the input is
 *  length-capped before testing anyway. */
const KNOWN_WORDS_ONLY_RE =
  /^(?:your|my|the|api|access|secret|token|key|here|goes|test|fake|todo|fixme|xxx|abc|value|insert|replace|placeholder|example|sample|dummy|redacted|change|me|github|stripe|slack|openai|anthropic|google|aws|pat|live|personal|auth)+$/;

/**
 * Placeholder check for prefixed/structured tokens. Only the variable (random) part is inspected, and
 * only for unambiguous placeholder shapes — never for arbitrary short substrings ("todo", "xxx") that
 * a random alphabet produces by chance.
 */
function isTokenPlaceholder(value: string, prefixLen: number): boolean {
  if (KNOWN_DOC_KEYS.has(value)) return true;
  const variable = value.slice(prefixLen);
  if (TOKEN_PLACEHOLDER_RUN_RE.test(variable)) return true;
  const lower = variable.toLowerCase();
  if (TOKEN_PLACEHOLDER_WORDS.some((w) => lower.includes(w))) return true;
  const letters = lower.replace(/[^a-z]/g, '');
  if (letters.length >= 4 && letters.length <= 96 && KNOWN_WORDS_ONLY_RE.test(letters)) return true;
  return hasDominantRepeatedRun(variable);
}

/** PEM bodies are base64: only literal placeholder bodies (`...`, `<paste key>`, `${KEY}`) and too-short
 *  bodies count as placeholders — never a substring of the (random) base64 text. */
function isPemPlaceholder(body: string): boolean {
  const compact = body.replace(/\s+/g, '');
  if (compact.length < 40) return true;
  if (/\.\.\.|…|[<>]|\$\{|\{\{/.test(compact)) return true;
  return hasDominantRepeatedRun(compact);
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

// --- redaction ---------------------------------------------------------------------------------

const PEM_REDACTED = '-----BEGIN … PRIVATE KEY-----';

/** Non-secret, fixed prefixes of typed tokens that may stay visible in the redacted form. */
const TYPED_PREFIX_RE =
  /^(?:gh[pousr]_|github_pat_|AKIA|ASIA|sk_live_|rk_live_|sk_test_|xox[baprs]-|https:\/\/hooks\.slack\.com\/services\/|sk-ant-(?:api|admin)\d{2}-|sk-(?:proj-|svcacct-|admin-)?|AIza|SG\.|SK|eyJ)/;

/** Reveals at most 25% of the value: per side min(4, floor(len/8)); nothing below 8 chars. */
function ratioRedact(value: string): string {
  if (value.length < 8) return '…';
  const n = Math.min(4, Math.floor(value.length / 8));
  return value.slice(0, n) + '…' + value.slice(-n);
}

function prefixOnlyRedact(value: string): string {
  return value.length < 8 ? '…' : value.slice(0, 2) + '…';
}

function redactDatabaseUrl(url: string): string {
  const at = url.indexOf('@');
  const scheme = url.indexOf('://');
  if (scheme === -1 || at === -1) return ratioRedact(url);
  const colon = url.indexOf(':', scheme + 3);
  if (colon === -1 || colon > at) return ratioRedact(url);
  return url.slice(0, colon + 1) + prefixOnlyRedact(url.slice(colon + 1, at)) + url.slice(at);
}

/**
 * Safe-to-persist form of a credential. Without `type`, reveals at most 25% (see ratioRedact). With a
 * typed token type, keeps the non-secret prefix (e.g. `ghp_`) plus at most 4 trailing chars;
 * generic secrets and database-url passwords reveal only a 2-char prefix.
 */
export function redact(value: string, type?: SecretType): string {
  if (value.startsWith('-----BEGIN')) return PEM_REDACTED;
  if (type === 'generic-secret') return prefixOnlyRedact(value);
  if (type === 'database-url') return redactDatabaseUrl(value);
  if (type !== undefined && type !== 'private-key') {
    const prefix = TYPED_PREFIX_RE.exec(value)?.[0];
    if (prefix) {
      const n = Math.min(4, Math.floor((value.length - prefix.length) / 8));
      return prefix + '…' + (n > 0 ? value.slice(-n) : '');
    }
  }
  return ratioRedact(value);
}

export function secretHash(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/** Client-exposed env prefixes, matched only at the start of an identifier (not `NON_PUBLIC_KEY`). */
const CLIENT_EXPOSED_RE = /\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|PUBLIC_)/;

export function isClientExposed(file: string, lineText: string): boolean {
  if (CLIENT_EXPOSED_RE.test(lineText)) return true;
  const segments = file.split('/');
  if (segments.includes('public') || segments.includes('static')) return true;
  if (/\.html?$/i.test(file)) return true;
  return false;
}

// --- line/column bookkeeping --------------------------------------------------------------

/** Start offset of every line in `text` (index 0 => line 1). */
function buildLineStarts(text: string): number[] {
  const starts = [0];
  let i = text.indexOf('\n');
  while (i !== -1) {
    starts.push(i + 1);
    i = text.indexOf('\n', i + 1);
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

type RawMatch = {
  type: SecretType;
  start: number;
  value: string;
  jwtRole?: string;
  redactOnly?: true;
  /** Leftmost offset the match depends on (e.g. a keyword before the value). Defaults to `start`. */
  anchor?: number;
};

function pushToken(out: RawMatch[], type: SecretType, start: number, value: string, prefixLen: number): void {
  if (!isTokenPlaceholder(value, prefixLen)) out.push({ type, start, value });
}

function matchGithub(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(/\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g)) pushToken(out, 'github-token', m.index, m[0], 4);
  for (const m of text.matchAll(/\bgithub_pat_[A-Za-z0-9_]{60,255}\b/g)) pushToken(out, 'github-token', m.index, m[0], 11);
  return out;
}

function matchAwsAccessKeys(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g)) pushToken(out, 'aws-access-key', m.index, m[0], 4);
  return out;
}

function matchStripe(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  const rules: Array<[RegExp, SecretType]> = [
    [/\bsk_live_[A-Za-z0-9]{24,255}\b/g, 'stripe-secret-key'],
    [/\brk_live_[A-Za-z0-9]{24,255}\b/g, 'stripe-restricted-key'],
    [/\bsk_test_[A-Za-z0-9]{24,255}\b/g, 'stripe-test-key'],
  ];
  for (const [re, type] of rules) {
    for (const m of text.matchAll(re)) pushToken(out, type, m.index, m[0], 8);
  }
  return out;
}

function matchSlack(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(/\bxox[baprs]-[A-Za-z0-9-]{10,255}\b/g)) pushToken(out, 'slack-token', m.index, m[0], 5);
  const webhookRe = /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{1,32}\/B[A-Z0-9]{1,32}\/[A-Za-z0-9]{1,64}/g;
  for (const m of text.matchAll(webhookRe)) {
    pushToken(out, 'slack-webhook', m.index, m[0], m[0].lastIndexOf('/') + 1);
  }
  return out;
}

/** Maximal runs of the OpenAI/Anthropic key alphabet. Linear: a greedy run never needs to backtrack. */
const KEY_RUN_RE = /[A-Za-z0-9_-]{20,}/g;
const OPENAI_LEGACY_MARKER = 'T3BlbkFJ';
const OPENAI_OPTIONAL_PREFIXES = ['proj-', 'svcacct-', 'admin-'];
const ANTHROPIC_INFIX_RE = /(?:api|admin)\d{2}-/y;

/**
 * Classifies the token `run[s..end)` (s is a word-boundary `sk-`). `nextMarker(from)` returns the first
 * legacy marker at/after `from` (amortised O(1): callers only ever ask for increasing `from`).
 */
function classifySkToken(
  run: string, s: number, end: number, nextMarker: (from: number) => number,
): { type: SecretType; prefixLen: number } | null {
  if (run.startsWith('sk-ant-', s)) {
    ANTHROPIC_INFIX_RE.lastIndex = s + 7;
    const infix = ANTHROPIC_INFIX_RE.exec(run);
    if (!infix) return null;
    const prefixLen = 7 + infix[0].length;
    const rest = end - s - prefixLen;
    return rest >= 80 && rest <= 512 ? { type: 'anthropic-api-key', prefixLen } : null;
  }
  const optional = OPENAI_OPTIONAL_PREFIXES.find((p) => run.startsWith(p, s + 3));
  // Legacy shape: sk-[prefix-]{20..74}T3BlbkFJ{20..74}. Try with and without the optional prefix.
  for (const pl of optional ? [optional.length, 0] : [0]) {
    const bodyStart = s + 3 + pl;
    const marker = nextMarker(bodyStart + 20);
    if (marker === -1 || marker > bodyStart + 74) continue;
    const after = end - (marker + OPENAI_LEGACY_MARKER.length);
    if (after >= 20 && after <= 74) return { type: 'openai-api-key', prefixLen: 3 + pl };
  }
  if (run.startsWith('sk-proj-', s)) {
    const rest = end - s - 8;
    if (rest >= 40 && rest <= 512) return { type: 'openai-api-key', prefixLen: 8 };
  }
  return null;
}

function matchOpenAiAndAnthropic(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(KEY_RUN_RE)) {
    const run = m[0];
    let s = run.indexOf('sk-');
    if (s === -1) continue;
    // Tokens end on a word boundary: trailing '-' are never part of them.
    let end = run.length;
    while (end > 0 && run.charCodeAt(end - 1) === 45 /* - */) end--;
    let markerAt = -2;
    const nextMarker = (from: number): number => {
      if (markerAt === -1) return -1;
      if (markerAt < from) markerAt = run.indexOf(OPENAI_LEGACY_MARKER, from);
      return markerAt;
    };
    while (s !== -1 && s < end) {
      if (s === 0 || run.charCodeAt(s - 1) === 45) {
        const hit = classifySkToken(run, s, end, nextMarker);
        if (hit) {
          pushToken(out, hit.type, m.index + s, run.slice(s, end), hit.prefixLen);
          break;
        }
      }
      s = run.indexOf('sk-', s + 1);
    }
  }
  return out;
}

function matchGoogle(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(/\bAIza[0-9A-Za-z_-]{35}\b/g)) pushToken(out, 'google-api-key', m.index, m[0], 4);
  return out;
}

function matchSendgrid(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(/\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g)) pushToken(out, 'sendgrid-api-key', m.index, m[0], 3);
  return out;
}

function matchTwilio(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(/\bSK[0-9a-fA-F]{32}\b/g)) pushToken(out, 'twilio-api-key', m.index, m[0], 2);
  return out;
}

const PEM_BEGIN_RE = /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/g;
const PEM_END_RE = /-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/g;

function matchPrivateKey(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  const ends = [...text.matchAll(PEM_END_RE)].map((m) => ({ start: m.index, end: m.index + m[0].length }));
  let endIdx = 0;
  for (const begin of text.matchAll(PEM_BEGIN_RE)) {
    const beginStart = begin.index;
    const beginEnd = beginStart + begin[0].length;
    while (endIdx < ends.length && ends[endIdx]!.start < beginEnd) endIdx++;
    const candidate = ends[endIdx];
    if (!candidate) continue; // unterminated block — skip, nothing clean to report
    const value = text.slice(beginStart, candidate.end);
    const body = text.slice(beginEnd, candidate.start).trim();
    endIdx++;
    if (isPemPlaceholder(body)) continue;
    out.push({ type: 'private-key', start: beginStart, value });
  }
  return out;
}

function decodeJwtRole(payloadPart: string): string | undefined {
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

/** Maximal runs of the JWT alphabet (incl. the '.' separators). */
const JWT_RUN_RE = /[A-Za-z0-9_.-]{33,}/g;
const JWT_MAX_SEGMENT = 8192;

/**
 * JWTs: `eyJ<10+>.eyJ<10+>.<10+>`, each segment in [A-Za-z0-9_-] and <= 8 KiB. The header starts at a
 * word boundary (run start, or after '-'/'.'); the signature is the whole third segment.
 */
function matchJwt(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(JWT_RUN_RE)) {
    const run = m[0];
    if (!run.includes('eyJ')) continue;
    const segs = run.split('.');
    const offsets: number[] = [];
    let off = 0;
    for (const seg of segs) {
      offsets.push(off);
      off += seg.length + 1;
    }
    for (let i = 0; i + 2 < segs.length; i++) {
      const head = segs[i]!;
      let p = 0;
      if (!head.startsWith('eyJ')) {
        const dash = head.indexOf('-eyJ');
        p = dash === -1 ? -1 : dash + 1;
      }
      if (p === -1 || head.length - p < 13 || head.length - p > JWT_MAX_SEGMENT) continue;
      const payload = segs[i + 1]!;
      const sig = segs[i + 2]!;
      if (!payload.startsWith('eyJ') || payload.length < 13 || payload.length > JWT_MAX_SEGMENT) continue;
      if (sig.length < 10 || sig.length > JWT_MAX_SEGMENT) continue;
      const start = m.index + offsets[i]! + p;
      const value = run.slice(offsets[i]! + p, offsets[i + 2]! + sig.length);
      i += 2;
      if (isTokenPlaceholder(sig, 0)) continue;
      const role = decodeJwtRole(payload);
      if (role === 'anon' || role === 'authenticated') {
        // Public by design: never a finding, but still kept out of snippets.
        out.push({ type: 'jwt', start, value, jwtRole: role, redactOnly: true });
      } else if (role === 'service_role') {
        out.push({ type: 'supabase-service-role', start, value, jwtRole: role });
      } else if (role !== undefined) {
        out.push({ type: 'jwt', start, value, jwtRole: role });
      } else {
        out.push({ type: 'jwt', start, value });
      }
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

/** Username may be empty (`redis://:pass@host`). All parts bounded; none can contain the scheme's '/'. */
const DATABASE_URL_RE =
  /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?):\/\/[^\s:'"@/]{0,256}:([^\s'"@/]{1,256})@[^\s'"]{1,2048}/g;

function matchDatabaseUrl(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(DATABASE_URL_RE)) {
    if (isDbPlaceholderPassword(m[1]!)) continue;
    out.push({ type: 'database-url', start: m.index, value: m[0] });
  }
  return out;
}

function passGenericChecks(value: string): boolean {
  return !isPlaceholder(value) && shannonEntropy(value) >= 3.5;
}

/** `password = "…"`, `"api_key": '…'` — keyword at a word boundary, quoted value. All bounded. */
const GENERIC_QUOTED_RE =
  /\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)['"]?\s{0,16}[:=]\s{0,16}(['"])([^'"\s]{8,1024})\1/gi;
/** One whole line: `[export ]KEY = value`, `KEY: value`, `"key": "value"`. Anchored, bounded. */
const GENERIC_LINE_RE =
  /^[ \t]{0,64}(?:export[ \t]{1,8})?(['"]?)([A-Za-z0-9_.-]{1,128})\1[ \t]{0,16}([=:])[ \t]{0,16}(['"]?)([^\s#'"]{8,1024})\4/;
/** Keys (any case) that name a credential: DB_PASSWORD, db_password, MY_APP_SECRET_TOKEN, api-key… */
const GENERIC_KEY_RE = /password|passwd|secret|token|api[_-]?key|apikey/i;
/** After an unquoted `key: value`, only an optional trailing comment may follow (YAML), not code. */
const YAML_TAIL_RE = /^[ \t]*(?:#.*)?$/;
const YAML_PLAIN_VALUE_RE = /^[A-Za-z0-9_\-+/=.~!@$%^&*]+$/;

function matchGenericLine(line: string, lineStart: number, out: RawMatch[]): void {
  const m = GENERIC_LINE_RE.exec(line);
  if (!m) return;
  const key = m[2]!;
  const sep = m[3]!;
  const quote = m[4]!;
  const value = m[5]!;
  if (!GENERIC_KEY_RE.test(key)) return;
  if (sep === '=' && value.startsWith('=')) return; // `a == b` comparison
  if (sep === ':' && quote === '') {
    // Unquoted `key: value` is YAML-ish only when nothing but a comment follows, and the value isn't a
    // bare identifier (`token: tokenFromRequest`) or code.
    if (!YAML_TAIL_RE.test(line.slice(m[0].length))) return;
    if (!YAML_PLAIN_VALUE_RE.test(value) || /^[A-Za-z]+$/.test(value)) return;
  }
  if (!passGenericChecks(value)) return;
  const valueStart = lineStart + m[0].length - quote.length - value.length;
  out.push({ type: 'generic-secret', start: valueStart, value, anchor: lineStart });
}

function matchGenericSecret(text: string, skipFirstLine: boolean): RawMatch[] {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(GENERIC_QUOTED_RE)) {
    const value = m[2]!;
    if (!passGenericChecks(value)) continue;
    out.push({ type: 'generic-secret', start: m.index + m[0].length - 1 - value.length, value, anchor: m.index });
  }
  let pos = 0;
  let first = true;
  while (pos <= text.length) {
    const nl = text.indexOf('\n', pos);
    const lineEnd = nl === -1 ? text.length : nl;
    if (!(first && skipFirstLine)) matchGenericLine(text.slice(pos, lineEnd), pos, out);
    first = false;
    if (nl === -1) break;
    pos = nl + 1;
  }
  return out;
}

// --- chunking (long-line windows) ----------------------------------------------------------

const MAX_SCAN_LINE = 16 * 1024;
const WINDOW_OVERLAP = 4 * 1024;

type Chunk = { text: string; base: number; cutLeft: boolean; cutRight: boolean };

/**
 * Splits `text` into chunks for the single-line rules: maximal groups of ordinary lines are one chunk;
 * each line longer than MAX_SCAN_LINE becomes overlapping windows (stride MAX_SCAN_LINE - WINDOW_OVERLAP).
 * `cutLeft`/`cutRight` mark window edges that are not real line edges.
 */
function chunkText(text: string): Chunk[] {
  const chunks: Chunk[] = [];
  let groupStart = 0;
  let pos = 0;
  while (pos < text.length) {
    const nl = text.indexOf('\n', pos);
    const lineEnd = nl === -1 ? text.length : nl;
    if (lineEnd - pos > MAX_SCAN_LINE) {
      if (pos > groupStart) chunks.push({ text: text.slice(groupStart, pos), base: groupStart, cutLeft: false, cutRight: false });
      for (let ws = pos; ; ws += MAX_SCAN_LINE - WINDOW_OVERLAP) {
        const we = Math.min(ws + MAX_SCAN_LINE, lineEnd);
        chunks.push({ text: text.slice(ws, we), base: ws, cutLeft: ws > pos, cutRight: we < lineEnd });
        if (we >= lineEnd) break;
      }
      groupStart = lineEnd;
    }
    if (nl === -1) break;
    pos = nl + 1;
  }
  if (groupStart < text.length) chunks.push({ text: text.slice(groupStart), base: groupStart, cutLeft: false, cutRight: false });
  return chunks;
}

const SINGLE_LINE_RULES: ReadonlyArray<(text: string) => RawMatch[]> = [
  matchGithub, matchAwsAccessKeys, matchStripe, matchSlack, matchOpenAiAndAnthropic, matchGoogle,
  matchSendgrid, matchTwilio, matchJwt, matchDatabaseUrl,
];

/** Projects chunk-relative matches to absolute offsets, dropping any that touch an artificial window
 *  edge (those may be truncated; the overlapping neighbour window sees them whole). */
function collect(chunk: Chunk, matches: readonly RawMatch[], seen: Set<string>, out: RawMatch[]): void {
  for (const m of matches) {
    if (chunk.cutLeft && (m.anchor ?? m.start) === 0) continue;
    if (chunk.cutRight && m.start + m.value.length >= chunk.text.length) continue;
    const start = chunk.base + m.start;
    const key = `${m.type}|${start}|${m.value.length}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const abs: RawMatch = { ...m, start };
    delete abs.anchor;
    out.push(abs);
  }
}

// --- AWS access-key / secret-key pairing ----------------------------------------------------

const AWS_CANDIDATE_SECRET_RE = /(?:['"]([A-Za-z0-9/+]{40})['"]|[:=][ \t]{0,16}([A-Za-z0-9/+]{40})(?=\s|$))/g;
const INI_SECTION_RE = /^[ \t]*\[[^\]\n]{1,128}\][ \t]*\r?$/;
const AWS_PAIR_LINE_WINDOW = 5;
const AWS_MAX_CANDIDATES_PER_KEY = 16;

/**
 * Pairs every AWS access key with the nearest *unclaimed* 40-char secret candidate within ±5 lines on a
 * line mentioning secret/aws. Preference order: same INI section, a line naming
 * secret_access_key/aws_secret, line distance, below the key, column distance. Assignment is a global
 * greedy over that order, so two profiles in one file never share (and leak) one secret.
 */
function pairAwsSecrets(text: string, lineStarts: readonly number[], matches: readonly RawMatch[]): Map<RawMatch, string> {
  const result = new Map<RawMatch, string>();
  const awsMatches = matches.filter((m) => m.type === 'aws-access-key');
  if (awsMatches.length === 0) return result;

  const lineText = (ln: number): string => {
    const s = lineStarts[ln - 1] ?? text.length;
    const next = lineStarts[ln];
    return text.slice(s, next === undefined ? text.length : next - 1);
  };
  const lineInfo = new Map<number, { eligible: boolean; preferred: boolean; section: boolean }>();
  const info = (ln: number) => {
    let v = lineInfo.get(ln);
    if (!v) {
      const t = lineText(ln);
      v = { eligible: /secret|aws/i.test(t), preferred: /secret_access_key|aws_secret/i.test(t), section: INI_SECTION_RE.test(t) };
      lineInfo.set(ln, v);
    }
    return v;
  };

  type Cand = { line: number; col: number; value: string; preferred: boolean };
  const byLine = new Map<number, Cand[]>();
  for (const m of text.matchAll(AWS_CANDIDATE_SECRET_RE)) {
    const value = m[1] ?? m[2];
    if (!value) continue;
    const loc = locate(lineStarts, m.index);
    const li = info(loc.line);
    if (!li.eligible) continue;
    const list = byLine.get(loc.line) ?? [];
    list.push({ line: loc.line, col: loc.col, value, preferred: li.preferred });
    byLine.set(loc.line, list);
  }
  if (byLine.size === 0) return result;

  const crossesSection = (a: number, b: number): boolean => {
    for (let ln = Math.min(a, b) + 1; ln < Math.max(a, b); ln++) if (info(ln).section) return true;
    return false;
  };

  // Scalar sort key: section crossing > preferred line > line distance > below-the-key > column distance.
  type Pair = { key: RawMatch; cand: Cand; score: number };
  const pairs: Pair[] = [];
  for (const key of awsMatches) {
    const kLoc = locate(lineStarts, key.start);
    let taken = 0;
    for (let d = 0; d <= AWS_PAIR_LINE_WINDOW && taken < AWS_MAX_CANDIDATES_PER_KEY; d++) {
      for (const ln of d === 0 ? [kLoc.line] : [kLoc.line + d, kLoc.line - d]) {
        for (const cand of byLine.get(ln) ?? []) {
          if (taken >= AWS_MAX_CANDIDATES_PER_KEY) break;
          taken++;
          pairs.push({
            key, cand,
            score: (crossesSection(kLoc.line, ln) ? 1e12 : 0) + (cand.preferred ? 0 : 1e11) + d * 1e10
              + (ln >= kLoc.line ? 0 : 1e9) + Math.min(Math.abs(cand.col - kLoc.col), 1e9 - 1),
          });
        }
      }
    }
  }
  pairs.sort((a, b) => a.score - b.score || a.key.start - b.key.start);
  const claimed = new Set<Cand>();
  for (const p of pairs) {
    if (result.has(p.key) || claimed.has(p.cand)) continue;
    result.set(p.key, p.cand.value);
    claimed.add(p.cand);
  }
  return result;
}

// --- public entry point ----------------------------------------------------------------------

/** True when [start, end) overlaps any interval in `sorted` (sorted by start; `maxEnd` = prefix max). */
function overlapsAny(sorted: readonly RawMatch[], maxEnd: readonly number[], start: number, end: number): boolean {
  let lo = 0;
  let hi = sorted.length - 1;
  let idx = -1; // last interval with start < end
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (sorted[mid]!.start < end) { idx = mid; lo = mid + 1; } else { hi = mid - 1; }
  }
  return idx >= 0 && maxEnd[idx]! > start;
}

export function detectSecrets(text: string, opts: DetectSecretsOptions = {}): SecretMatch[] {
  const lineStarts = buildLineStarts(text);

  const primary: RawMatch[] = [];
  const generic: RawMatch[] = [];
  const seenPrimary = new Set<string>();
  const seenGeneric = new Set<string>();
  for (const chunk of chunkText(text)) {
    for (const rule of SINGLE_LINE_RULES) collect(chunk, rule(chunk.text), seenPrimary, primary);
    // Generic: one finding per value position (the quoted and line rules may both hit it).
    collect(chunk, matchGenericSecret(chunk.text, chunk.cutLeft), seenGeneric, generic);
  }
  primary.push(...matchPrivateKey(text));

  const pairs = pairAwsSecrets(text, lineStarts, primary);
  const pairedValues = new Set(pairs.values());

  const sorted = [...primary].sort((a, b) => a.start - b.start);
  const maxEnd: number[] = [];
  let running = -1;
  for (const p of sorted) {
    running = Math.max(running, p.start + p.value.length);
    maxEnd.push(running);
  }
  const genericByStart = new Set<number>();
  const keptGeneric = generic.filter((g) => {
    if (genericByStart.has(g.start)) return false;
    genericByStart.add(g.start);
    // A secret already reported via an AWS pairing is part of that finding, not a separate one.
    if (pairedValues.has(g.value)) return false;
    return !overlapsAny(sorted, maxEnd, g.start, g.start + g.value.length);
  });

  const all = [...primary, ...keptGeneric].filter((m) => opts.includeRedactOnly || !m.redactOnly);
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
    if (m.redactOnly) match.redactOnly = true;
    const paired = pairs.get(m);
    if (paired !== undefined) match.pairedSecret = paired;
    return match;
  });

  return result.sort((a, b) => a.line - b.line || a.startCol - b.startCol);
}
