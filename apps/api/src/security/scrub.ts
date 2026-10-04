const REDACTED = '[REDACTED]';

const PATTERNS: RegExp[] = [
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{40,}\b/g,
  /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
  /\b[rs]k_live_[A-Za-z0-9]{16,}\b/g,
  /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,
];

// Only redact credential-looking authorization values, not prose that merely
// mentions the word. With a scheme keyword, the scheme + following token is
// opaque and always redacted. Without one, require a single unbroken run of
// >=16 base64/token-alphabet chars ending at EOS/whitespace/quote/comma — long
// enough to rule out ordinary words like "required" or a sentence of prose.
const AUTH_PREFIX = 'authorization\\s*["\']?\\s*[:=]\\s*["\']?';
const AUTH_SCHEME = new RegExp(`(${AUTH_PREFIX})(?:basic|bearer|token)\\s+[^\\s"',]+`, 'gi');
const AUTH_OPAQUE = new RegExp(`(${AUTH_PREFIX})[A-Za-z0-9._~+/=-]{16,}(?=$|[\\s"',])`, 'gi');

const SENSITIVE_KEY = /token|secret|password|passwd|api[_-]?key|authorization|credential|private[_-]?key/i;
const SENSITIVE_KEY_EXEMPT_SUFFIX = /(?:type|fingerprint|count|id)$/i;

function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY.test(key) && !SENSITIVE_KEY_EXEMPT_SUFFIX.test(key);
}

// --- Linear-time PEM block scrubbing -----------------------------------------
//
// The previous implementation used /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END ...-----/g.
// When a BEGIN marker has no matching END, the lazy [\s\S]*? forces a scan to the
// end of the remaining text for *every* BEGIN marker, which is quadratic for input
// containing many unterminated BEGIN markers. This scan instead finds all BEGIN and
// END markers in one indexOf-based pass each (each occurrence check is bounded by a
// small constant), then pairs them left-to-right, capping the BEGIN->END distance it
// will treat as one block at PEM_WINDOW_BYTES.

const PEM_BEGIN_PREFIX = '-----BEGIN ';
const PEM_END_PREFIX = '-----END ';
const PEM_KEY_SUFFIX = 'PRIVATE KEY-----';
const PEM_MAX_LABEL_CHARS = 32;
const PEM_WINDOW_BYTES = 16 * 1024;

type PemMarker = { start: number; end: number };

// A line made up entirely of base64 alphabet chars (len >=16) is almost certainly
// PEM body content rather than prose, so it's safe to redact it too.
const PEM_BASE64_LINE = /^[A-Za-z0-9+/=]{16,}[ \t\r]*$/;

function isUpperOrSpace(code: number): boolean {
  return (code >= 65 && code <= 90) || code === 32;
}

/** Finds every `${prefix}[A-Z ]*PRIVATE KEY-----` marker, each check bounded to a small constant. */
function findPemMarkers(text: string, prefix: string): PemMarker[] {
  const markers: PemMarker[] = [];
  let searchFrom = 0;
  for (;;) {
    const start = text.indexOf(prefix, searchFrom);
    if (start === -1) break;
    const bodyStart = start + prefix.length;
    const probeEnd = Math.min(text.length, bodyStart + PEM_MAX_LABEL_CHARS + PEM_KEY_SUFFIX.length);
    const probe = text.slice(bodyStart, probeEnd);
    const suffixAt = probe.indexOf(PEM_KEY_SUFFIX);
    let isValidLabel = suffixAt !== -1;
    if (isValidLabel) {
      for (let i = 0; i < suffixAt; i++) {
        if (!isUpperOrSpace(probe.charCodeAt(i))) { isValidLabel = false; break; }
      }
    }
    if (isValidLabel) {
      const end = bodyStart + suffixAt + PEM_KEY_SUFFIX.length;
      markers.push({ start, end });
      searchFrom = end;
    } else {
      searchFrom = bodyStart;
    }
  }
  return markers;
}

/**
 * When a BEGIN marker has no END nearby, extend the redaction past the marker's
 * own line to cover the consecutive base64-looking lines that follow (bounded by
 * PEM_WINDOW_BYTES from the marker), so the key body doesn't leak. Returns
 * markerEnd unchanged when the marker isn't followed by a line break or by any
 * matching line, so the existing "no body" behavior is untouched.
 */
function consumePemBody(text: string, markerEnd: number): number {
  let pos = markerEnd;
  if (text[pos] === '\r' && text[pos + 1] === '\n') pos += 2;
  else if (text[pos] === '\n') pos += 1;
  else return markerEnd;

  const windowEnd = Math.min(text.length, markerEnd + PEM_WINDOW_BYTES);
  let cursor = pos;
  let consumedAny = false;
  while (cursor < windowEnd) {
    let lineEnd = text.indexOf('\n', cursor);
    if (lineEnd === -1 || lineEnd > windowEnd) lineEnd = windowEnd;
    const line = text.slice(cursor, lineEnd);
    if (!PEM_BASE64_LINE.test(line)) break;
    consumedAny = true;
    cursor = lineEnd < text.length && text[lineEnd] === '\n' ? lineEnd + 1 : lineEnd;
  }
  return consumedAny ? cursor : markerEnd;
}

function scrubPemBlocks(text: string): string {
  const begins = findPemMarkers(text, PEM_BEGIN_PREFIX);
  if (begins.length === 0) return text;
  const ends = findPemMarkers(text, PEM_END_PREFIX);

  let out = '';
  let cursor = 0;
  let endIdx = 0;
  for (const begin of begins) {
    if (begin.start < cursor) continue; // already swallowed by a previous block
    out += text.slice(cursor, begin.start);
    while (endIdx < ends.length && ends[endIdx]!.start < begin.end) endIdx++;
    const candidate = ends[endIdx];
    if (candidate && candidate.start - begin.end <= PEM_WINDOW_BYTES) {
      out += REDACTED;
      cursor = candidate.end;
      endIdx++;
    } else {
      // No END marker nearby: redact the exposed BEGIN line plus any base64-looking
      // body lines right after it, not the whole tail.
      out += REDACTED;
      cursor = consumePemBody(text, begin.end);
    }
  }
  out += text.slice(cursor);
  return out;
}

export function scrubSecrets(text: string): string {
  let out = text.replace(AUTH_SCHEME, `$1${REDACTED}`);
  out = out.replace(AUTH_OPAQUE, `$1${REDACTED}`);
  for (const re of PATTERNS) out = out.replace(re, REDACTED);
  out = scrubPemBlocks(out);
  return out;
}

function scrubDeepInner(value: unknown, seen: WeakSet<object>): unknown {
  if (typeof value === 'string') return scrubSecrets(value);
  if (value === null || typeof value !== 'object') return value;

  if (seen.has(value)) return '[Circular]';

  if (value instanceof Date) return value.toISOString();
  if (value instanceof Error) return { name: value.name, message: scrubSecrets(value.message) };
  if (ArrayBuffer.isView(value)) return `[binary ${(value as ArrayBufferView).byteLength} bytes]`;
  if (value instanceof ArrayBuffer) return `[binary ${value.byteLength} bytes]`;

  // Track the ancestor path, not every object ever visited: add before recursing
  // into children and remove once this node's subtree is done, so a shared
  // (non-cyclic) reference reached twice via different parents is scrubbed twice
  // instead of being flagged as circular.
  seen.add(value);

  let out: unknown;
  if (Array.isArray(value)) {
    out = value.map((v) => scrubDeepInner(v, seen));
  } else {
    const obj: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      obj[k] = isSensitiveKey(k) && typeof v === 'string' ? REDACTED : scrubDeepInner(v, seen);
    }
    out = obj;
  }

  seen.delete(value);
  return out;
}

export function scrubDeep<T>(value: T): T {
  return scrubDeepInner(value, new WeakSet<object>()) as T;
}
