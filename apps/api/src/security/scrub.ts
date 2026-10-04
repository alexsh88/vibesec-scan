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

// Anything after `authorization: ` (with or without a scheme keyword) up to end of
// line or end of a JSON string value is opaque and must be redacted — opaque
// (schemeless) tokens leak otherwise.
const AUTH_HEADER = /(authorization\s*["']?\s*[:=]\s*["']?)(?:(?:basic|bearer|token)\s+)?[^\n\r"',]*/gi;

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
      // No END marker nearby: redact just the exposed BEGIN line, not the whole tail.
      out += REDACTED;
      cursor = begin.end;
    }
  }
  out += text.slice(cursor);
  return out;
}

export function scrubSecrets(text: string): string {
  let out = text.replace(AUTH_HEADER, `$1${REDACTED}`);
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

  seen.add(value);

  if (Array.isArray(value)) return value.map((v) => scrubDeepInner(v, seen));

  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = isSensitiveKey(k) && typeof v === 'string' ? REDACTED : scrubDeepInner(v, seen);
  }
  return out;
}

export function scrubDeep<T>(value: T): T {
  return scrubDeepInner(value, new WeakSet<object>()) as T;
}
