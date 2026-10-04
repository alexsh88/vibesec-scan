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
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
];

const AUTH_HEADER = /(authorization\s*[:=]\s*)(?:basic|bearer|token)\s+\S+/gi;
const SENSITIVE_KEY = /^(?:token|password|secret|apiKey|api_key|authorization|accessToken)$/i;

export function scrubSecrets(text: string): string {
  let out = text.replace(AUTH_HEADER, `$1${REDACTED}`);
  for (const re of PATTERNS) out = out.replace(re, REDACTED);
  return out;
}

export function scrubDeep<T>(value: T): T {
  if (typeof value === 'string') return scrubSecrets(value) as T;
  if (Array.isArray(value)) return value.map((v) => scrubDeep(v)) as T;
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = SENSITIVE_KEY.test(k) && typeof v === 'string' ? REDACTED : scrubDeep(v);
    }
    return out as T;
  }
  return value;
}
