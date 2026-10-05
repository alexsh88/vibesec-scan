// Deterministic, seeded generator of realistic-looking fake credentials for tests.
//
// Nothing here is a literal credential-shaped string in source: every value is assembled at
// runtime from a seeded PRNG (mulberry32), so this file itself can never be flagged by a real
// secret scanner and a fresh test run always derives its own fixtures structurally rather than
// comparing against hardcoded strings. Deliberately NOT repeated-char placeholders (e.g.
// "xxxxxxxx") — those are exactly what `isPlaceholder` is supposed to reject.

const SEED = 0xc0ffee;
let state = SEED >>> 0;

/** mulberry32: small, fast, deterministic PRNG — good enough for test fixtures. */
function next(): number {
  state = (state + 0x6d2b79f5) | 0;
  let t = Math.imul(state ^ (state >>> 15), 1 | state);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const UPPER_ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const DIGITS = '0123456789';
const HEX = '0123456789abcdef';
const URL_SAFE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
const BASE64ISH = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+';

function randomFrom(length: number, alphabet: string): string {
  let out = '';
  for (let i = 0; i < length; i++) {
    out += alphabet.charAt(Math.floor(next() * alphabet.length));
  }
  return out;
}

function base64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export const fake = {
  github(): string {
    return 'ghp_' + randomFrom(36, ALNUM);
  },
  githubPat(): string {
    return 'github_pat_' + randomFrom(60, ALNUM);
  },
  awsAccessKey(): string {
    return 'AKIA' + randomFrom(16, UPPER_ALNUM);
  },
  awsSecretKey(): string {
    return randomFrom(40, BASE64ISH);
  },
  stripeLive(): string {
    return 'sk_live_' + randomFrom(24, ALNUM);
  },
  stripeRestricted(): string {
    return 'rk_live_' + randomFrom(24, ALNUM);
  },
  stripeTest(): string {
    return 'sk_test_' + randomFrom(24, ALNUM);
  },
  stripePublishable(): string {
    return 'pk_live_' + randomFrom(24, ALNUM);
  },
  slackToken(): string {
    return `xoxb-${randomFrom(11, DIGITS)}-${randomFrom(11, DIGITS)}-${randomFrom(24, ALNUM)}`;
  },
  slackWebhook(): string {
    return `https://hooks.slack.com/services/T${randomFrom(9, UPPER_ALNUM)}/B${randomFrom(9, UPPER_ALNUM)}/${randomFrom(24, ALNUM)}`;
  },
  openaiLegacy(): string {
    return 'sk-' + randomFrom(20, ALNUM) + 'T3BlbkFJ' + randomFrom(20, ALNUM);
  },
  openaiProj(): string {
    return 'sk-proj-' + randomFrom(44, URL_SAFE);
  },
  anthropic(): string {
    return 'sk-ant-api03-' + randomFrom(85, URL_SAFE);
  },
  google(): string {
    return 'AIza' + randomFrom(35, URL_SAFE);
  },
  sendgrid(): string {
    return `SG.${randomFrom(22, URL_SAFE)}.${randomFrom(43, URL_SAFE)}`;
  },
  twilio(): string {
    return 'SK' + randomFrom(32, HEX);
  },
  privateKeyPem(kind = 'RSA'): string {
    const lines = [`-----BEGIN ${kind} PRIVATE KEY-----`];
    for (let i = 0; i < 4; i++) lines.push(randomFrom(64, BASE64ISH));
    lines.push(`-----END ${kind} PRIVATE KEY-----`);
    return lines.join('\n');
  },
  jwt(claims: Record<string, unknown> = {}): string {
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload = { iat: 1_700_000_000, exp: 1_999_999_999, ...claims };
    const signature = randomFrom(43, URL_SAFE);
    return `${base64url(header)}.${base64url(payload)}.${signature}`;
  },
  supabaseAnonJwt(): string {
    return fake.jwt({ role: 'anon', iss: 'supabase' });
  },
  supabaseServiceRoleJwt(): string {
    return fake.jwt({ role: 'service_role', iss: 'supabase' });
  },
  databaseUrl(scheme = 'postgres'): string {
    const password = randomFrom(20, ALNUM);
    return `${scheme}://app_user:${password}@db.internal.example.com:5432/app_production`;
  },
  genericSecretValue(length = 24): string {
    return randomFrom(length, ALNUM);
  },
};
