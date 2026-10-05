// Deterministic, seeded fake-secret generator for tests.
//
// These values are NOT real secrets: every character is produced by a seeded
// PRNG at test runtime, so nothing realistic-looking is ever committed to the
// repo as a literal string (avoids GitHub push-protection / repo secret
// scanners tripping on fixtures). Shapes match the regexes in
// `src/analyzers/secrets/rules.ts` closely enough to exercise them.

const UPPER_ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const BASE64 = ALNUM + '+/';
const BASE64URL = ALNUM + '-_';
const HEX = '0123456789abcdef';

/** mulberry32: small, fast, deterministic PRNG from an integer seed. */
function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

class Rng {
  private readonly next: () => number;
  constructor(seed: number) {
    this.next = mulberry32(seed);
  }
  int(maxExclusive: number): number {
    return Math.floor(this.next() * maxExclusive);
  }
  string(length: number, alphabet: string = ALNUM): string {
    let out = '';
    for (let i = 0; i < length; i++) out += alphabet.charAt(this.int(alphabet.length));
    return out;
  }
}

function base64urlEncode(input: string): string {
  return Buffer.from(input, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export type Fake = {
  github(): string;
  githubPat(): string;
  awsAccessKey(): string;
  awsSecretKey(): string;
  stripeLive(): string;
  stripeRestricted(): string;
  stripeTest(): string;
  stripePublishable(): string;
  slackToken(): string;
  slackWebhook(): string;
  openaiLegacy(): string;
  openaiProj(): string;
  anthropic(): string;
  google(): string;
  sendgrid(): string;
  twilio(): string;
  privateKeyPem(label?: string): string;
  jwt(payload: Record<string, unknown>): string;
  supabaseAnonJwt(): string;
  supabaseServiceRoleJwt(): string;
  databaseUrl(scheme: string, password?: string): string;
  genericSecretValue(length?: number): string;
};

/** Builds a fresh deterministic fake generator. Same seed -> same sequence of values. */
export function createFake(seed = 1337): Fake {
  const rng = new Rng(seed);
  return {
    github: () => 'ghp_' + rng.string(36, ALNUM),
    githubPat: () => 'github_pat_' + rng.string(82, ALNUM + '_'),
    awsAccessKey: () => 'AKIA' + rng.string(16, UPPER_ALNUM),
    awsSecretKey: () => rng.string(40, BASE64),
    stripeLive: () => 'sk_live_' + rng.string(32, ALNUM),
    stripeRestricted: () => 'rk_live_' + rng.string(32, ALNUM),
    stripeTest: () => 'sk_test_' + rng.string(32, ALNUM),
    stripePublishable: () => 'pk_live_' + rng.string(32, ALNUM),
    slackToken: () => 'xoxb-' + rng.string(24, ALNUM),
    slackWebhook: () =>
      `https://hooks.slack.com/services/T${rng.string(9, UPPER_ALNUM)}/B${rng.string(9, UPPER_ALNUM)}/${rng.string(24, ALNUM)}`,
    openaiLegacy: () => 'sk-' + rng.string(20, ALNUM + '_-') + 'T3BlbkFJ' + rng.string(20, ALNUM + '_-'),
    openaiProj: () => 'sk-proj-' + rng.string(48, ALNUM + '_-'),
    anthropic: () => 'sk-ant-api03-' + rng.string(95, ALNUM + '_-'),
    google: () => 'AIza' + rng.string(35, ALNUM + '_-'),
    sendgrid: () => 'SG.' + rng.string(22, ALNUM + '_-') + '.' + rng.string(43, ALNUM + '_-'),
    twilio: () => 'SK' + rng.string(32, HEX),
    privateKeyPem: (label = 'RSA ') => {
      const lines = Array.from({ length: 4 }, () => rng.string(64, BASE64));
      return `-----BEGIN ${label}PRIVATE KEY-----\n${lines.join('\n')}\n-----END ${label}PRIVATE KEY-----`;
    },
    jwt: (payload: Record<string, unknown>) => {
      const header = base64urlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
      const body = base64urlEncode(JSON.stringify(payload));
      const signature = rng.string(43, BASE64URL);
      return `${header}.${body}.${signature}`;
    },
    supabaseAnonJwt: () =>
      createFake(seed + 1).jwt({ role: 'anon', iss: 'supabase', iat: 1700000000, exp: 1999999999 }),
    supabaseServiceRoleJwt: () =>
      createFake(seed + 2).jwt({ role: 'service_role', iss: 'supabase', iat: 1700000000, exp: 1999999999 }),
    databaseUrl: (scheme: string, password?: string) =>
      `${scheme}://app_user:${password ?? rng.string(20, ALNUM)}@db.internal.example:5432/app_db`,
    genericSecretValue: (length = 32) => rng.string(length, ALNUM),
  };
}

/** Default shared instance -- deterministic across the whole test run. */
export const fake: Fake = createFake();
