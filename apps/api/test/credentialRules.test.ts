import { describe, expect, it } from 'vitest';
import {
  detectSecrets, isClientExposed, isPlaceholder, redact, secretHash, shannonEntropy,
} from '../src/analyzers/credentials/rules';
import { fake } from './fakeCredentials';

describe('detectSecrets — one match per type with correct position', () => {
  it('github-token (classic ghp_)', () => {
    const token = fake.github();
    const text = `const t = "${token}";`;
    const [m] = detectSecrets(text);
    expect(m).toBeDefined();
    expect(m!.type).toBe('github-token');
    expect(m!.value).toBe(token);
    expect(m!.line).toBe(1);
    expect(m!.startCol).toBe(text.indexOf(token) + 1);
  });

  it('github-token (github_pat_)', () => {
    const token = fake.githubPat();
    const [m] = detectSecrets(`TOKEN=${token}\n`);
    expect(m!.type).toBe('github-token');
    expect(m!.value).toBe(token);
  });

  it('aws-access-key, paired with a secret two lines below', () => {
    const access = fake.awsAccessKey();
    const secret = fake.awsSecretKey();
    const text = `aws_access_key_id = "${access}"\nregion = "us-east-1"\naws_secret_access_key = "${secret}"\n`;
    const matches = detectSecrets(text);
    const aws = matches.find((x) => x.type === 'aws-access-key');
    expect(aws).toBeDefined();
    expect(aws!.value).toBe(access);
    expect(aws!.line).toBe(1);
    expect(aws!.pairedSecret).toBe(secret);
  });

  it('stripe-secret-key, stripe-restricted-key, stripe-test-key', () => {
    const live = fake.stripeLive();
    const restricted = fake.stripeRestricted();
    const test = fake.stripeTest();
    const matches = detectSecrets(`${live}\n${restricted}\n${test}\n`);
    expect(matches.map((m) => m.type).sort()).toEqual(['stripe-restricted-key', 'stripe-secret-key', 'stripe-test-key'].sort());
  });

  it('pk_live publishable key is not reported', () => {
    const matches = detectSecrets(`STRIPE_PUBLISHABLE_KEY=${fake.stripePublishable()}\n`);
    expect(matches).toHaveLength(0);
  });

  it('slack-token and slack-webhook', () => {
    const token = fake.slackToken();
    const webhook = fake.slackWebhook();
    const matches = detectSecrets(`${token}\n${webhook}\n`);
    expect(matches.find((m) => m.type === 'slack-token')?.value).toBe(token);
    expect(matches.find((m) => m.type === 'slack-webhook')?.value).toBe(webhook);
  });

  it('openai-api-key (legacy + proj) without cross-matching anthropic', () => {
    const legacy = fake.openaiLegacy();
    const proj = fake.openaiProj();
    const anthropicKey = fake.anthropic();
    const matches = detectSecrets(`${legacy}\n${proj}\n${anthropicKey}\n`);
    const openaiMatches = matches.filter((m) => m.type === 'openai-api-key');
    const anthropicMatches = matches.filter((m) => m.type === 'anthropic-api-key');
    expect(openaiMatches.map((m) => m.value).sort()).toEqual([legacy, proj].sort());
    expect(anthropicMatches.map((m) => m.value)).toEqual([anthropicKey]);
  });

  it('google-api-key', () => {
    const key = fake.google();
    const [m] = detectSecrets(`GOOGLE_API_KEY=${key}\n`);
    expect(m!.type).toBe('google-api-key');
    expect(m!.value).toBe(key);
  });

  it('sendgrid-api-key', () => {
    const key = fake.sendgrid();
    const [m] = detectSecrets(key);
    expect(m!.type).toBe('sendgrid-api-key');
    expect(m!.value).toBe(key);
  });

  it('twilio-api-key', () => {
    const key = fake.twilio();
    const [m] = detectSecrets(key);
    expect(m!.type).toBe('twilio-api-key');
    expect(m!.value).toBe(key);
  });

  it('private-key: multi-line PEM block produces one match with line/endLine', () => {
    const pem = fake.privateKeyPem();
    const text = `before\n${pem}\nafter\n`;
    const matches = detectSecrets(text);
    const keys = matches.filter((m) => m.type === 'private-key');
    expect(keys).toHaveLength(1);
    const pemLines = pem.split('\n').length;
    expect(keys[0]!.line).toBe(2);
    expect(keys[0]!.endLine).toBe(2 + pemLines - 1);
    expect(keys[0]!.value).toBe(pem);
  });

  it('jwt: supabase service_role -> supabase-service-role, anon -> not reported, other -> jwt with jwtRole', () => {
    const anon = fake.supabaseAnonJwt();
    const serviceRole = fake.supabaseServiceRoleJwt();
    const other = fake.jwt({ role: 'editor' });
    const matches = detectSecrets(`${anon}\n${serviceRole}\n${other}\n`);
    expect(matches.some((m) => m.value === anon)).toBe(false);
    const svc = matches.find((m) => m.value === serviceRole);
    expect(svc?.type).toBe('supabase-service-role');
    expect(svc?.jwtRole).toBe('service_role');
    const oth = matches.find((m) => m.value === other);
    expect(oth?.type).toBe('jwt');
    expect(oth?.jwtRole).toBe('editor');
  });

  it('database-url with a real-looking password is reported, placeholder passwords are not', () => {
    const real = fake.databaseUrl('postgres');
    const matches = detectSecrets(real);
    expect(matches.find((m) => m.type === 'database-url')?.value).toBe(real);

    const placeholders = [
      'postgres://user:password@localhost/db',
      'postgres://user:postgres@localhost/db',
      'mysql://root:root@localhost/db',
      'postgres://user:${DB_PASSWORD}@localhost/db',
      'postgres://user:<password>@localhost/db',
    ];
    for (const url of placeholders) {
      expect(detectSecrets(url).filter((m) => m.type === 'database-url')).toHaveLength(0);
    }
  });

  it('generic-secret: high entropy reported, low entropy not, placeholders not', () => {
    const highEntropy = fake.genericSecretValue(24);
    expect(detectSecrets(`password = "${highEntropy}"`).some((m) => m.type === 'generic-secret')).toBe(true);
    expect(detectSecrets('password = "aaaabbbb"')).toHaveLength(0);
  });

  it('generic-secret does not double-report a value already matched by a specific rule', () => {
    const token = fake.github();
    const matches = detectSecrets(`api_key = "${token}"`);
    expect(matches).toHaveLength(1);
    expect(matches[0]!.type).toBe('github-token');
  });

  it('generic-secret: KEY=value .env shape without quotes', () => {
    const value = fake.genericSecretValue(24);
    const matches = detectSecrets(`MY_APP_SECRET_TOKEN=${value}\n`);
    expect(matches.find((m) => m.type === 'generic-secret')?.value).toBe(value);
  });
});

describe('placeholders are not reported', () => {
  it.each([
    ['ghp_' + 'x'.repeat(36)],
    ['AKIAIOSFODNN7EXAMPLE'],
    ['password = "changeme123"'],
    ['API_KEY=${API_KEY}'],
    ['secret: process.env.SECRET'],
    ['postgres://user:password@localhost/db'],
  ])('%s', (text) => {
    expect(detectSecrets(text)).toHaveLength(0);
  });
});

describe('isPlaceholder', () => {
  it('flags known placeholder shapes', () => {
    expect(isPlaceholder('your_api_key_here')).toBe(true);
    expect(isPlaceholder('<your-token>')).toBe(true);
    expect(isPlaceholder('xxxxxxxxxxxxxxxx')).toBe(true);
    expect(isPlaceholder('00000000')).toBe(true);
    expect(isPlaceholder('********')).toBe(true);
    expect(isPlaceholder('AKIAIOSFODNN7EXAMPLE')).toBe(true);
    expect(isPlaceholder('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')).toBe(true);
    expect(isPlaceholder('${SOME_VAR}')).toBe(true);
    expect(isPlaceholder('{{secret}}')).toBe(true);
  });

  it('does not flag a genuinely random value', () => {
    expect(isPlaceholder(fake.genericSecretValue(32))).toBe(false);
  });
});

describe('shannonEntropy', () => {
  it('is 0 for a constant string', () => {
    expect(shannonEntropy('aaaa')).toBe(0);
  });

  it('is high for a random 32-char string', () => {
    expect(shannonEntropy(fake.genericSecretValue(32))).toBeGreaterThan(4);
  });
});

describe('redact', () => {
  it('never contains the middle of the secret', () => {
    const value = fake.github();
    const r = redact(value);
    expect(r).not.toContain(value.slice(10, 20));
    expect(r.startsWith(value.slice(0, 4))).toBe(true);
    expect(r.endsWith(value.slice(-4))).toBe(true);
  });

  it('uses first 2 + ellipsis for short values', () => {
    const r = redact('abcdefgh');
    expect(r).toBe('ab…');
  });

  it('redacts PEM blocks without leaking body lines', () => {
    const pem = fake.privateKeyPem();
    const r = redact(pem);
    const bodyLine = pem.split('\n')[1]!;
    expect(r).not.toContain(bodyLine);
    expect(r).toContain('PRIVATE KEY');
    expect(r).toContain('BEGIN');
  });
});

describe('secretHash', () => {
  it('is a stable 64-char hex digest', () => {
    const value = fake.genericSecretValue(20);
    const h1 = secretHash(value);
    const h2 = secretHash(value);
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('isClientExposed', () => {
  it.each([
    ['src/config.ts', 'const key = NEXT_PUBLIC_API_KEY;', true],
    ['src/config.ts', 'const key = VITE_API_KEY;', true],
    ['src/config.ts', 'const key = REACT_APP_API_KEY;', true],
    ['src/config.ts', 'const key = EXPO_PUBLIC_API_KEY;', true],
    ['src/config.ts', 'const key = PUBLIC_API_KEY;', true],
    ['src/config.ts', 'const key = NUXT_PUBLIC_API_KEY;', true],
    ['public/index.html', 'const key = "x";', true],
    ['static/app.js', 'const key = "x";', true],
    ['site/index.html', 'const key = "x";', true],
    ['src/server.ts', 'const key = "x";', false],
  ] as const)('%s / %s -> %s', (file, line, expected) => {
    expect(isClientExposed(file, line)).toBe(expected);
  });
});
