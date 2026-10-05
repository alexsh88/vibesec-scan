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
    // ...but it is still surfaced as a redact-only match when asked for (so snippets can hide it).
    const withRedactOnly = detectSecrets(`${anon}\n`, { includeRedactOnly: true });
    expect(withRedactOnly).toHaveLength(1);
    expect(withRedactOnly[0]!.redactOnly).toBe(true);
    expect(withRedactOnly[0]!.value).toBe(anon);
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

  it('reveals at most 25% of an untyped value (per side min(4, floor(len/8)))', () => {
    for (let len = 8; len <= 16; len++) {
      const value = fake.genericSecretValue(len);
      const r = redact(value);
      const revealed = r.replace('…', '').length;
      expect(revealed).toBeLessThanOrEqual(Math.floor(len * 0.25));
      const n = Math.min(4, Math.floor(len / 8));
      expect(r).toBe(`${value.slice(0, n)}…${value.slice(-n)}`);
    }
    expect(redact('abcdefgh')).toBe('a…h');
  });

  it('reveals nothing for values shorter than 8 chars', () => {
    expect(redact('a')).toBe('…');
    expect(redact('abcdefg')).toBe('…');
  });

  it('generic-secret reveals only a 2-char prefix', () => {
    const value = fake.genericSecretValue(12);
    expect(redact(value, 'generic-secret')).toBe(`${value.slice(0, 2)}…`);
    expect(redact('short', 'generic-secret')).toBe('…');
  });

  it('database-url hides all but 2 chars of the password', () => {
    const url = fake.databaseUrl('postgres');
    const password = /:\/\/[^:]*:([^@]+)@/.exec(url)![1]!;
    const r = redact(url, 'database-url');
    expect(r).not.toContain(password.slice(2));
    expect(r).toContain(`${password.slice(0, 2)}…@`);
  });

  it('typed tokens keep their (non-secret) prefix and at most 4 trailing chars', () => {
    const gh = fake.github();
    expect(redact(gh, 'github-token')).toBe(`ghp_…${gh.slice(-4)}`);
    const aws = fake.awsAccessKey();
    expect(redact(aws, 'aws-access-key')).toBe(`AKIA…${aws.slice(-2)}`);
    const stripe = fake.stripeLive();
    expect(redact(stripe, 'stripe-secret-key')).toBe(`sk_live_…${stripe.slice(-3)}`);
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
    ['src/server.ts', 'const key = NON_PUBLIC_KEY;', false],
    ['src/server.ts', 'const key = import.meta.env.PUBLIC_KEY;', true],
  ] as const)('%s / %s -> %s', (file, line, expected) => {
    expect(isClientExposed(file, line)).toBe(expected);
  });
});

describe('AWS secret pairing', () => {
  it('pairs each access key with its own profile secret in a two-profile credentials file', () => {
    const k1 = fake.awsAccessKey();
    const k2 = fake.awsAccessKey();
    const s1 = fake.awsSecretKey();
    const s2 = fake.awsSecretKey();
    const text = `[default]\naws_access_key_id = ${k1}\naws_secret_access_key = ${s1}\n[prod]\naws_access_key_id = ${k2}\naws_secret_access_key = ${s2}\n`;
    const matches = detectSecrets(text);
    expect(matches.find((m) => m.value === k1)?.pairedSecret).toBe(s1);
    expect(matches.find((m) => m.value === k2)?.pairedSecret).toBe(s2);
    // The paired secrets are reported as part of the AWS findings, not as separate generic secrets.
    expect(matches.filter((m) => m.type === 'generic-secret')).toHaveLength(0);
  });

  it('pairs within the INI section even when the secret precedes the key id', () => {
    const k1 = fake.awsAccessKey();
    const k2 = fake.awsAccessKey();
    const s1 = fake.awsSecretKey();
    const s2 = fake.awsSecretKey();
    const text = `[a]\naws_secret_access_key = ${s1}\naws_access_key_id = ${k1}\n[b]\naws_secret_access_key = ${s2}\naws_access_key_id = ${k2}\n`;
    const matches = detectSecrets(text);
    expect(matches.find((m) => m.value === k1)?.pairedSecret).toBe(s1);
    expect(matches.find((m) => m.value === k2)?.pairedSecret).toBe(s2);
  });
});

describe('placeholder filtering does not drop real high-entropy credentials', () => {
  const pemWith = (needle: string) => {
    const pem = fake.privateKeyPem();
    const lines = pem.split('\n');
    lines[2] = lines[2]!.slice(0, 20) + needle + lines[2]!.slice(20 + needle.length);
    return lines.join('\n');
  };

  it.each(['xXx', 'ToDo', 'sample', 'your', 'Insert'])('PEM body containing %s is still detected', (needle) => {
    const pem = pemWith(needle);
    const keys = detectSecrets(pem).filter((m) => m.type === 'private-key');
    expect(keys).toHaveLength(1);
    expect(keys[0]!.value).toBe(pem);
  });

  it('ghp_ token whose random part contains "todo" is still detected', () => {
    const token = 'ghp_' + fake.genericSecretValue(10) + 'todo' + fake.genericSecretValue(22);
    expect(detectSecrets(`t = "${token}"`).map((m) => m.value)).toEqual([token]);
  });

  it('JWT whose signature contains "xxx" is still detected', () => {
    const jwt = fake.jwt({ role: 'editor' });
    const tampered = jwt.slice(0, -10) + 'xxx' + jwt.slice(-7);
    expect(detectSecrets(tampered).map((m) => m.value)).toEqual([tampered]);
  });

  it.each([
    ['ghp_' + 'x'.repeat(36)],
    ['ghp_YourGithubTokenGoesHereYourToken0123'],
    ['ghp_abcdXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'],
    ['AKIAI44QH8DHBEXAMPLE'],
    ['-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----'],
    ['-----BEGIN PRIVATE KEY-----\n<your private key goes here, paste the whole thing>\n-----END PRIVATE KEY-----'],
    ['-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...\n...\n-----END PRIVATE KEY-----'],
  ])('real placeholder %s is still filtered', (text) => {
    expect(detectSecrets(text)).toHaveLength(0);
  });
});

describe('detection gaps (M1)', () => {
  it('database-url with an empty username (redis://:pass@host)', () => {
    const password = fake.genericSecretValue(20);
    const url = `redis://:${password}@cache.internal:6379/0`;
    expect(detectSecrets(url).find((m) => m.type === 'database-url')?.value).toBe(url);
  });

  it('lowercase .env keys are detected by the generic rule', () => {
    const value = fake.genericSecretValue(24);
    expect(detectSecrets(`db_password=${value}\n`).find((m) => m.type === 'generic-secret')?.value).toBe(value);
  });

  it('unquoted YAML values are detected by the generic rule', () => {
    const value = fake.genericSecretValue(16) + '9';
    const m = detectSecrets(`database:\n  password: ${value}\n`).find((x) => x.type === 'generic-secret');
    expect(m?.value).toBe(value);
    expect(m?.line).toBe(2);
    expect(m?.startCol).toBe('  password: '.length + 1);
  });

  it('generic rule still filters placeholders and low entropy, and ignores code', () => {
    expect(detectSecrets('db_password=changeme123\n')).toHaveLength(0);
    expect(detectSecrets('password: aaaabbbbcccc\n')).toHaveLength(0);
    expect(detectSecrets('const token = getTokenFromRequest(req);\n')).toHaveLength(0);
    expect(detectSecrets('  token: tokenFromRequest,\n')).toHaveLength(0);
  });
});

describe('ReDoS resistance (2 MiB adversarial inputs)', () => {
  const MIB2 = 2 * 1024 * 1024;
  const fill = (unit: string) => unit.repeat(Math.ceil(MIB2 / unit.length)).slice(0, MIB2);
  const minifiedJsLike = () => {
    const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.=:"\'(){};,/+ ';
    const out: string[] = [];
    let x = 12345;
    for (let i = 0; i < MIB2; i++) {
      x = (Math.imul(x, 1103515245) + 12345) & 0x7fffffff;
      out.push(alphabet.charAt(x % alphabet.length));
    }
    return out.join('');
  };

  it.each([
    ['jwt prefix run', () => fill('-eyJ')],
    ['jwt header-like segments', () => fill('eyJaaaaaaaaaaaaa.')],
    ['openai legacy prefix run', () => fill('sk-')],
    ['openai proj prefix run', () => fill('-sk-proj-')],
    ['anthropic prefix run', () => fill('-sk-ant-api03-')],
    ['env keyword run (one line)', () => fill('TOKEN')],
    ['env keyword run (many lines)', () => fill('API_TOKEN=\n')],
    ['quoted generic', () => fill('password=')],
    ['db url', () => fill('redis://a:')],
    ['slack', () => fill('xoxb-')],
    ['aws candidates', () => fill(`aws = ${'A'.repeat(40)} \n`)],
    ['aws keys + candidates on one line', () => fill(`${fake.awsAccessKey()} aws = ${fake.awsSecretKey()} `)],
    ['minified js-like single line', minifiedJsLike],
  ])('%s finishes detectSecrets in < 1.5 s', (_name, gen) => {
    const text = gen();
    const t0 = performance.now();
    detectSecrets(text);
    expect(performance.now() - t0).toBeLessThan(1500);
  }, 30_000);

  it('still finds tokens straddling the 16 KiB window boundaries of a long single line', () => {
    const filler = minifiedJsLike().replace(/[A-Za-z0-9_-]/g, ' ').slice(0, 64 * 1024);
    const tokens = [16_380, 12_280, 24_570, 40_950].map((offset) => ({ offset, token: fake.github() }));
    let line = filler;
    for (const { offset, token } of tokens) {
      line = line.slice(0, offset) + ` ${token} ` + line.slice(offset + token.length + 2);
    }
    const matches = detectSecrets(`first\n${line}\nlast\n`);
    expect(matches.map((m) => m.value).sort()).toEqual(tokens.map((t) => t.token).sort());
    for (const { offset, token } of tokens) {
      const m = matches.find((x) => x.value === token)!;
      expect(m.line).toBe(2);
      expect(m.startCol).toBe(offset + 2);
    }
  });
});
