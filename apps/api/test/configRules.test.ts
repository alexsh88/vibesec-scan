import { describe, expect, it } from 'vitest';
import { githubActionsIssues, isGithubActionsWorkflow } from '../src/analyzers/code/config/githubActions';
import { dockerfileIssues, isDockerfile } from '../src/analyzers/code/config/dockerfile';
import {
  envExposureIssues,
  envFileCommittedIssues,
  clientExposedCredentialIssues,
  isClientExposedCredentialName,
} from '../src/analyzers/code/config/envExposure';
import { configIssues } from '../src/analyzers/code/config/index';

const WF = '.github/workflows/ci.yml';

function issuesOf(ruleId: string, issues: ReturnType<typeof githubActionsIssues>) {
  return issues.filter((i) => i.ruleId === ruleId);
}

describe('path matchers', () => {
  it('recognizes workflow and Dockerfile paths', () => {
    expect(isGithubActionsWorkflow('.github/workflows/ci.yml')).toBe(true);
    expect(isGithubActionsWorkflow('.github/workflows/ci.yaml')).toBe(true);
    expect(isGithubActionsWorkflow('src/ci.yml')).toBe(false);
    expect(isDockerfile('Dockerfile')).toBe(true);
    expect(isDockerfile('docker/Dockerfile.prod')).toBe(true);
    expect(isDockerfile('web.Dockerfile')).toBe(true);
    expect(isDockerfile('Containerfile')).toBe(true);
    expect(isDockerfile('notes.md')).toBe(false);
  });
});

describe('config/gha-pull-request-target-checkout', () => {
  it('flags checking out the PR head on pull_request_target', () => {
    const text = [
      'on: pull_request_target',
      'jobs:',
      '  build:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '        with:',
      '          ref: ${{ github.event.pull_request.head.sha }}',
    ].join('\n');
    const issues = githubActionsIssues([{ path: WF, text }]);
    const found = issuesOf('config/gha-pull-request-target-checkout', issues);
    expect(found).toHaveLength(1);
    expect(found[0]!.severity).toBe('critical');
    expect(found[0]!.cwe).toBe('CWE-829');
  });

  it('does not flag pull_request (not _target)', () => {
    const text = [
      'on: pull_request',
      'jobs:',
      '  build:',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '        with:',
      '          ref: ${{ github.event.pull_request.head.sha }}',
    ].join('\n');
    const issues = githubActionsIssues([{ path: WF, text }]);
    expect(issuesOf('config/gha-pull-request-target-checkout', issues)).toHaveLength(0);
  });

  it('does not flag a default checkout with no ref override', () => {
    const text = ['on: pull_request_target', 'jobs:', '  build:', '    steps:', '      - uses: actions/checkout@v4'].join('\n');
    const issues = githubActionsIssues([{ path: WF, text }]);
    expect(issuesOf('config/gha-pull-request-target-checkout', issues)).toHaveLength(0);
  });

  it('flags head_ref as well as head.sha', () => {
    const text = [
      'on: pull_request_target',
      'jobs:',
      '  build:',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '        with:',
      '          ref: ${{ github.head_ref }}',
    ].join('\n');
    const issues = githubActionsIssues([{ path: WF, text }]);
    expect(issuesOf('config/gha-pull-request-target-checkout', issues)).toHaveLength(1);
  });
});

describe('config/gha-script-injection', () => {
  it('flags an untrusted expression interpolated into run:', () => {
    const text = [
      'on: pull_request_target',
      'jobs:',
      '  build:',
      '    steps:',
      '      - run: |',
      '          echo "${{ github.event.issue.title }}"',
    ].join('\n');
    const issues = githubActionsIssues([{ path: WF, text }]);
    const found = issuesOf('config/gha-script-injection', issues);
    expect(found).toHaveLength(1);
    expect(found[0]!.severity).toBe('high');
    expect(found[0]!.startLine).toBe(6);
  });

  it('does not flag the safe env: indirection pattern', () => {
    const text = [
      'on: pull_request_target',
      'jobs:',
      '  build:',
      '    steps:',
      '      - env:',
      '          TITLE: ${{ github.event.issue.title }}',
      '        run: |',
      '          echo "$TITLE"',
    ].join('\n');
    const issues = githubActionsIssues([{ path: WF, text }]);
    expect(issuesOf('config/gha-script-injection', issues)).toHaveLength(0);
  });

  it('does not flag trusted contexts like github.sha', () => {
    const text = ['jobs:', '  build:', '    steps:', '      - run: echo "${{ github.sha }}"'].join('\n');
    const issues = githubActionsIssues([{ path: WF, text }]);
    expect(issuesOf('config/gha-script-injection', issues)).toHaveLength(0);
  });
});

describe('config/gha-unpinned-action', () => {
  it('flags a third-party action pinned to a tag', () => {
    const text = ['jobs:', '  build:', '    steps:', '      - uses: someuser/some-action@v1'].join('\n');
    const issues = githubActionsIssues([{ path: WF, text }]);
    const found = issuesOf('config/gha-unpinned-action', issues);
    expect(found).toHaveLength(1);
    expect(found[0]!.severity).toBe('medium');
  });

  it('does not flag a third-party action pinned to a 40-char SHA', () => {
    const text = ['jobs:', '  build:', '    steps:', '      - uses: someuser/some-action@abcdefabcdefabcdefabcdefabcdefabcdefabcd'].join('\n');
    const issues = githubActionsIssues([{ path: WF, text }]);
    expect(issuesOf('config/gha-unpinned-action', issues)).toHaveLength(0);
  });

  it('does not flag official actions/* or github/* even unpinned', () => {
    const text = ['jobs:', '  build:', '    steps:', '      - uses: actions/checkout@v4', '      - uses: github/codeql-action/init@v2'].join('\n');
    const issues = githubActionsIssues([{ path: WF, text }]);
    expect(issuesOf('config/gha-unpinned-action', issues)).toHaveLength(0);
  });

  it('does not flag local actions', () => {
    const text = ['jobs:', '  build:', '    steps:', '      - uses: ./.github/actions/local'].join('\n');
    const issues = githubActionsIssues([{ path: WF, text }]);
    expect(issuesOf('config/gha-unpinned-action', issues)).toHaveLength(0);
  });
});

describe('config/gha-excessive-permissions', () => {
  it('flags workflow-level write-all', () => {
    const text = ['permissions: write-all', 'jobs:', '  build:', '    steps:', '      - run: echo hi'].join('\n');
    const issues = githubActionsIssues([{ path: WF, text }]);
    expect(issuesOf('config/gha-excessive-permissions', issues).length).toBeGreaterThanOrEqual(1);
  });

  it('flags a pull_request_target workflow with no permissions at all', () => {
    const text = ['on: pull_request_target', 'jobs:', '  build:', '    steps:', '      - run: echo hi'].join('\n');
    const issues = githubActionsIssues([{ path: WF, text }]);
    expect(issuesOf('config/gha-excessive-permissions', issues)).toHaveLength(1);
  });

  it('does not flag when scoped permissions are declared', () => {
    const text = [
      'on: pull_request_target',
      'permissions:',
      '  contents: read',
      'jobs:',
      '  build:',
      '    steps:',
      '      - run: echo hi',
    ].join('\n');
    const issues = githubActionsIssues([{ path: WF, text }]);
    expect(issuesOf('config/gha-excessive-permissions', issues)).toHaveLength(0);
  });
});

describe('github actions: malformed yaml is tolerated', () => {
  it('does not throw on invalid YAML and returns an array', () => {
    const text = 'on: [pull_request_target\njobs:\n  build\n    steps: - uses:::: broken';
    expect(() => githubActionsIssues([{ path: WF, text }])).not.toThrow();
    expect(Array.isArray(githubActionsIssues([{ path: WF, text }]))).toBe(true);
  });
});

describe('config/docker-root-user', () => {
  it('flags a Dockerfile with no USER instruction', () => {
    const text = ['FROM node:18.19.0', 'COPY . .', 'CMD ["node", "server.js"]'].join('\n');
    const issues = dockerfileIssues([{ path: 'Dockerfile', text }]);
    const found = issuesOf('config/docker-root-user', issues);
    expect(found).toHaveLength(1);
    expect(found[0]!.severity).toBe('medium');
  });

  it('flags an explicit USER root', () => {
    const text = ['FROM node:18.19.0', 'USER root', 'CMD ["node", "server.js"]'].join('\n');
    const issues = dockerfileIssues([{ path: 'Dockerfile', text }]);
    expect(issuesOf('config/docker-root-user', issues)).toHaveLength(1);
  });

  it('does not flag a non-root USER', () => {
    const text = ['FROM node:18.19.0', 'RUN useradd -m appuser', 'USER appuser', 'CMD ["node", "server.js"]'].join('\n');
    const issues = dockerfileIssues([{ path: 'Dockerfile', text }]);
    expect(issuesOf('config/docker-root-user', issues)).toHaveLength(0);
  });

  it('judges the final stage in a multi-stage build (no inherited USER)', () => {
    const text = [
      'FROM node:18.19.0 AS builder',
      'RUN npm install',
      'USER node',
      'FROM node:18.19.0-alpine',
      'COPY --from=builder /app /app',
      'CMD ["node", "server.js"]',
    ].join('\n');
    const issues = dockerfileIssues([{ path: 'Dockerfile', text }]);
    expect(issuesOf('config/docker-root-user', issues)).toHaveLength(1);
  });

  it('inherits a non-root USER from an earlier stage referenced by alias', () => {
    const text = [
      'FROM node:18.19.0 AS base',
      'RUN useradd -m appuser',
      'USER appuser',
      'FROM base AS final',
      'CMD ["node", "server.js"]',
    ].join('\n');
    const issues = dockerfileIssues([{ path: 'Dockerfile', text }]);
    expect(issuesOf('config/docker-root-user', issues)).toHaveLength(0);
  });
});

describe('config/docker-latest-tag', () => {
  it('flags :latest', () => {
    const text = 'FROM node:latest\nCMD ["node", "server.js"]';
    const issues = dockerfileIssues([{ path: 'Dockerfile', text }]);
    expect(issuesOf('config/docker-latest-tag', issues)).toHaveLength(1);
  });

  it('flags a missing tag (implicit latest)', () => {
    const text = 'FROM node\nCMD ["node", "server.js"]';
    const issues = dockerfileIssues([{ path: 'Dockerfile', text }]);
    expect(issuesOf('config/docker-latest-tag', issues)).toHaveLength(1);
  });

  it('does not flag a pinned version tag', () => {
    const text = 'FROM node:18.19.0\nCMD ["node", "server.js"]';
    const issues = dockerfileIssues([{ path: 'Dockerfile', text }]);
    expect(issuesOf('config/docker-latest-tag', issues)).toHaveLength(0);
  });

  it('does not flag a digest-pinned image', () => {
    const text = 'FROM node@sha256:' + 'a'.repeat(64) + '\nCMD ["node", "server.js"]';
    const issues = dockerfileIssues([{ path: 'Dockerfile', text }]);
    expect(issuesOf('config/docker-latest-tag', issues)).toHaveLength(0);
  });

  it('does not flag scratch or a reference to an earlier stage alias', () => {
    const text = ['FROM node:18.19.0 AS builder', 'FROM builder', 'FROM scratch AS base2'].join('\n');
    const issues = dockerfileIssues([{ path: 'Dockerfile', text }]);
    expect(issuesOf('config/docker-latest-tag', issues)).toHaveLength(0);
  });
});

describe('config/docker-secret-in-arg-env', () => {
  it('flags ARG with a credential-like name and literal default', () => {
    const text = ['FROM node:18.19.0', 'ARG DB_PASSWORD=supersecret123', 'CMD ["node"]'].join('\n');
    const issues = dockerfileIssues([{ path: 'Dockerfile', text }]);
    const found = issuesOf('config/docker-secret-in-arg-env', issues);
    expect(found).toHaveLength(1);
    expect(found[0]!.severity).toBe('high');
    expect(found[0]!.snippet).not.toContain('supersecret123');
    expect(found[0]!.explanation).not.toContain('supersecret123');
  });

  it('flags ENV with a credential-like name (modern form)', () => {
    const text = ['FROM node:18.19.0', 'ENV API_KEY=abcdef123456', 'CMD ["node"]'].join('\n');
    const issues = dockerfileIssues([{ path: 'Dockerfile', text }]);
    const found = issuesOf('config/docker-secret-in-arg-env', issues);
    expect(found).toHaveLength(1);
    expect(found[0]!.snippet).not.toContain('abcdef123456');
  });

  it('does not flag ARG with no default value', () => {
    const text = ['FROM node:18.19.0', 'ARG DB_PASSWORD', 'CMD ["node"]'].join('\n');
    const issues = dockerfileIssues([{ path: 'Dockerfile', text }]);
    expect(issuesOf('config/docker-secret-in-arg-env', issues)).toHaveLength(0);
  });

  it('does not flag a non-credential ARG name', () => {
    const text = ['FROM node:18.19.0', 'ARG BUILD_VERSION=1.0.0', 'CMD ["node"]'].join('\n');
    const issues = dockerfileIssues([{ path: 'Dockerfile', text }]);
    expect(issuesOf('config/docker-secret-in-arg-env', issues)).toHaveLength(0);
  });
});

describe('config/docker-curl-pipe-shell', () => {
  it('flags curl | bash', () => {
    const text = ['FROM node:18.19.0', 'RUN curl -sSL https://get.example.com | bash', 'CMD ["node"]'].join('\n');
    const issues = dockerfileIssues([{ path: 'Dockerfile', text }]);
    const found = issuesOf('config/docker-curl-pipe-shell', issues);
    expect(found).toHaveLength(1);
    expect(found[0]!.severity).toBe('high');
  });

  it('flags wget -O- | sh across a line continuation, reporting the first physical line', () => {
    const text = ['FROM node:18.19.0', 'RUN wget -O- \\', '    https://get.example.com/install.sh | sh', 'CMD ["node"]'].join('\n');
    const issues = dockerfileIssues([{ path: 'Dockerfile', text }]);
    const found = issuesOf('config/docker-curl-pipe-shell', issues);
    expect(found).toHaveLength(1);
    expect(found[0]!.startLine).toBe(2);
  });

  it('does not flag curl downloading to a file without piping to a shell', () => {
    const text = [
      'FROM node:18.19.0',
      'RUN curl -o installer.sh https://example.com/install.sh && chmod +x installer.sh && ./installer.sh',
      'CMD ["node"]',
    ].join('\n');
    const issues = dockerfileIssues([{ path: 'Dockerfile', text }]);
    expect(issuesOf('config/docker-curl-pipe-shell', issues)).toHaveLength(0);
  });
});

describe('config/env-file-committed', () => {
  it('flags a committed .env with a real-looking value', () => {
    const text = 'DB_PASSWORD=S0methingReal!23\nOTHER=1\n';
    const issues = envFileCommittedIssues([{ path: '.env', text }]);
    expect(issues).toHaveLength(1);
    expect(issues[0]!.severity).toBe('high');
    expect(issues[0]!.snippet).not.toContain('S0methingReal!23');
  });

  it('does not flag .env.example', () => {
    const text = 'DB_PASSWORD=S0methingReal!23\n';
    const issues = envFileCommittedIssues([{ path: '.env.example', text }]);
    expect(issues).toHaveLength(0);
  });

  it('does not flag a .env with only placeholder values', () => {
    const text = 'DB_PASSWORD=changeme\nAPI_KEY=your_api_key_here\n';
    const issues = envFileCommittedIssues([{ path: '.env', text }]);
    expect(issues).toHaveLength(0);
  });
});

describe('config/client-exposed-credential', () => {
  it('flags a client-exposed credential-shaped name in a .env file', () => {
    const issues = clientExposedCredentialIssues([{ path: '.env', text: 'NEXT_PUBLIC_SECRET_KEY=abc123\n' }]);
    expect(issues).toHaveLength(1);
    expect(issues[0]!.severity).toBe('high');
  });

  it('does not flag known-safe public suffixes', () => {
    const issues = clientExposedCredentialIssues([
      { path: '.env', text: 'NEXT_PUBLIC_SUPABASE_ANON_KEY=abc123\nVITE_GA_MEASUREMENT_ID=G-ABC123\n' },
    ]);
    expect(issues).toHaveLength(0);
  });

  it('flags process.env.NEXT_PUBLIC_* usage in code', () => {
    const text = 'export const key = process.env.NEXT_PUBLIC_API_KEY;\n';
    const issues = clientExposedCredentialIssues([{ path: 'src/config.ts', text }]);
    expect(issues).toHaveLength(1);
  });

  it('flags import.meta.env.VITE_* usage in code', () => {
    const text = 'const token = import.meta.env.VITE_SECRET_TOKEN;\n';
    const issues = clientExposedCredentialIssues([{ path: 'src/config.ts', text }]);
    expect(issues).toHaveLength(1);
  });

  it('does not flag a server-only credential (no public prefix)', () => {
    const text = 'const key = process.env.API_KEY;\n';
    const issues = clientExposedCredentialIssues([{ path: 'src/config.ts', text }]);
    expect(issues).toHaveLength(0);
  });

  it('isClientExposedCredentialName exercises prefix and suffix rules directly', () => {
    expect(isClientExposedCredentialName('NEXT_PUBLIC_SECRET_KEY')).toBe(true);
    expect(isClientExposedCredentialName('NEXT_PUBLIC_SUPABASE_ANON_KEY')).toBe(false);
    expect(isClientExposedCredentialName('VITE_SITE_KEY')).toBe(false);
    expect(isClientExposedCredentialName('SECRET_KEY')).toBe(false); // no public prefix
    expect(isClientExposedCredentialName('NEXT_PUBLIC_API_URL')).toBe(false); // not credential-shaped
  });
});

describe('configIssues aggregator', () => {
  it('routes files to the right rule set and never leaks a credential value', () => {
    const files = [
      {
        path: WF,
        text: ['on: pull_request_target', 'jobs:', '  build:', '    steps:', '      - uses: actions/checkout@v4', '        with:', '          ref: ${{ github.event.pull_request.head.sha }}'].join('\n'),
      },
      { path: 'Dockerfile', text: ['FROM node:18.19.0', 'ARG SECRET_TOKEN=verySecretValue999', 'CMD ["node"]'].join('\n') },
      { path: '.env', text: 'STRIPE_SECRET=sk_' + 'live_realvaluethatshouldneverappear\n' },
    ];
    const issues = configIssues(files);
    const ruleIds = new Set(issues.map((i) => i.ruleId));
    expect(ruleIds.has('config/gha-pull-request-target-checkout')).toBe(true);
    expect(ruleIds.has('config/docker-secret-in-arg-env')).toBe(true);
    expect(ruleIds.has('config/env-file-committed')).toBe(true);
    for (const issue of issues) {
      expect(issue.snippet).not.toContain('verySecretValue999');
      expect(issue.snippet).not.toContain('realvaluethatshouldneverappear');
      expect(issue.explanation).not.toContain('verySecretValue999');
      expect(issue.explanation).not.toContain('realvaluethatshouldneverappear');
      expect(issue.snippet.length).toBeLessThanOrEqual(300);
    }
  });
});

describe('performance: linear time on adversarial input', () => {
  it('handles a 2 MiB adversarial workflow file quickly', () => {
    const junkLine = 'x'.repeat(2000) + ' ${{ not.a.real.context }}';
    const lineCount = Math.ceil((2 * 1024 * 1024) / junkLine.length);
    const runBody = Array.from({ length: lineCount }, () => `          echo "${junkLine}"`).join('\n');
    const text = ['on: pull_request_target', 'jobs:', '  build:', '    steps:', '      - run: |', runBody].join('\n');
    const t0 = performance.now();
    const issues = githubActionsIssues([{ path: WF, text }]);
    const elapsed = performance.now() - t0;
    expect(Array.isArray(issues)).toBe(true);
    expect(elapsed).toBeLessThan(4000);
  }, 20_000);

  it('handles a 2 MiB adversarial Dockerfile quickly', () => {
    const junkLine = 'RUN echo "' + 'y'.repeat(2000) + '" && true';
    const lineCount = Math.ceil((2 * 1024 * 1024) / junkLine.length);
    const text = ['FROM node:18.19.0', ...Array.from({ length: lineCount }, () => junkLine), 'CMD ["node"]'].join('\n');
    const t0 = performance.now();
    const issues = dockerfileIssues([{ path: 'Dockerfile', text }]);
    const elapsed = performance.now() - t0;
    expect(Array.isArray(issues)).toBe(true);
    expect(elapsed).toBeLessThan(4000);
  }, 20_000);
});

describe('envExposureIssues combines both rules', () => {
  it('aggregates env-file-committed and client-exposed-credential', () => {
    const issues = envExposureIssues([{ path: '.env', text: 'DB_PASSWORD=RealValue123\nNEXT_PUBLIC_SECRET_KEY=abc\n' }]);
    const ruleIds = new Set(issues.map((i) => i.ruleId));
    expect(ruleIds.has('config/env-file-committed')).toBe(true);
    expect(ruleIds.has('config/client-exposed-credential')).toBe(true);
  });
});
