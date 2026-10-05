import { describe, expect, it } from 'vitest';
import { gitEnv, safeGitFlags } from '../src/git/gitEnv';

const base = { PATH: '/usr/bin', HOME: '/home/x', ANTHROPIC_API_KEY: 'sk-ant-secret', GIT_DIR: '/evil', GIT_CONFIG_GLOBAL: '/home/x/.gitconfig' };

describe('gitEnv', () => {
  it('keeps only an allow-list of host variables', () => {
    const env = gitEnv({ emptyConfigPath: '/w/.gitconfig-empty', homeDir: '/w/.home', base });
    expect(env.PATH).toBe('/usr/bin');
    expect(env.ANTHROPIC_API_KEY).toBeUndefined();
    expect(env.GIT_DIR).toBeUndefined();
  });

  it('never exposes the host HOME/USERPROFILE (so ~/.netrc / _netrc can never authenticate git)', () => {
    const host = { ...base, USERPROFILE: 'C:\\Users\\op', XDG_CONFIG_HOME: '/home/x/.config' };
    const env = gitEnv({ emptyConfigPath: '/w/e', homeDir: '/w/.home', base: host });
    expect(env.HOME).toBe('/w/.home');
    expect(env.USERPROFILE).toBe('/w/.home');
    expect(env.XDG_CONFIG_HOME).toBe('/w/.home');
    expect(Object.values(env)).not.toContain('/home/x');
    expect(Object.values(env)).not.toContain('C:\\Users\\op');
  });

  it('passes proxy settings through', () => {
    const proxies = {
      HTTP_PROXY: 'http://p:1', HTTPS_PROXY: 'http://p:2', NO_PROXY: 'localhost',
      http_proxy: 'http://p:3', https_proxy: 'http://p:4', no_proxy: 'example.com',
    };
    const env = gitEnv({ emptyConfigPath: '/w/e', homeDir: '/w/.home', base: { ...base, ...proxies } });
    expect(env).toMatchObject(proxies);
  });

  it('isolates git from host config, prompts and credential helpers', () => {
    const env = gitEnv({ emptyConfigPath: '/w/.gitconfig-empty', homeDir: '/w/.home', base });
    expect(env).toMatchObject({
      GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/w/.gitconfig-empty', GIT_LFS_SKIP_SMUDGE: '1',
    });
    const pairs = configPairs(env);
    expect(pairs).toContainEqual(['credential.helper', '']);
  });

  it('passes the token only as a github.com-scoped extraHeader, never in argv or URL', () => {
    const env = gitEnv({ emptyConfigPath: '/w/e', homeDir: '/w/.home', base, auth: { token: 'ghp_TOKEN123' } });
    const header = configPairs(env).find(([k]) => k === 'http.https://github.com/.extraHeader');
    expect(header?.[1]).toBe(`Authorization: Basic ${Buffer.from('x-access-token:ghp_TOKEN123').toString('base64')}`);
    expect(JSON.stringify(safeGitFlags(false))).not.toContain('ghp_');
  });

  it('adds no auth header without a token', () => {
    const env = gitEnv({ emptyConfigPath: '/w/e', homeDir: '/w/.home', base });
    expect(configPairs(env).some(([k]) => k.includes('extraHeader'))).toBe(false);
  });
});

describe('safeGitFlags', () => {
  it('disables symlinks and non-https transports', () => {
    const flags = safeGitFlags(false);
    expect(flags).toEqual(expect.arrayContaining(['core.symlinks=false', 'protocol.allow=never', 'protocol.https.allow=always']));
    expect(flags).not.toContain('protocol.file.allow=always');
  });

  it('allows file:// only when explicitly requested (tests / local fixtures)', () => {
    expect(safeGitFlags(true)).toContain('protocol.file.allow=always');
  });
});

function configPairs(env: NodeJS.ProcessEnv): [string, string][] {
  const n = Number(env.GIT_CONFIG_COUNT);
  return Array.from({ length: n }, (_, i) => [env[`GIT_CONFIG_KEY_${i}`]!, env[`GIT_CONFIG_VALUE_${i}`]!]);
}
