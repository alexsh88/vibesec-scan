export type GitAuth = { token?: string };

const HOST_VARS = [
  'PATH', 'Path', 'PATHEXT', 'SYSTEMROOT', 'SystemRoot', 'WINDIR', 'COMSPEC',
  'TEMP', 'TMP', 'TMPDIR', 'LANG',
  'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy',
] as const;

/**
 * Hermetic environment for every git invocation:
 * - only an allow-list of host variables (no API keys, no inherited GIT_* overrides);
 * - HOME/USERPROFILE/XDG_CONFIG_HOME point at a private empty directory, never the operator's home, so
 *   libcurl can never pick up ~/.netrc / _netrc (or any other per-user git/curl config) and authenticate as the host;
 * - no system/global config and no credential helpers, so host credentials (e.g. Git Credential Manager)
 *   can never authenticate a scan the user did not authorize;
 * - the token travels only as an http.extraHeader scoped to https://github.com/, via GIT_CONFIG_* env vars
 *   (never in argv, URLs or .git/config).
 */
export function gitEnv(opts: {
  emptyConfigPath: string; homeDir: string; auth?: GitAuth; base?: NodeJS.ProcessEnv;
}): NodeJS.ProcessEnv {
  const base = opts.base ?? process.env;
  const env: NodeJS.ProcessEnv = {};
  for (const key of HOST_VARS) if (base[key] !== undefined) env[key] = base[key];

  Object.assign(env, {
    HOME: opts.homeDir,
    USERPROFILE: opts.homeDir,
    XDG_CONFIG_HOME: opts.homeDir,
    GIT_TERMINAL_PROMPT: '0',
    GIT_ASKPASS: '',
    SSH_ASKPASS: '',
    GCM_INTERACTIVE: 'never',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: opts.emptyConfigPath,
    GIT_LFS_SKIP_SMUDGE: '1',
    LC_ALL: 'C',
  });

  const pairs: [string, string][] = [['credential.helper', '']];
  if (opts.auth?.token) {
    const basic = Buffer.from(`x-access-token:${opts.auth.token}`).toString('base64');
    pairs.push(['http.https://github.com/.extraHeader', `Authorization: Basic ${basic}`]);
  }
  env.GIT_CONFIG_COUNT = String(pairs.length);
  pairs.forEach(([key, value], i) => {
    env[`GIT_CONFIG_KEY_${i}`] = key;
    env[`GIT_CONFIG_VALUE_${i}`] = value;
  });
  return env;
}

/** `-c` flags placed before every git subcommand. file:// is allowed only for local test fixtures. */
export function safeGitFlags(allowFileProtocol: boolean): string[] {
  const settings = [
    'core.symlinks=false',
    'core.longpaths=true',
    'core.fsmonitor=false',
    'advice.detachedHead=false',
    'protocol.allow=never',
    'protocol.https.allow=always',
    ...(allowFileProtocol ? ['protocol.file.allow=always'] : []),
  ];
  return settings.flatMap((s) => ['-c', s]);
}
