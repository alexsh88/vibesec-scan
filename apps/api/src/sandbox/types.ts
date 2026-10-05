import type { Ecosystem } from '../analyzers/dependencies/types';
import type { runProcess } from '../process/runProcess';

export type SandboxAvailability = { ok: true; serverVersion: string } | { ok: false; reason: string };

export type InstallFailureCode = 'SANDBOX_UNAVAILABLE' | 'SANDBOX_TIMEOUT' | 'SANDBOX_INSTALL_FAILED';
export type AnalyzeFailureCode = 'SANDBOX_UNAVAILABLE' | 'SANDBOX_TIMEOUT' | 'SANDBOX_ANALYZE_FAILED';

export type InstallResult =
  | {
    ok: true;
    ecosystem: Ecosystem;
    /** Host dir with the installed packages (node_modules, or the pip --target dir for PyPI). Attacker-controlled
     * content: never follow symlinks inside it on the host; mount it read-only into phase B instead. */
    depsDir: string;
    /** npm/yarn: `npm ls --all --json` output; pnpm: `pnpm ls --json --depth Infinity`; PyPI: pip `--report` JSON.
     * Parsed but unvalidated — the caller validates. null when the tree command produced nothing usable. */
    tree: unknown;
    warnings: string[];
  }
  | { ok: false; code: InstallFailureCode; message: string };

export type AnalyzeResult =
  | { ok: true; usages: unknown /* parsed /out/usages.json, validated later by caller */ }
  | { ok: false; code: AnalyzeFailureCode; message: string };

/**
 * npm installs from the repo's manifest dir (package.json + lockfile only; .npmrc/.yarnrc are never copied).
 * PyPI installs from a host-side pinned requirement list: poetry.lock / uv.lock / Pipfile.lock / requirements
 * are converted to `name==version` lines by the caller, so no build backend or pip config from the repo ever runs.
 */
export type InstallOptions = { scanId: string; signal: AbortSignal } & (
  | { ecosystem: 'npm'; srcDir: string; /** repo-relative, '' for the root */ manifestDir: string }
  | { ecosystem: 'PyPI'; requirements: string[] }
);

export type AnalyzeOptions = {
  scanId: string;
  ecosystem: Ecosystem;
  srcDir: string;
  /** A depsDir returned by install() for the same scan (anything else is refused). */
  depsDir?: string;
  packages: string[];
  signal: AbortSignal;
};

export type RunFn = typeof runProcess;

export type DockerSandboxOptions = {
  workDir: string;
  imagePrefix: string;
  installTimeoutMs?: number;
  analyzeTimeoutMs?: number;
  /** Installed-deps disk cap; larger installs fail with SANDBOX_INSTALL_FAILED and are deleted. Default 1.5 GiB. */
  maxDepsBytes?: number;
  run?: RunFn;
  /** Base environment the docker CLI env allowlist is taken from (default process.env). */
  hostEnv?: NodeJS.ProcessEnv;
  dockerBinary?: string;
};
