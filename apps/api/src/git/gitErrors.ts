import { AppError } from '../errors/AppError';
import { ProcessError } from '../process/runProcess';
import { scrubSecrets } from '../security/scrub';

const REF_NOT_FOUND = /couldn't find remote ref|Remote branch .+ not found|unknown revision|not a valid object name|reference is not a tree|did not match any file|invalid reference/i;
const AUTH = /Authentication failed|could not read (Username|Password)|terminal prompts disabled|returned error: 40[13]|HTTP Basic: Access denied|Invalid username or password|Write access to repository not granted/i;
const REPO_NOT_FOUND = /Repository not found|repository '.+' not found|does not appear to be a git repository|returned error: 404/i;
const NETWORK = /Could not resolve host|Failed to connect|Connection (timed out|reset|refused)|Operation timed out|early EOF|RPC failed|remote end hung up|returned error: 5\d\d|SSL|TLS|schannel|gnutls/i;

/** Maps git's stderr to a typed AppError. The user message never contains raw stderr. */
export function classifyGitFailure(stderr: string, ctx: { hasToken: boolean }): AppError {
  const details = { stderr: scrubSecrets(stderr.slice(-2_000)) };
  if (REF_NOT_FOUND.test(stderr)) {
    return new AppError('REF_NOT_FOUND', 'permanent', 'Branch, tag or commit not found in this repository', { details });
  }
  if (AUTH.test(stderr)) {
    return ctx.hasToken
      ? new AppError('AUTH_INVALID', 'permanent', 'GitHub rejected the token, or it lacks Contents: read access to this repository', { details })
      : new AppError('AUTH_REQUIRED', 'permanent', 'This repository requires a token (it may be private). Provide a token with Contents: read access.', { details });
  }
  if (REPO_NOT_FOUND.test(stderr)) {
    return new AppError('REPO_NOT_FOUND', 'permanent', 'Repository not found, or the token cannot access it', { details });
  }
  if (NETWORK.test(stderr)) {
    return new AppError('INTERNAL', 'transient', 'Network error while talking to GitHub', { details });
  }
  return new AppError('INTERNAL', 'permanent', 'git failed unexpectedly', { details });
}

export function fromProcessError(err: ProcessError): AppError {
  const details = { stderr: scrubSecrets(err.stderrTail.slice(-2_000)) };
  switch (err.reason) {
    case 'timeout':
    case 'stall':
      return new AppError('CLONE_TIMEOUT', 'transient', 'Fetching the repository took too long', { cause: err, details });
    case 'aborted':
      return new AppError('CANCELLED', 'cancelled', 'Operation was cancelled', { cause: err });
    case 'output_limit':
      return new AppError('REPO_TOO_LARGE', 'permanent', 'The repository is too large to scan', { cause: err, details });
    case 'spawn':
      return new AppError('INTERNAL', 'permanent', 'git is not installed or not on PATH', { cause: err, details });
  }
}
