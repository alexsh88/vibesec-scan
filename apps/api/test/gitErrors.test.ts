import { describe, expect, it } from 'vitest';
import { classifyGitFailure, fromProcessError } from '../src/git/gitErrors';
import { ProcessError } from '../src/process/runProcess';

describe('classifyGitFailure', () => {
  it.each([
    ["fatal: couldn't find remote ref refs/heads/nope", 'REF_NOT_FOUND', 'permanent'],
    ['fatal: Remote branch nope not found in upstream origin', 'REF_NOT_FOUND', 'permanent'],
    ["fatal: reference is not a tree: deadbeef", 'REF_NOT_FOUND', 'permanent'],
    ['remote: Repository not found.\nfatal: repository \'https://github.com/a/b.git/\' not found', 'REPO_NOT_FOUND', 'permanent'],
    ['fatal: unable to access \'https://github.com/a/b.git/\': Could not resolve host: github.com', 'INTERNAL', 'transient'],
    ['error: RPC failed; curl 56 Recv failure: Connection reset by peer', 'INTERNAL', 'transient'],
    ['fatal: the remote end hung up unexpectedly', 'INTERNAL', 'transient'],
    ['fatal: something unexpected', 'INTERNAL', 'permanent'],
  ])('%s → %s', (stderr, code, kind) => {
    expect(classifyGitFailure(stderr, { hasToken: false })).toMatchObject({ code, kind });
  });

  it('maps auth failures to AUTH_REQUIRED without a token and AUTH_INVALID with one', () => {
    const stderr = "fatal: could not read Username for 'https://github.com': terminal prompts disabled";
    expect(classifyGitFailure(stderr, { hasToken: false }).code).toBe('AUTH_REQUIRED');
    expect(classifyGitFailure('remote: Invalid username or password.\nfatal: Authentication failed', { hasToken: true }).code).toBe('AUTH_INVALID');
  });

  it('never puts raw stderr in the user message and scrubs it in details', () => {
    const err = classifyGitFailure('fatal: weird ghp_0123456789abcdefghijABCDEFGHIJ012345', { hasToken: true });
    expect(err.userMessage).not.toContain('ghp_');
    expect(JSON.stringify(err.details)).not.toContain('ghp_0123456789');
  });
});

describe('fromProcessError', () => {
  it.each([
    ['timeout', 'CLONE_TIMEOUT', 'transient'],
    ['stall', 'CLONE_TIMEOUT', 'transient'],
    ['aborted', 'CANCELLED', 'cancelled'],
    ['spawn', 'INTERNAL', 'permanent'],
    ['output_limit', 'REPO_TOO_LARGE', 'permanent'],
  ] as const)('%s → %s', (reason, code, kind) => {
    expect(fromProcessError(new ProcessError(reason, 'x', ''))).toMatchObject({ code, kind });
  });
});
