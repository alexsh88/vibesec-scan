import { spawn, type ChildProcess } from 'node:child_process';

export type ProcessFailure = 'timeout' | 'stall' | 'aborted' | 'spawn' | 'output_limit';

/** stderrTail is RAW process output and may contain secrets: scrub before logging or displaying. */
export class ProcessError extends Error {
  constructor(readonly reason: ProcessFailure, message: string, readonly stderrTail: string) {
    super(message);
    this.name = 'ProcessError';
  }
}

export type RunOptions = {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  signal?: AbortSignal;
  timeoutMs: number;
  /** Abort when neither stdout nor stderr produced data for this long. */
  stallMs?: number;
  maxStdoutBytes?: number;
  onStderrLine?: (line: string) => void;
  /** Called on any output; use it to keep the scan watchdog alive. */
  onActivity?: () => void;
  /** @internal undocumented: how long to wait for `close` after killTree before settling anyway. Default 5_000. */
  killGraceMs?: number;
  /** @internal undocumented: override for process-tree kill, for tests. */
  _killTree?: (child: ChildProcess) => void;
};

export type RunResult = { code: number; stdout: string; stderr: string };

const STDERR_TAIL_BYTES = 8_192;

/** Spawns without a shell. Resolves for any exit code; rejects only for the ProcessFailure reasons. */
export function runProcess(cmd: string, args: readonly string[], opts: RunOptions): Promise<RunResult> {
  return new Promise<RunResult>((resolve, reject) => {
    if (opts.signal?.aborted) {
      reject(new ProcessError('aborted', `${cmd} aborted`, ''));
      return;
    }

    const child = spawn(cmd, args, {
      cwd: opts.cwd, env: opts.env, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    });

    const stdout: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrTail = '';
    let lineBuffer = '';
    let failure: ProcessError | null = null;
    let settled = false;
    let stallTimer: NodeJS.Timeout | undefined;
    let killGraceTimer: NodeJS.Timeout | undefined;
    const killTreeImpl = opts._killTree ?? killTree;

    const fail = (reason: ProcessFailure, message: string) => {
      if (failure || settled) return;
      failure = new ProcessError(reason, message, stderrTail);
      killTreeImpl(child);
      // Belt-and-suspenders: if killTree doesn't produce a `close` event (e.g. a wedged process
      // on a platform where the kill signal is ignored), don't hang forever waiting for it.
      killGraceTimer = setTimeout(() => finish(null), opts.killGraceMs ?? 5_000);
      killGraceTimer.unref();
    };

    const totalTimer = setTimeout(() => fail('timeout', `${cmd} timed out after ${opts.timeoutMs} ms`), opts.timeoutMs);
    const armStall = () => {
      if (!opts.stallMs || settled || failure) return;
      clearTimeout(stallTimer);
      stallTimer = setTimeout(() => fail('stall', `${cmd} made no progress for ${opts.stallMs} ms`), opts.stallMs);
    };
    // Arm only once the child has actually started: cold start (process spawn, OS scheduling)
    // shouldn't eat into the stall budget before the child has had a chance to produce output.
    child.on('spawn', armStall);

    const onAbort = () => fail('aborted', `${cmd} aborted`);
    opts.signal?.addEventListener('abort', onAbort, { once: true });

    const activity = () => {
      armStall();
      opts.onActivity?.();
    };

    child.stdout?.on('data', (chunk: Buffer) => {
      activity();
      stdoutBytes += chunk.length;
      if (opts.maxStdoutBytes !== undefined && stdoutBytes > opts.maxStdoutBytes) {
        fail('output_limit', `${cmd} produced more than ${opts.maxStdoutBytes} bytes of output`);
        return;
      }
      stdout.push(chunk);
    });

    child.stderr?.on('data', (chunk: Buffer) => {
      activity();
      const text = chunk.toString('utf8');
      stderrTail = (stderrTail + text).slice(-STDERR_TAIL_BYTES);
      if (!opts.onStderrLine) return;
      lineBuffer += text;
      const parts = lineBuffer.split(/\r\n|\r|\n/);
      lineBuffer = parts.pop() ?? '';
      for (const part of parts) if (part) opts.onStderrLine(part);
    });

    const finish = (code: number | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(totalTimer);
      clearTimeout(stallTimer);
      clearTimeout(killGraceTimer);
      opts.signal?.removeEventListener('abort', onAbort);
      if (opts.onStderrLine && lineBuffer) opts.onStderrLine(lineBuffer);
      if (failure) reject(failure);
      else resolve({ code: code ?? -1, stdout: Buffer.concat(stdout).toString('utf8'), stderr: stderrTail });
    };

    child.on('error', (err) => {
      failure ??= new ProcessError('spawn', `failed to start ${cmd}: ${err.message}`, stderrTail);
      finish(null);
    });
    child.on('close', (code) => finish(code));
  });
}

function killTree(child: ChildProcess): void {
  if (child.pid === undefined || child.exitCode !== null) return;
  if (process.platform === 'win32') {
    const killer = spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
    killer.on('error', () => child.kill());
  } else {
    child.kill('SIGKILL');
  }
}
