// Deterministic Dockerfile security rules. Pure, synchronous, no network/LLM.
// Line continuations (`\` at end of line) are joined before parsing an instruction's arguments,
// but every finding still reports the *first* physical line of that instruction.

import type { RawCodeIssue } from '../types';

const DOCKERFILE_PATH_RE = /(^|\/)(Dockerfile(\.[^/]+)?|[^/]+\.[Dd]ockerfile|Containerfile(\.[^/]+)?)$/;
const MAX_LINE = 16 * 1024;
const SNIPPET_LIMIT = 300;

export function isDockerfile(path: string): boolean {
  return DOCKERFILE_PATH_RE.test(path);
}

function clamp(line: string): string {
  return line.length > MAX_LINE ? line.slice(0, MAX_LINE) : line;
}

function snippetOf(line: string | undefined): string {
  const l = (line ?? '').trim();
  return l.length > SNIPPET_LIMIT ? l.slice(0, SNIPPET_LIMIT) : l;
}

function makeIssue(opts: {
  ruleId: string;
  title: string;
  severity: RawCodeIssue['severity'];
  cwe?: string;
  file: string;
  line: number;
  snippet: string;
  explanation: string;
  impact: string;
  remediation: string;
}): RawCodeIssue {
  const issue: RawCodeIssue = {
    ruleId: opts.ruleId,
    title: opts.title,
    severity: opts.severity,
    confidence: 'high',
    file: opts.file,
    startLine: opts.line,
    endLine: opts.line,
    snippet: opts.snippet,
    explanation: opts.explanation,
    impact: opts.impact,
    remediation: opts.remediation,
  };
  if (opts.cwe) issue.cwe = opts.cwe;
  return issue;
}

// --- logical-line parsing (joins `\` continuations) -----------------------------------------------

type LogicalLine = { startLine: number; instruction: string; rest: string };

function buildLogicalLines(text: string): LogicalLine[] {
  const raw = text.split('\n').map((l) => clamp(l.replace(/\r$/, '')));
  const out: LogicalLine[] = [];
  let i = 0;
  while (i < raw.length) {
    const startLine = i + 1;
    let content = raw[i] ?? '';
    const trimmedFirst = content.trim();
    if (trimmedFirst === '' || trimmedFirst.startsWith('#')) {
      i++;
      continue;
    }
    while (/\\\s*$/.test(content) && i + 1 < raw.length) {
      i++;
      content = content.replace(/\\\s*$/, ' ') + (raw[i] ?? '');
    }
    const m = /^(\S+)\s*(.*)$/.exec(content.trim());
    if (m) out.push({ startLine, instruction: m[1]!.toUpperCase(), rest: m[2] ?? '' });
    i++;
  }
  return out;
}

function stripQuotes(value: string): string {
  const v = value.trim();
  if (v.length >= 2 && ((v[0] === '"' && v[v.length - 1] === '"') || (v[0] === "'" && v[v.length - 1] === "'"))) {
    return v.slice(1, -1);
  }
  return v;
}

function redactLine(rawLine: string, value: string): string {
  if (value === '' || !rawLine.includes(value)) return snippetOf(rawLine);
  const redacted = value.length <= 2 ? '…' : value.slice(0, 2) + '…';
  return snippetOf(rawLine.replace(value, redacted));
}

// --- rule: docker-secret-in-arg-env ----------------------------------------------------------------

const CRED_NAME_RE = /PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY/i;
const ENV_PAIR_RE = /([A-Za-z_][A-Za-z0-9_]*)=("(?:[^"\\]|\\.){0,2048}"|'[^']{0,2048}'|\S{0,2048})/g;

function checkSecretAssignment(name: string, value: string, path: string, line: number, rawLine: string): RawCodeIssue | null {
  if (value === '' || !CRED_NAME_RE.test(name)) return null;
  return makeIssue({
    ruleId: 'config/docker-secret-in-arg-env',
    title: 'Credential-like build ARG/ENV with a literal default',
    severity: 'high',
    cwe: 'CWE-798',
    file: path,
    line,
    snippet: redactLine(rawLine, value),
    explanation: `'${name}' looks like a credential and has a literal default value baked into the image.`,
    impact: 'ARG/ENV defaults are stored in the image history/layers and are readable by anyone who can pull or inspect the image.',
    remediation: 'Pass secrets at runtime (e.g. a mounted secret or orchestrator secret store), never as an ARG/ENV default.',
  });
}

function checkArgEnv(ll: LogicalLine, path: string, rawLine: string): RawCodeIssue[] {
  const issues: RawCodeIssue[] = [];
  const rest = ll.rest.trim();
  if (ll.instruction === 'ARG') {
    const m = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/.exec(rest);
    if (!m) return issues;
    const value = stripQuotes(m[2]!);
    const issue = checkSecretAssignment(m[1]!, value, path, ll.startLine, rawLine);
    if (issue) issues.push(issue);
    return issues;
  }
  if (ll.instruction === 'ENV') {
    if (rest.includes('=')) {
      let any = false;
      ENV_PAIR_RE.lastIndex = 0;
      let match = ENV_PAIR_RE.exec(rest);
      while (match !== null) {
        any = true;
        const value = stripQuotes(match[2]!);
        const issue = checkSecretAssignment(match[1]!, value, path, ll.startLine, rawLine);
        if (issue) issues.push(issue);
        match = ENV_PAIR_RE.exec(rest);
      }
      if (any) return issues;
    }
    const legacy = /^(\S+)\s+(.+)$/.exec(rest);
    if (legacy) {
      const issue = checkSecretAssignment(legacy[1]!, legacy[2]!.trim(), path, ll.startLine, rawLine);
      if (issue) issues.push(issue);
    }
  }
  return issues;
}

// --- rule: docker-curl-pipe-shell ------------------------------------------------------------------

const CURL_PIPE_RE = /\b(?:curl|wget)\b[^\n]{0,1000}\|\s{0,20}(?:sudo\s{1,10})?(?:[\w./-]{1,100}\/)?(?:sh|bash|zsh|ash)\b/i;

function checkCurlPipeShell(ll: LogicalLine, path: string, rawLine: string): RawCodeIssue | null {
  if (ll.instruction !== 'RUN') return null;
  if (!CURL_PIPE_RE.test(ll.rest)) return null;
  return makeIssue({
    ruleId: 'config/docker-curl-pipe-shell',
    title: 'Piping a remote download directly into a shell',
    severity: 'high',
    cwe: 'CWE-829',
    file: path,
    line: ll.startLine,
    snippet: snippetOf(rawLine),
    explanation: 'This RUN instruction downloads a remote script and pipes it straight into a shell.',
    impact: 'There is no integrity check on the downloaded content; a compromised server or MITM runs arbitrary code during the image build.',
    remediation: 'Download to a file, verify its checksum/signature, then execute it.',
  });
}

// --- stages (FROM/USER tracking for docker-root-user and docker-latest-tag) -----------------------

type Stage = {
  index: number;
  name: string | null;
  fromImage: string | null;
  fromLine: number;
  users: { value: string; line: number }[];
};

const FROM_FLAG_RE = /^--/;

function parseFromArgs(rest: string): { image: string | null; alias: string | null } {
  const tokens = rest.trim().split(/\s+/).filter((t) => t.length > 0);
  let i = 0;
  while (i < tokens.length && FROM_FLAG_RE.test(tokens[i]!)) i++;
  const image = tokens[i] ?? null;
  let alias: string | null = null;
  if (tokens[i + 1] && /^as$/i.test(tokens[i + 1]!)) alias = tokens[i + 2] ?? null;
  return { image, alias };
}

function buildStages(lines: readonly LogicalLine[]): Stage[] {
  const stages: Stage[] = [];
  let current: Stage | null = null;
  for (const ll of lines) {
    if (ll.instruction === 'FROM') {
      const { image, alias } = parseFromArgs(ll.rest);
      current = { index: stages.length, name: alias, fromImage: image, fromLine: ll.startLine, users: [] };
      stages.push(current);
    } else if (ll.instruction === 'USER' && current) {
      current.users.push({ value: ll.rest.trim(), line: ll.startLine });
    }
  }
  return stages;
}

function resolveEffectiveUser(
  stageIdx: number,
  stages: readonly Stage[],
  byName: ReadonlyMap<string, number>,
  visited: Set<number> = new Set(),
): { value: string; line: number } | null {
  if (visited.has(stageIdx)) return null;
  visited.add(stageIdx);
  const stage = stages[stageIdx];
  if (!stage) return null;
  if (stage.users.length > 0) return stage.users[stage.users.length - 1]!;
  const baseIdx = stage.fromImage ? byName.get(stage.fromImage) : undefined;
  if (baseIdx !== undefined && baseIdx < stageIdx) return resolveEffectiveUser(baseIdx, stages, byName, visited);
  return null;
}

function isRootUser(value: string): boolean {
  const user = stripQuotes(value).split(':')[0]!.trim();
  return user === 'root' || user === '0';
}

function checkRootUser(path: string, lines: readonly LogicalLine[], rawLines: readonly string[]): RawCodeIssue | null {
  const stages = buildStages(lines);
  if (stages.length === 0) return null;
  const byName = new Map<string, number>();
  for (const s of stages) if (s.name) byName.set(s.name, s.index);

  const finalIdx = stages.length - 1;
  const effective = resolveEffectiveUser(finalIdx, stages, byName);

  if (!effective) {
    const line = stages[finalIdx]!.fromLine;
    return makeIssue({
      ruleId: 'config/docker-root-user',
      title: 'Container runs as root (no USER instruction)',
      severity: 'medium',
      cwe: 'CWE-250',
      file: path,
      line,
      snippet: snippetOf(rawLines[line - 1]),
      explanation: 'The final stage never sets a USER, so the container runs as root by default.',
      impact: 'A compromised process running as root can take over the whole container (and more easily escape it).',
      remediation: 'Create an unprivileged user and switch to it with USER before the final CMD/ENTRYPOINT.',
    });
  }
  if (isRootUser(effective.value)) {
    return makeIssue({
      ruleId: 'config/docker-root-user',
      title: 'Container explicitly runs as root',
      severity: 'medium',
      cwe: 'CWE-250',
      file: path,
      line: effective.line,
      snippet: snippetOf(rawLines[effective.line - 1]),
      explanation: `The last USER in the final stage is '${effective.value.trim()}'.`,
      impact: 'A compromised process running as root can take over the whole container (and more easily escape it).',
      remediation: 'Create an unprivileged user and switch to it with USER before the final CMD/ENTRYPOINT.',
    });
  }
  return null;
}

// --- rule: docker-latest-tag ------------------------------------------------------------------------

function parseImageTag(image: string): { hasDigest: boolean; tag: string | null } {
  if (image.includes('@')) return { hasDigest: true, tag: null };
  const lastSlash = image.lastIndexOf('/');
  const lastColon = image.lastIndexOf(':');
  if (lastColon > lastSlash) return { hasDigest: false, tag: image.slice(lastColon + 1) };
  return { hasDigest: false, tag: null };
}

function checkLatestTag(path: string, stages: readonly Stage[], rawLines: readonly string[]): RawCodeIssue[] {
  const byName = new Set<string>();
  for (const s of stages) if (s.name) byName.add(s.name);
  const issues: RawCodeIssue[] = [];
  for (const s of stages) {
    if (!s.fromImage || s.fromImage.toLowerCase() === 'scratch') continue;
    if (byName.has(s.fromImage)) continue; // references an earlier stage, not an external image
    const { hasDigest, tag } = parseImageTag(s.fromImage);
    if (hasDigest) continue;
    if (tag !== null && tag !== 'latest') continue;
    issues.push(
      makeIssue({
        ruleId: 'config/docker-latest-tag',
        title: tag === 'latest' ? 'Base image pinned to :latest' : 'Base image has no tag (defaults to latest)',
        severity: 'low',
        cwe: 'CWE-829',
        file: path,
        line: s.fromLine,
        snippet: snippetOf(rawLines[s.fromLine - 1]),
        explanation: `FROM ${s.fromImage} is not pinned to a specific version or digest.`,
        impact: 'The base image can change contents between builds without notice, breaking reproducibility and supply-chain guarantees.',
        remediation: 'Pin the base image to a specific version tag or, better, a content digest (image@sha256:…).',
      }),
    );
  }
  return issues;
}

// --- public entry point ---------------------------------------------------------------------------

export function dockerfileIssues(files: readonly { path: string; text: string }[]): RawCodeIssue[] {
  const issues: RawCodeIssue[] = [];
  for (const file of files) {
    if (!isDockerfile(file.path)) continue;
    const rawLines = file.text.split('\n').map((l) => l.replace(/\r$/, ''));
    const lines = buildLogicalLines(file.text);

    for (const ll of lines) {
      const rawLine = rawLines[ll.startLine - 1] ?? '';
      issues.push(...checkArgEnv(ll, file.path, rawLine));
      const curl = checkCurlPipeShell(ll, file.path, rawLine);
      if (curl) issues.push(curl);
    }

    const stages = buildStages(lines);
    const rootUser = checkRootUser(file.path, lines, rawLines);
    if (rootUser) issues.push(rootUser);
    issues.push(...checkLatestTag(file.path, stages, rawLines));
  }
  return issues;
}
