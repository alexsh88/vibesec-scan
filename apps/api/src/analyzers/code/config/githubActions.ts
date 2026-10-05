// Deterministic GitHub Actions workflow security rules. Pure, synchronous, no network/LLM.
// YAML parse errors are tolerated — a malformed workflow simply yields fewer/no findings rather
// than throwing; the `yaml` package keeps giving us a best-effort document + LineCounter either way.

import { LineCounter, parseDocument, isMap, isScalar, isSeq } from 'yaml';
import type { Node } from 'yaml';
import type { RawCodeIssue } from '../types';

const WORKFLOW_PATH_RE = /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i;
const MAX_LINE = 16 * 1024;
const SNIPPET_LIMIT = 300;

export function isGithubActionsWorkflow(path: string): boolean {
  return WORKFLOW_PATH_RE.test(path);
}

function clamp(line: string): string {
  return line.length > MAX_LINE ? line.slice(0, MAX_LINE) : line;
}

function snippetOf(line: string | undefined): string {
  const l = (line ?? '').trim();
  return l.length > SNIPPET_LIMIT ? l.slice(0, SNIPPET_LIMIT) : l;
}

function lineOf(lineCounter: LineCounter, offset: number | undefined): number {
  if (offset === undefined) return 1;
  return lineCounter.linePos(offset).line;
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

// --- yaml node helpers ---------------------------------------------------------------------------

function mapGetNode(node: unknown, key: string): Node | undefined {
  if (!isMap(node)) return undefined;
  for (const pair of node.items) {
    if (isScalar(pair.key) && pair.key.value === key) return pair.value as Node | undefined;
  }
  return undefined;
}

function scalarString(node: unknown): string | undefined {
  if (isScalar(node) && typeof node.value === 'string') return node.value;
  return undefined;
}

function triggerNames(onNode: unknown): Set<string> {
  const names = new Set<string>();
  const s = scalarString(onNode);
  if (s !== undefined) {
    names.add(s);
  } else if (isSeq(onNode)) {
    for (const item of onNode.items) {
      const v = scalarString(item);
      if (v !== undefined) names.add(v);
    }
  } else if (isMap(onNode)) {
    for (const pair of onNode.items) {
      const v = scalarString(pair.key);
      if (v !== undefined) names.add(v);
    }
  }
  return names;
}

type Step = { node: Node; usesNode: Node | undefined; withNode: Node | undefined; runNode: Node | undefined };

function jobEntries(jobsNode: unknown): { name: string; node: Node }[] {
  if (!isMap(jobsNode)) return [];
  const out: { name: string; node: Node }[] = [];
  for (const pair of jobsNode.items) {
    const name = scalarString(pair.key) ?? '?';
    if (pair.value !== undefined && pair.value !== null) out.push({ name, node: pair.value as Node });
  }
  return out;
}

function jobSteps(jobNode: unknown): Step[] {
  const stepsNode = mapGetNode(jobNode, 'steps');
  if (!isSeq(stepsNode)) return [];
  const out: Step[] = [];
  for (const item of stepsNode.items) {
    if (!isMap(item)) continue;
    out.push({
      node: item,
      usesNode: mapGetNode(item, 'uses'),
      withNode: mapGetNode(item, 'with'),
      runNode: mapGetNode(item, 'run'),
    });
  }
  return out;
}

// --- rule: gha-pull-request-target-checkout -------------------------------------------------------

const UNTRUSTED_REF_NEEDLES = ['github.event.pull_request.head', 'github.head_ref'];

function checkPullRequestTargetCheckout(path: string, text: string, triggers: Set<string>, jobs: { name: string; node: Node }[], lc: LineCounter): RawCodeIssue[] {
  if (!triggers.has('pull_request_target')) return [];
  const lines = text.split('\n');
  const issues: RawCodeIssue[] = [];
  for (const { node: jobNode } of jobs) {
    for (const step of jobSteps(jobNode)) {
      const uses = scalarString(step.usesNode);
      if (!uses || !/^actions\/checkout(@|$)/.test(uses)) continue;
      const ref = scalarString(mapGetNode(step.withNode, 'ref'));
      if (ref === undefined) continue;
      if (!UNTRUSTED_REF_NEEDLES.some((n) => ref.includes(n))) continue;
      const line = lineOf(lc, step.node.range?.[0]);
      issues.push(
        makeIssue({
          ruleId: 'config/gha-pull-request-target-checkout',
          title: 'pull_request_target checks out the PR head',
          severity: 'critical',
          cwe: 'CWE-829',
          file: path,
          line,
          snippet: snippetOf(lines[line - 1]),
          explanation: 'This workflow runs on pull_request_target (with write access to secrets and the base repo) but checks out the PR head ref.',
          impact: "A PR author can make the privileged workflow run their own code, exfiltrating secrets or writing to the base repo.",
          remediation: 'Checkout the base ref instead, or switch the trigger to pull_request with no secrets.',
        }),
      );
    }
  }
  return issues;
}

// --- rule: gha-script-injection -------------------------------------------------------------------

const TEMPLATE_EXPR_RE = /\$\{\{([^}]{0,500})\}\}/g;
const SIMPLE_UNTRUSTED_NEEDLES = [
  'github.event.issue.title',
  'github.event.issue.body',
  'github.event.pull_request.title',
  'github.event.pull_request.body',
  'github.event.pull_request.head.ref',
  'github.event.pull_request.head.label',
  'github.event.comment.body',
  'github.event.review.body',
  'github.event.review_comment.body',
  'github.event.discussion.title',
  'github.event.discussion.body',
  'github.event.head_commit.message',
  'github.head_ref',
];

function isUntrustedExpr(expr: string): boolean {
  const e = expr.trim();
  if (SIMPLE_UNTRUSTED_NEEDLES.some((n) => e.includes(n))) return true;
  if (e.includes('github.event.commits.') && e.includes('.message')) return true;
  if (e.includes('github.event.pages.') && e.includes('.page_name')) return true;
  return false;
}

function checkScriptInjection(path: string, text: string, jobs: { name: string; node: Node }[], lc: LineCounter): RawCodeIssue[] {
  const issues: RawCodeIssue[] = [];
  for (const { node: jobNode } of jobs) {
    for (const step of jobSteps(jobNode)) {
      const range = step.runNode?.range;
      if (!isScalar(step.runNode) || typeof step.runNode.value !== 'string' || !range) continue;
      const startLine = lineOf(lc, range[0]);
      const slice = text.slice(range[0], range[1]);
      const scriptLines = slice.split('\n');
      for (let i = 0; i < scriptLines.length; i++) {
        const raw = clamp(scriptLines[i] ?? '');
        TEMPLATE_EXPR_RE.lastIndex = 0;
        let match: RegExpExecArray | null = TEMPLATE_EXPR_RE.exec(raw);
        while (match !== null) {
          const expr = match[1] ?? '';
          if (isUntrustedExpr(expr)) {
            const line = startLine + i;
            issues.push(
              makeIssue({
                ruleId: 'config/gha-script-injection',
                title: 'Untrusted value interpolated into a run: script',
                severity: 'high',
                cwe: 'CWE-78',
                file: path,
                line,
                snippet: snippetOf(raw),
                explanation: `An attacker-controlled value (${expr.trim()}) is interpolated directly into a shell script.`,
                impact: 'The value can break out of its context and run arbitrary commands in the workflow runner.',
                remediation: 'Pass the value through an `env:` variable and reference it as $VAR inside the script instead of templating it directly.',
              }),
            );
            break; // one finding per line is enough
          }
          match = TEMPLATE_EXPR_RE.exec(raw);
        }
      }
    }
  }
  return issues;
}

// --- rule: gha-unpinned-action --------------------------------------------------------------------

const SHA_RE = /^[0-9a-f]{40}$/i;
const OFFICIAL_OWNERS = new Set(['actions', 'github']);

function checkUnpinnedAction(path: string, text: string, jobs: { name: string; node: Node }[], lc: LineCounter): RawCodeIssue[] {
  const lines = text.split('\n');
  const issues: RawCodeIssue[] = [];
  const seen = new Set<string>();
  for (const { node: jobNode } of jobs) {
    for (const step of jobSteps(jobNode)) {
      const uses = scalarString(step.usesNode);
      if (!uses) continue;
      if (uses.startsWith('./') || uses.startsWith('.\\') || uses.startsWith('docker://')) continue;
      const at = uses.lastIndexOf('@');
      const spec = at === -1 ? uses : uses.slice(0, at);
      const ref = at === -1 ? '' : uses.slice(at + 1);
      const owner = spec.split('/')[0] ?? '';
      if (OFFICIAL_OWNERS.has(owner)) continue;
      if (SHA_RE.test(ref)) continue;
      const line = lineOf(lc, step.usesNode!.range?.[0]);
      const key = `${line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      issues.push(
        makeIssue({
          ruleId: 'config/gha-unpinned-action',
          title: 'Third-party action not pinned to a commit SHA',
          severity: 'medium',
          cwe: 'CWE-829',
          file: path,
          line,
          snippet: snippetOf(lines[line - 1]),
          explanation: `'${uses}' is pinned to a mutable ${ref ? 'tag/branch' : 'default ref'}, not a commit SHA.`,
          impact: 'A compromised or rewritten tag/branch on the third-party action runs arbitrary code in this workflow.',
          remediation: 'Pin the action to a full 40-character commit SHA.',
        }),
      );
    }
  }
  return issues;
}

// --- rule: gha-excessive-permissions ---------------------------------------------------------------

function checkExcessivePermissions(path: string, text: string, triggers: Set<string>, topPermissions: Node | undefined, jobs: { name: string; node: Node }[], lc: LineCounter): RawCodeIssue[] {
  const lines = text.split('\n');
  const issues: RawCodeIssue[] = [];

  const flagWriteAll = (node: Node | undefined, scope: string): void => {
    const v = scalarString(node);
    if (v !== 'write-all') return;
    const line = lineOf(lc, node!.range?.[0]);
    issues.push(
      makeIssue({
        ruleId: 'config/gha-excessive-permissions',
        title: 'Workflow grants write-all permissions',
        severity: 'medium',
        cwe: 'CWE-250',
        file: path,
        line,
        snippet: snippetOf(lines[line - 1]),
        explanation: `${scope} sets permissions: write-all.`,
        impact: 'The GITHUB_TOKEN can write to every scope (contents, packages, issues, …) beyond what the job needs.',
        remediation: 'Grant the minimum permissions each job actually needs, e.g. `contents: read`.',
      }),
    );
  };

  flagWriteAll(topPermissions, 'This workflow');
  let anyJobHasPermissions = false;
  for (const { node: jobNode } of jobs) {
    const jobPerms = mapGetNode(jobNode, 'permissions');
    if (jobPerms) anyJobHasPermissions = true;
    flagWriteAll(jobPerms, 'This job');
  }

  if (topPermissions === undefined && !anyJobHasPermissions && triggers.has('pull_request_target')) {
    issues.push(
      makeIssue({
        ruleId: 'config/gha-excessive-permissions',
        title: 'pull_request_target workflow has no explicit permissions',
        severity: 'medium',
        cwe: 'CWE-250',
        file: path,
        line: 1,
        snippet: snippetOf(lines[0]),
        explanation: 'This pull_request_target workflow declares no `permissions:` key, so GITHUB_TOKEN defaults to the (often broad) repository setting.',
        impact: 'A privileged workflow with default-scoped permissions is a higher-value target if any step is tricked into running untrusted code.',
        remediation: 'Add an explicit `permissions:` block scoped to what the workflow needs, e.g. `contents: read`.',
      }),
    );
  }

  return issues;
}

// --- public entry point ---------------------------------------------------------------------------

export function githubActionsIssues(files: readonly { path: string; text: string }[]): RawCodeIssue[] {
  const issues: RawCodeIssue[] = [];
  for (const file of files) {
    if (!isGithubActionsWorkflow(file.path)) continue;
    const lc = new LineCounter();
    let doc;
    try {
      doc = parseDocument(file.text, { lineCounter: lc });
    } catch {
      continue;
    }
    if (!doc || !isMap(doc.contents)) continue;

    const onNode = mapGetNode(doc.contents, 'on');
    const triggers = triggerNames(onNode);
    const topPermissions = mapGetNode(doc.contents, 'permissions');
    const jobsNode = mapGetNode(doc.contents, 'jobs');
    const jobs = jobEntries(jobsNode);

    issues.push(...checkPullRequestTargetCheckout(file.path, file.text, triggers, jobs, lc));
    issues.push(...checkScriptInjection(file.path, file.text, jobs, lc));
    issues.push(...checkUnpinnedAction(file.path, file.text, jobs, lc));
    issues.push(...checkExcessivePermissions(file.path, file.text, triggers, topPermissions, jobs, lc));
  }
  return issues;
}
