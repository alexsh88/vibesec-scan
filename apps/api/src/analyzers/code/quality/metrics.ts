// Deterministic code-quality metrics: function/nesting extraction (JS/TS via the TypeScript
// compiler API, Python via an indentation heuristic), duplicate-block detection, and the
// RawCodeIssue templates built from those numbers. Pure, synchronous, no network/LLM.

import ts from 'typescript';
import type { RawCodeIssue } from '../types';

export type QualityLanguage = 'js' | 'ts' | 'py';

export type FunctionMetric = {
  name: string;
  startLine: number;
  endLine: number;
  /** endLine - startLine + 1 */
  length: number;
  /** Max depth of nested control-flow blocks (if/for/while/switch/try…) inside this function. */
  maxNesting: number;
};

export type FileMetrics = {
  path: string;
  lines: number;
  codeLines: number;
  functions: FunctionMetric[];
  /** Max nesting depth anywhere in the file (inside or outside a function). */
  maxNesting: number;
  todoCount: number;
  /** TODO/FIXME markers per 100 code lines. 0 when codeLines === 0. */
  todoDensity: number;
  /** Count of functions longer than LONG_FUNCTION_LINES. */
  longFunctions: number;
  /** Count of functions nested deeper than DEEP_NESTING_DEPTH. */
  deepNesting: number;
};

export type DuplicateBlock = {
  hash: string;
  occurrences: { path: string; startLine: number }[];
};

// --- thresholds --------------------------------------------------------------------------------

export const LONG_FILE_LINES = 600;
export const LONG_FUNCTION_LINES = 80;
export const DEEP_NESTING_DEPTH = 4;
export const TODO_DENSITY_THRESHOLD = 5; // per 100 code lines
export const DUPLICATE_WINDOW = 6;

// --- shared line helpers -------------------------------------------------------------------------

const TODO_RE = /\b(?:TODO|FIXME|XXX|HACK)\b/;

function splitLines(text: string): string[] {
  // Normalize CRLF so line counts/line numbers match what an editor shows.
  const normalized = text.includes('\r\n') ? text.replace(/\r\n/g, '\n') : text;
  return normalized.length === 0 ? [''] : normalized.split('\n');
}

function isCommentOrBlank(line: string, lang: QualityLanguage, inBlockComment: boolean): boolean {
  const t = line.trim();
  if (t === '') return true;
  if (inBlockComment) return true;
  if (lang === 'py') return t.startsWith('#');
  return t.startsWith('//') || t.startsWith('/*') || t.startsWith('*');
}

/**
 * Counts total lines, code lines (non-blank, non-comment-only) and TODO markers in one pass.
 * Block-comment tracking is conservative: a line that opens or closes a `/* ... *\/` block is
 * always treated as comment-only, even if it also has trailing code on the same line.
 */
function computeLineStats(
  lines: readonly string[],
  lang: QualityLanguage,
): { codeLines: number; todoCount: number } {
  let codeLines = 0;
  let todoCount = 0;
  let inBlockComment = false;
  for (const raw of lines) {
    const trimmed = raw.trim();
    if (!isCommentOrBlank(raw, lang, inBlockComment)) codeLines++;
    if (lang !== 'py') {
      if (!inBlockComment && trimmed.startsWith('/*') && !trimmed.includes('*/')) inBlockComment = true;
      else if (inBlockComment && trimmed.includes('*/')) inBlockComment = false;
    }
    if (TODO_RE.test(raw)) todoCount++;
  }
  return { codeLines, todoCount };
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
}

// --- JS/TS metrics via the TypeScript compiler API -----------------------------------------------

const CONTROL_FLOW_KINDS = new Set<ts.SyntaxKind>([
  ts.SyntaxKind.IfStatement,
  ts.SyntaxKind.ForStatement,
  ts.SyntaxKind.ForInStatement,
  ts.SyntaxKind.ForOfStatement,
  ts.SyntaxKind.WhileStatement,
  ts.SyntaxKind.DoStatement,
  ts.SyntaxKind.SwitchStatement,
  ts.SyntaxKind.CatchClause,
  ts.SyntaxKind.TryStatement,
]);

type NestFrame = { current: number; max: number };

function isFunctionLike(node: ts.Node): node is ts.FunctionLikeDeclaration {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isConstructorDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node)
  );
}

function nameFromProperty(name: ts.PropertyName | undefined): string | null {
  if (!name) return null;
  if (ts.isIdentifier(name) || ts.isPrivateIdentifier(name)) return name.text;
  if (ts.isStringLiteralLike(name)) return name.text;
  if (ts.isNumericLiteral(name)) return name.text;
  return '[computed]';
}

function functionName(node: ts.FunctionLikeDeclaration): string {
  if (ts.isConstructorDeclaration(node)) return 'constructor';
  if (ts.isGetAccessorDeclaration(node)) return `get ${nameFromProperty(node.name) ?? 'anonymous'}`;
  if (ts.isSetAccessorDeclaration(node)) return `set ${nameFromProperty(node.name) ?? 'anonymous'}`;
  if (ts.isMethodDeclaration(node)) return nameFromProperty(node.name) ?? 'anonymous';
  if ((ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node)) && node.name) return node.name.text;

  const parent = node.parent;
  if (parent) {
    if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) return parent.name.text;
    if (ts.isPropertyAssignment(parent)) return nameFromProperty(parent.name) ?? 'anonymous';
    if (ts.isPropertyDeclaration(parent)) return nameFromProperty(parent.name) ?? 'anonymous';
    if (ts.isBinaryExpression(parent) && parent.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      if (ts.isIdentifier(parent.left)) return parent.left.text;
      if (ts.isPropertyAccessExpression(parent.left)) return parent.left.name.text;
    }
  }
  return 'anonymous';
}

function scriptKindFor(path: string, lang: QualityLanguage): ts.ScriptKind {
  const lower = path.toLowerCase();
  if (lower.endsWith('.tsx')) return ts.ScriptKind.TSX;
  if (lower.endsWith('.jsx')) return ts.ScriptKind.JSX;
  if (lang === 'ts') return ts.ScriptKind.TS;
  return ts.ScriptKind.JS;
}

function computeJsTsMetrics(path: string, text: string, lang: QualityLanguage): Pick<
  FileMetrics,
  'functions' | 'maxNesting'
> {
  const source = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, scriptKindFor(path, lang));
  const functions: FunctionMetric[] = [];
  const topFrame: NestFrame = { current: 0, max: 0 };
  const stack: NestFrame[] = [topFrame];

  const lineOf = (pos: number): number => source.getLineAndCharacterOfPosition(pos).line + 1;

  function visit(node: ts.Node): void {
    if (CONTROL_FLOW_KINDS.has(node.kind)) {
      const frame = stack[stack.length - 1]!;
      frame.current++;
      if (frame.current > frame.max) frame.max = frame.current;
      ts.forEachChild(node, visit);
      frame.current--;
      return;
    }
    if (isFunctionLike(node) && node.body) {
      const frame: NestFrame = { current: 0, max: 0 };
      stack.push(frame);
      const startLine = lineOf(node.getStart(source));
      const endLine = lineOf(node.getEnd());
      ts.forEachChild(node, visit);
      stack.pop();
      functions.push({
        name: functionName(node),
        startLine,
        endLine,
        length: endLine - startLine + 1,
        maxNesting: frame.max,
      });
      return;
    }
    ts.forEachChild(node, visit);
  }

  ts.forEachChild(source, visit);
  const maxNesting = Math.max(topFrame.max, ...functions.map((f) => f.maxNesting), 0);
  return { functions, maxNesting };
}

// --- Python metrics via an indentation heuristic --------------------------------------------------

const PY_DEF_RE = /^(async\s+)?def\s+([A-Za-z_]\w*)/;
const PY_CLASS_RE = /^class\s+([A-Za-z_]\w*)/;
const PY_CONTROL_RE = /^(?:async\s+)?(?:if|elif|else|for|while|with|try|except|finally|match|case)\b/;

function indentOf(line: string): number {
  let n = 0;
  while (n < line.length && (line[n] === ' ' || line[n] === '\t')) n++;
  return n;
}

type PyStackEntry = {
  headerIndent: number;
  kind: 'func' | 'other' | 'root';
  frame?: NestFrame;
  targetFrame?: NestFrame;
  name?: string;
  startLine?: number;
};

function computePyMetrics(text: string, lines: readonly string[]): Pick<FileMetrics, 'functions' | 'maxNesting'> {
  const functions: FunctionMetric[] = [];
  const rootFrame: NestFrame = { current: 0, max: 0 };
  const stack: PyStackEntry[] = [{ headerIndent: -1, kind: 'root', frame: rootFrame }];
  let lastLogicalLine = 0;

  const nearestFrame = (): NestFrame | undefined => {
    for (let i = stack.length - 1; i >= 0; i--) {
      const f = stack[i]!.frame;
      if (f) return f;
    }
    return undefined;
  };

  const closeEntry = (entry: PyStackEntry, endLine: number): void => {
    if (entry.kind === 'func' && entry.frame && entry.name !== undefined && entry.startLine !== undefined) {
      functions.push({
        name: entry.name,
        startLine: entry.startLine,
        endLine,
        length: endLine - entry.startLine + 1,
        maxNesting: entry.frame.max,
      });
    } else if (entry.kind === 'other' && entry.targetFrame) {
      entry.targetFrame.current--;
    }
  };

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!;
    const trimmed = raw.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;
    const lineNo = i + 1;
    const indent = indentOf(raw);

    while (stack.length > 1 && indent <= stack[stack.length - 1]!.headerIndent) {
      const entry = stack.pop()!;
      closeEntry(entry, lastLogicalLine);
    }

    const defMatch = PY_DEF_RE.exec(trimmed);
    const classMatch = !defMatch ? PY_CLASS_RE.exec(trimmed) : null;
    if (defMatch) {
      stack.push({
        headerIndent: indent,
        kind: 'func',
        frame: { current: 0, max: 0 },
        name: defMatch[2]!,
        startLine: lineNo,
      });
    } else if (classMatch) {
      stack.push({ headerIndent: indent, kind: 'other' });
    } else if (PY_CONTROL_RE.test(trimmed)) {
      const target = nearestFrame();
      if (target) {
        target.current++;
        if (target.current > target.max) target.max = target.current;
      }
      stack.push({ headerIndent: indent, kind: 'other', targetFrame: target });
    }

    lastLogicalLine = lineNo;
  }

  while (stack.length > 1) {
    const entry = stack.pop()!;
    closeEntry(entry, lastLogicalLine);
  }

  const maxNesting = Math.max(rootFrame.max, ...functions.map((f) => f.maxNesting), 0);
  return { functions, maxNesting };
}

// --- public API ------------------------------------------------------------------------------

export function computeFileMetrics(path: string, text: string, language: QualityLanguage): FileMetrics {
  const lines = splitLines(text);
  const { codeLines, todoCount } = computeLineStats(lines, language);
  const { functions, maxNesting } =
    language === 'py' ? computePyMetrics(text, lines) : computeJsTsMetrics(path, text, language);

  const todoDensity = codeLines === 0 ? 0 : round1((todoCount / codeLines) * 100);
  const longFunctions = functions.filter((f) => f.length > LONG_FUNCTION_LINES).length;
  const deepNesting = functions.filter((f) => f.maxNesting > DEEP_NESTING_DEPTH).length;

  return {
    path,
    lines: lines.length,
    codeLines,
    functions,
    maxNesting,
    todoCount,
    todoDensity,
    longFunctions,
    deepNesting,
  };
}

// --- duplicate block detection -----------------------------------------------------------------

/** Lines that are overwhelmingly punctuation/imports — windows dominated by these are not
 *  interesting duplicates (every file has `});` or `import x from 'y'` repeated). */
const TRIVIAL_LINE_RE =
  /^[{}()[\];,]*$|^(?:import|export)\b.*|^from\s+['"].*['"];?$|^(?:use strict|"use strict";?)$/;

function normalizeLine(line: string): string {
  return line.trim().replace(/\s+/g, ' ');
}

function isSkippableLine(line: string, lang: QualityLanguage): boolean {
  const t = line.trim();
  if (t === '') return true;
  if (lang === 'py') return t.startsWith('#');
  return t.startsWith('//') || t === '*' || t.startsWith('/*') || t.startsWith('*/');
}

function languageOfPath(path: string): QualityLanguage {
  const lower = path.toLowerCase();
  if (lower.endsWith('.py')) return 'py';
  if (lower.endsWith('.ts') || lower.endsWith('.tsx')) return 'ts';
  return 'js';
}

function isTrivialWindow(texts: readonly string[]): boolean {
  let trivial = 0;
  for (const t of texts) if (TRIVIAL_LINE_RE.test(t)) trivial++;
  return trivial / texts.length > 0.5;
}

/** Cheap 32-bit FNV-1a hash of a string, rendered as 8 hex chars. Used only to label a duplicate
 *  group (equality for grouping is always done on the normalized text itself, never the hash). */
function hashString(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, '0');
}

type SigLine = { text: string; origLine: number };

const MAX_GROUP_SIZE = 25;
const MAX_EXTENSION = 2000;
const MAX_DUPLICATE_GROUPS = 50;

export function findDuplicateBlocks(
  files: readonly { path: string; text: string }[],
  window: number = DUPLICATE_WINDOW,
): DuplicateBlock[] {
  const sigByFile: SigLine[][] = files.map((f) => {
    const lang = languageOfPath(f.path);
    const lines = splitLines(f.text);
    const out: SigLine[] = [];
    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i]!;
      if (isSkippableLine(raw, lang)) continue;
      out.push({ text: normalizeLine(raw), origLine: i + 1 });
    }
    return out;
  });

  type Loc = { fileIdx: number; idx: number };
  const seeds = new Map<string, Loc[]>();

  for (let fileIdx = 0; fileIdx < sigByFile.length; fileIdx++) {
    const sig = sigByFile[fileIdx]!;
    for (let idx = 0; idx + window <= sig.length; idx++) {
      const texts: string[] = [];
      for (let k = 0; k < window; k++) texts.push(sig[idx + k]!.text);
      if (isTrivialWindow(texts)) continue;
      const key = texts.join('\n');
      const list = seeds.get(key);
      if (list) list.push({ fileIdx, idx });
      else seeds.set(key, [{ fileIdx, idx }]);
    }
  }

  const results: DuplicateBlock[] = [];
  const emitted = new Set<string>();

  for (const [, locs] of seeds) {
    if (locs.length < 2) continue;
    if (results.length >= MAX_DUPLICATE_GROUPS) break;
    const capped = locs.slice(0, MAX_GROUP_SIZE);
    const base = capped[0]!;
    const baseSig = sigByFile[base.fileIdx]!;

    let forwardExt = 0;
    for (let k = window; k < MAX_EXTENSION; k++) {
      const baseLine = baseSig[base.idx + k];
      if (!baseLine) break;
      let allMatch = true;
      for (const loc of capped) {
        const sig = sigByFile[loc.fileIdx]!;
        const line = sig[loc.idx + k];
        if (!line || line.text !== baseLine.text) {
          allMatch = false;
          break;
        }
      }
      if (!allMatch) break;
      forwardExt = k - window + 1;
    }

    let backwardExt = 0;
    for (let k = 1; k < MAX_EXTENSION; k++) {
      const baseLine = baseSig[base.idx - k];
      if (!baseLine) break;
      let allMatch = true;
      for (const loc of capped) {
        const sig = sigByFile[loc.fileIdx]!;
        const line = sig[loc.idx - k];
        if (!line || line.text !== baseLine.text) {
          allMatch = false;
          break;
        }
      }
      if (!allMatch) break;
      backwardExt = k;
    }

    const occurrences = capped.map((loc) => {
      const sig = sigByFile[loc.fileIdx]!;
      const startSigIdx = loc.idx - backwardExt;
      return { path: files[loc.fileIdx]!.path, startLine: sig[startSigIdx]!.origLine };
    });
    occurrences.sort((a, b) => (a.path === b.path ? a.startLine - b.startLine : a.path < b.path ? -1 : 1));

    const dedupeKey = occurrences.map((o) => `${o.path}:${o.startLine}`).join('|');
    if (emitted.has(dedupeKey)) continue;
    emitted.add(dedupeKey);

    const endSigIdx = base.idx + window - 1 + forwardExt;
    const contentText = Array.from(
      { length: endSigIdx - (base.idx - backwardExt) + 1 },
      (_, i) => baseSig[base.idx - backwardExt + i]!.text,
    ).join('\n');

    results.push({ hash: hashString(contentText), occurrences });
  }

  return results.slice(0, MAX_DUPLICATE_GROUPS);
}

// --- issue construction + ranking -----------------------------------------------------------------

function firstLineText(text: string, line: number): string {
  const lines = splitLines(text);
  const raw = lines[line - 1] ?? '';
  return raw.length > 300 ? raw.slice(0, 300) : raw;
}

function makeIssue(partial: Omit<RawCodeIssue, 'confidence' | 'severity'> & { severity: RawCodeIssue['severity'] }): RawCodeIssue {
  return { confidence: 'high', ...partial };
}

export function qualityIssuesFromMetrics(
  files: readonly { path: string; text: string }[],
  metrics: readonly FileMetrics[],
  duplicates: readonly DuplicateBlock[],
): RawCodeIssue[] {
  const textByPath = new Map(files.map((f) => [f.path, f.text]));
  const issues: RawCodeIssue[] = [];

  for (const m of metrics) {
    const text = textByPath.get(m.path) ?? '';

    if (m.lines > LONG_FILE_LINES) {
      issues.push(
        makeIssue({
          ruleId: 'quality/long-file',
          title: 'Long file',
          severity: 'low',
          file: m.path,
          startLine: 1,
          endLine: m.lines,
          snippet: firstLineText(text, 1),
          explanation: `File has ${m.lines} lines (threshold ${LONG_FILE_LINES}).`,
          impact: 'Large files are harder to review and more likely to hide bugs.',
          remediation: 'Split this file into smaller, cohesive modules.',
        }),
      );
    }

    for (const fn of m.functions) {
      if (fn.length > LONG_FUNCTION_LINES) {
        issues.push(
          makeIssue({
            ruleId: 'quality/long-function',
            title: 'Long function',
            severity: 'low',
            file: m.path,
            startLine: fn.startLine,
            endLine: fn.endLine,
            snippet: firstLineText(text, fn.startLine),
            explanation: `Function '${fn.name}' is ${fn.length} lines long (threshold ${LONG_FUNCTION_LINES}).`,
            impact: 'Long functions are harder to test, review and understand.',
            remediation: 'Extract smaller functions with a single responsibility.',
          }),
        );
      }
      if (fn.maxNesting > DEEP_NESTING_DEPTH) {
        issues.push(
          makeIssue({
            ruleId: 'quality/deep-nesting',
            title: 'Deeply nested function',
            severity: 'low',
            file: m.path,
            startLine: fn.startLine,
            endLine: fn.endLine,
            snippet: firstLineText(text, fn.startLine),
            explanation: `Function '${fn.name}' nests ${fn.maxNesting} levels deep (threshold ${DEEP_NESTING_DEPTH}).`,
            impact: 'Deep nesting increases cyclomatic complexity and the chance of logic errors.',
            remediation: 'Flatten control flow with early returns, guard clauses, or extracted helpers.',
          }),
        );
      }
    }

    if (m.todoDensity > TODO_DENSITY_THRESHOLD) {
      issues.push(
        makeIssue({
          ruleId: 'quality/todo-density',
          title: 'High TODO/FIXME density',
          severity: 'info',
          file: m.path,
          startLine: 1,
          endLine: m.lines,
          snippet: firstLineText(text, 1),
          explanation: `${m.todoCount} TODO/FIXME/XXX/HACK markers, ${m.todoDensity} per 100 code lines (threshold ${TODO_DENSITY_THRESHOLD}).`,
          impact: 'A high density of TODO markers suggests unfinished or poorly tracked work.',
          remediation: 'Convert TODOs into tracked issues or resolve them.',
        }),
      );
    }
  }

  for (const dup of duplicates) {
    for (const occ of dup.occurrences) {
      const text = textByPath.get(occ.path) ?? '';
      const others = dup.occurrences.filter((o) => o !== occ).map((o) => `${o.path}:${o.startLine}`);
      issues.push(
        makeIssue({
          ruleId: 'quality/duplicate-code',
          title: 'Duplicate code block',
          severity: 'low',
          file: occ.path,
          startLine: occ.startLine,
          endLine: occ.startLine + DUPLICATE_WINDOW - 1,
          snippet: firstLineText(text, occ.startLine),
          explanation: `Duplicate of ${dup.occurrences.length} copies total (also at ${others.join(', ')}).`,
          impact: 'Duplicated logic drifts out of sync and multiplies the cost of fixes.',
          remediation: 'Extract the shared logic into a single function or module.',
        }),
      );
    }
  }

  return issues;
}

export function rankFilesForQualityReview(metrics: readonly FileMetrics[]): string[] {
  const scored = metrics.map((m) => {
    const score =
      m.longFunctions * 10 +
      m.deepNesting * 8 +
      Math.max(0, m.lines - LONG_FILE_LINES) / 50 +
      Math.max(0, m.todoDensity - TODO_DENSITY_THRESHOLD);
    return { path: m.path, score };
  });
  scored.sort((a, b) => b.score - a.score || a.path.localeCompare(b.path));
  return scored.map((s) => s.path);
}
