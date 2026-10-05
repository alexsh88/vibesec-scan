import type { Root } from 'hast';
import { toJsxRuntime } from 'hast-util-to-jsx-runtime';
import { Check, Copy } from 'lucide-react';
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Fragment, jsx, jsxs } from 'react/jsx-runtime';
import { highlight, langFromPath } from '@/lib/highlighter';
import { cn } from '@/lib/utils';

type Props = {
  code: string;
  /** Shiki language id; derived from `path` when omitted. */
  lang?: string;
  /** File path, shown in the header and used for language detection. */
  path?: string;
  /** Line number of the first line of `code` (default 1). */
  startLine?: number;
  /** Absolute line range to highlight (e.g. a finding's startLine..endLine). */
  highlight?: { from: number; to: number };
  /** Right side of the header (e.g. a permalink button). */
  actions?: ReactNode;
  className?: string;
  showLineNumbers?: boolean;
};

/**
 * Read-only code viewer with lazy Shiki highlighting. Renders plain monospace immediately and swaps
 * in the highlighted tree once the grammar is loaded. Shiki's HAST is rendered as React elements
 * (no innerHTML), so scanned repository code can never inject markup.
 */
export function CodeBlock({ code, lang, path, startLine = 1, highlight: hl, actions, className, showLineNumbers = true }: Props) {
  const [tree, setTree] = useState<Root | null>(null);
  const [copied, setCopied] = useState(false);
  const language = lang ?? (path ? langFromPath(path) : 'text');
  const from = hl?.from;
  const to = hl?.to;

  useEffect(() => {
    let alive = true;
    setTree(null);
    const lines: number[] = [];
    if (from !== undefined && to !== undefined) for (let l = from; l <= to; l++) lines.push(l - startLine + 1);
    highlight(code, { lang: language, highlightLines: lines })
      .then((t) => {
        if (alive) setTree(t);
      })
      .catch(() => {
        /* keep the plain fallback */
      });
    return () => {
      alive = false;
    };
  }, [code, language, startLine, from, to]);

  const rendered = useMemo(() => (tree ? toJsxRuntime(tree, { Fragment, jsx, jsxs }) : null), [tree]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1_500);
    } catch {
      /* clipboard blocked */
    }
  };

  return (
    <div className={cn('vs-code overflow-hidden rounded-lg border bg-card', className)}>
      <div className="flex items-center gap-2 border-b bg-surface-raised px-3 py-1.5">
        <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground" title={path}>
          {path ?? language}
        </span>
        {actions}
        <button
          type="button"
          onClick={copy}
          className="inline-flex size-6 items-center justify-center rounded text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          aria-label={copied ? 'Copied' : 'Copy code'}
        >
          {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
        </button>
      </div>
      <div
        className={cn('overflow-x-auto py-2 text-[12.5px] leading-[1.6]', showLineNumbers && 'vs-code-numbered')}
        style={{ counterReset: `line ${startLine - 1}` }}
      >
        {rendered ?? (
          <pre className="shiki">
            <code>
              {code.split('\n').map((l, i) => {
                const n = startLine + i;
                const on = from !== undefined && to !== undefined && n >= from && n <= to;
                return (
                  <Fragment key={i}>
                    <span className={cn('line', on && 'line-hl')}>{l}</span>
                    {'\n'}
                  </Fragment>
                );
              })}
            </code>
          </pre>
        )}
      </div>
    </div>
  );
}
