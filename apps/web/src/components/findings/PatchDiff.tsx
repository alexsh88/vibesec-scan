import { Check, Copy, FileDiff } from 'lucide-react';
import { useMemo, useState } from 'react';
import { cn } from '@/lib/utils';

type CodeRow = { kind: 'add' | 'del' | 'ctx'; text: string; old: number | null; new: number | null };
type Row = { kind: 'meta' | 'hunk' | 'note'; text: string } | CodeRow;
const isCode = (r: Row): r is CodeRow => r.kind === 'add' || r.kind === 'del' || r.kind === 'ctx';

/** Parses a unified diff into display rows with old/new line numbers (tolerant of hunk-less text). */
export function parseUnifiedDiff(patch: string): { rows: Row[]; files: string[]; added: number; removed: number } {
  const rows: Row[] = [];
  const files: string[] = [];
  let oldN = 0;
  let newN = 0;
  let inHunk = false;
  let added = 0;
  let removed = 0;
  const lines = patch.replace(/\n$/, '').split('\n');
  for (const line of lines) {
    const hunk = line.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunk) {
      oldN = Number(hunk[1]);
      newN = Number(hunk[2]);
      inHunk = true;
      rows.push({ kind: 'hunk', text: line });
    } else if (!inHunk && /^(diff |index |--- |\+\+\+ |new file|deleted file|similarity|rename )/.test(line)) {
      if (line.startsWith('+++ ')) files.push(line.slice(4).replace(/^b\//, ''));
      rows.push({ kind: 'meta', text: line });
    } else if (line.startsWith('diff ')) {
      inHunk = false;
      rows.push({ kind: 'meta', text: line });
    } else if (line.startsWith('\\')) {
      rows.push({ kind: 'note', text: line });
    } else if (line.startsWith('+')) {
      added++;
      rows.push({ kind: 'add', text: line.slice(1), old: null, new: inHunk ? newN++ : null });
    } else if (line.startsWith('-')) {
      removed++;
      rows.push({ kind: 'del', text: line.slice(1), old: inHunk ? oldN++ : null, new: null });
    } else {
      const text = line.startsWith(' ') ? line.slice(1) : line;
      rows.push({ kind: 'ctx', text, old: inHunk ? oldN++ : null, new: inHunk ? newN++ : null });
    }
  }
  return { rows, files, added, removed };
}

const SIGN = { add: '+', del: '−', ctx: ' ' } as const;

/** Unified diff viewer: +/− lines coloured, old/new gutters, copy-as-patch. Text only (no HTML). */
export function PatchDiff({ patch, className }: { patch: string; className?: string }) {
  const { rows, files, added, removed } = useMemo(() => parseUnifiedDiff(patch), [patch]);
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(patch);
      setCopied(true);
      setTimeout(() => setCopied(false), 1_500);
    } catch {
      /* clipboard blocked */
    }
  };
  return (
    <div className={cn('overflow-hidden rounded-lg border bg-card', className)}>
      <div className="flex items-center gap-2 border-b bg-surface-raised px-3 py-1.5">
        <FileDiff aria-hidden className="size-3.5 text-muted-foreground" />
        <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground">{files.join(', ') || 'suggested patch'}</span>
        <span className="font-mono text-[11px] tabular">
          <span className="text-status-fixed">+{added}</span> <span className="text-sev-critical">−{removed}</span>
        </span>
        <button
          type="button"
          onClick={copy}
          className="inline-flex h-6 items-center gap-1 rounded px-1.5 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          aria-label={copied ? 'Patch copied' : 'Copy patch'}
        >
          {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse font-mono text-[12px] leading-[1.6]">
          <tbody>
            {rows.map((r, i) => {
              if (!isCode(r)) {
                return (
                  <tr key={i} className={r.kind === 'hunk' ? 'bg-signal-soft' : ''}>
                    <td colSpan={4} className={cn('px-3 whitespace-pre', r.kind === 'hunk' ? 'text-muted-foreground' : 'text-muted-foreground/70', r.kind === 'meta' && 'font-medium')}>
                      {r.text}
                    </td>
                  </tr>
                );
              }
              return (
                <tr
                  key={i}
                  className={cn(r.kind === 'add' && 'bg-status-fixed/10', r.kind === 'del' && 'bg-sev-critical/10')}
                >
                  <td className="w-[1%] px-2 text-right text-muted-foreground/50 select-none tabular">{r.old ?? ''}</td>
                  <td className="w-[1%] px-2 text-right text-muted-foreground/50 select-none tabular">{r.new ?? ''}</td>
                  <td
                    aria-hidden
                    className={cn(
                      'w-[1%] pr-1 pl-1 select-none',
                      r.kind === 'add' && 'text-status-fixed',
                      r.kind === 'del' && 'text-sev-critical',
                    )}
                  >
                    {SIGN[r.kind]}
                  </td>
                  <td className="pr-4 whitespace-pre">
                    <span className="sr-only">{r.kind === 'add' ? 'added: ' : r.kind === 'del' ? 'removed: ' : ''}</span>
                    {r.text || ' '}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
