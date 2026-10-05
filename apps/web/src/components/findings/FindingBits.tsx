import type { Finding, Severity } from '@vibesec/shared';
import { cn } from '@/lib/utils';
import { SEVERITY_CLASSES } from '@/lib/taxonomy';
import { CONFIDENCE_LABEL } from './meta';

/** Score bands from the API's risk model (≥85 critical, ≥65 high, ≥40 medium, ≥15 low). */
const BANDS = [15, 40, 65, 85] as const;

export function bandOf(score: number): Severity {
  if (score >= 85) return 'critical';
  if (score >= 65) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 15) return 'low';
  return 'info';
}

/** 0–100 risk score as a thin gauge with band ticks; colour follows the score's band. */
export function RiskBar({ score, className, showValue = true }: { score: number; className?: string; showValue?: boolean }) {
  const s = Math.max(0, Math.min(100, Math.round(score)));
  const c = SEVERITY_CLASSES[bandOf(s)];
  return (
    <span className={cn('inline-flex items-center gap-2', className)} title={`Risk score ${s}/100`}>
      <span aria-hidden className="relative h-1.5 w-14 overflow-hidden rounded-full bg-muted">
        <span className={cn('absolute inset-y-0 left-0 rounded-full', c.bg)} style={{ width: `${Math.max(s, 3)}%` }} />
        {BANDS.map((b) => (
          <span key={b} className="absolute inset-y-0 w-px bg-background/70" style={{ left: `${b}%` }} />
        ))}
      </span>
      {showValue && <span className={cn('w-6 text-right font-mono text-xs tabular', c.text)}>{s}</span>}
      <span className="sr-only">Risk score {s} of 100</span>
    </span>
  );
}

/** Three-pip confidence indicator (high = 3). */
export function ConfidencePips({ confidence, withLabel, className }: { confidence: Finding['confidence']; withLabel?: boolean; className?: string }) {
  const n = confidence === 'high' ? 3 : confidence === 'medium' ? 2 : 1;
  return (
    <span className={cn('inline-flex items-center gap-1.5', className)} title={`${CONFIDENCE_LABEL[confidence]} confidence`}>
      <span aria-hidden className="inline-flex gap-[3px]">
        {[0, 1, 2].map((i) => (
          <span key={i} className={cn('size-[5px] rounded-full', i < n ? 'bg-foreground/75' : 'bg-foreground/15')} />
        ))}
      </span>
      {withLabel ? (
        <span className="text-xs text-muted-foreground">{CONFIDENCE_LABEL[confidence]}</span>
      ) : (
        <span className="sr-only">{CONFIDENCE_LABEL[confidence]} confidence</span>
      )}
    </span>
  );
}

/** Analyzer chips ("semgrep", "ai-review"), collapsed to `max` + "+n". */
export function AnalyzerChips({ analyzers, max = 2, className }: { analyzers: string[] | undefined; max?: number; className?: string }) {
  if (!analyzers?.length) return null;
  const shown = analyzers.slice(0, max);
  const rest = analyzers.length - shown.length;
  return (
    <span className={cn('inline-flex flex-wrap items-center gap-1', className)} title={analyzers.join(', ')}>
      {shown.map((a) => (
        <AnalyzerChip key={a} name={a} />
      ))}
      {rest > 0 && <span className="font-mono text-[10px] text-muted-foreground">+{rest}</span>}
    </span>
  );
}

export function AnalyzerChip({ name, className }: { name: string; className?: string }) {
  return (
    <span className={cn('inline-flex h-[18px] items-center rounded-[4px] border bg-surface-raised px-1.5 font-mono text-[10px] text-muted-foreground', className)}>
      {name}
    </span>
  );
}

/** Mono `path:line` with the directory dimmed so the file name stands out in dense tables. */
export function FileRef({ file, line, className }: { file: string; line?: number; className?: string }) {
  const slash = file.lastIndexOf('/');
  const dir = slash >= 0 ? file.slice(0, slash + 1) : '';
  const base = slash >= 0 ? file.slice(slash + 1) : file;
  return (
    <span className={cn('inline-flex min-w-0 font-mono text-xs', className)} title={line ? `${file}:${line}` : file}>
      <span className="truncate text-muted-foreground/80" style={{ direction: 'rtl', textAlign: 'left' }}>
        <bdi>{dir}</bdi>
      </span>
      <span className="shrink-0 text-foreground/90">{base}</span>
      {line !== undefined && <span className="shrink-0 text-muted-foreground">:{line}</span>}
    </span>
  );
}
