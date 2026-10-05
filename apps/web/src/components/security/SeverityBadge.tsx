import type { Severity } from '@vibesec/shared';
import { cn } from '@/lib/utils';
import { SEVERITY_CLASSES, SEVERITY_LABEL } from '@/lib/taxonomy';

/** Bar glyph per severity so meaning never depends on colour alone. */
function SeverityGlyph({ severity }: { severity: Severity }) {
  const filled = severity === 'critical' ? 4 : severity === 'high' ? 3 : severity === 'medium' ? 2 : severity === 'low' ? 1 : 0;
  return (
    <span aria-hidden className="inline-flex items-end gap-[2px]">
      {[0, 1, 2, 3].map((i) => (
        <span
          key={i}
          className={cn('w-[3px] rounded-[1px]', i < filled ? 'bg-current' : 'bg-current/25')}
          style={{ height: 4 + i * 2 }}
        />
      ))}
    </span>
  );
}

type Props = {
  severity: Severity;
  /** `solid` for drawer headers / top risks, `soft` (default) for tables, `dot` for dense lists. */
  variant?: 'soft' | 'solid' | 'dot';
  /** Optional risk score (0–100) appended in mono. */
  score?: number;
  className?: string;
};

/** The one way to render a severity. Uses the --sev-* tokens; never hand-roll severity colours. */
export function SeverityBadge({ severity, variant = 'soft', score, className }: Props) {
  const c = SEVERITY_CLASSES[severity];
  const label = SEVERITY_LABEL[severity];
  if (variant === 'dot') {
    return (
      <span className={cn('inline-flex items-center gap-1.5 text-xs font-medium', className)}>
        <span aria-hidden className={cn('size-2 rounded-full', c.dot)} />
        {label}
      </span>
    );
  }
  return (
    <span
      className={cn(
        'inline-flex h-5.5 items-center gap-1.5 rounded-[5px] border px-1.5 font-mono text-[11px] font-medium tracking-wide uppercase',
        variant === 'solid' ? cn(c.bg, 'border-transparent text-background') : cn(c.soft, c.border, c.text),
        className,
      )}
      title={score !== undefined ? `${label} severity · risk score ${Math.round(score)}/100` : `${label} severity`}
    >
      <SeverityGlyph severity={severity} />
      {label}
      {score !== undefined && <span className="tabular opacity-75">· {Math.round(score)}</span>}
    </span>
  );
}

/** Compact count chip "● 3" coloured by severity (overview stats, tab counts). */
export function SeverityCount({ severity, count, className }: { severity: Severity; count: number; className?: string }) {
  const c = SEVERITY_CLASSES[severity];
  return (
    <span
      className={cn('inline-flex items-center gap-1 font-mono text-xs tabular', count === 0 ? 'text-muted-foreground/60' : c.text, className)}
      title={`${count} ${SEVERITY_LABEL[severity].toLowerCase()}`}
    >
      <span aria-hidden className={cn('size-1.5 rounded-full', count === 0 ? 'bg-muted-foreground/30' : c.dot)} />
      {count}
      <span className="sr-only"> {SEVERITY_LABEL[severity]}</span>
    </span>
  );
}
