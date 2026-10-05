import type { Finding } from '@vibesec/shared';
import { Bot } from 'lucide-react';
import { SeverityBadge } from '@/components/security/SeverityBadge';
import { cn } from '@/lib/utils';
import { bandOf, RiskBar } from './FindingBits';
import { factorLabel, formatEffect, isReviewFactor } from './meta';

/**
 * Risk score with its explanation: one chip per factor ("Live credential +23", "Dev dependency −18"),
 * the reason on hover, and AI-review / skeptic verdicts spelled out (they can drop a finding to info,
 * so the "why" must be visible without hovering).
 */
export function RiskFactors({ finding }: { finding: Finding }) {
  const factors = finding.riskFactors;
  const review = factors.filter((f) => isReviewFactor(f.factor) && f.reason);
  const score = Math.round(finding.riskScore);
  return (
    <div className="space-y-2.5">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <span className="font-mono text-2xl leading-none font-semibold tabular">
          {score}
          <span className="text-sm font-normal text-muted-foreground">/100</span>
        </span>
        <RiskBar score={score} showValue={false} className="[&>span:first-child]:w-28" />
        {finding.baseSeverity !== finding.severity && (
          <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
            base <SeverityBadge severity={finding.baseSeverity} className="opacity-70" /> → <SeverityBadge severity={bandOf(score)} />
          </span>
        )}
      </div>
      {factors.length > 0 ? (
        <ul className="flex flex-wrap gap-1.5" aria-label="Risk factors">
          {factors.map((f, i) => (
            <li key={`${f.factor}-${i}`}>
              <FactorChip factor={f.factor} effect={f.effect} reason={f.reason} />
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-xs text-muted-foreground">No contextual adjustments: the score is the base severity’s impact.</p>
      )}
      {review.length > 0 && (
        <ul className="space-y-1.5">
          {review.map((f, i) => (
            <li key={`${f.factor}-r${i}`} className="flex gap-2 rounded-md border border-dashed bg-muted/40 px-2.5 py-2 text-xs">
              <Bot aria-hidden className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" />
              <span>
                <span className="font-medium">{factorLabel(f.factor)}:</span> <span className="text-muted-foreground">{f.reason}</span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function FactorChip({ factor, effect, reason }: { factor: string; effect: number; reason: string }) {
  const up = effect > 0;
  const down = effect < 0;
  return (
    <span
      title={reason}
      className={cn(
        'inline-flex h-6 items-center gap-1.5 rounded-md border pr-1 pl-2 text-xs',
        up && 'border-sev-high/35 bg-sev-high/8',
        down && 'border-status-fixed/35 bg-status-fixed/8',
        !up && !down && 'bg-muted/50',
        factor.startsWith('policy:') && 'border-dashed',
      )}
    >
      {factorLabel(factor)}
      <span
        className={cn(
          'rounded-[4px] px-1 font-mono text-[11px] font-medium tabular',
          up && 'bg-sev-high/15 text-sev-high',
          down && 'bg-status-fixed/15 text-status-fixed',
          !up && !down && 'text-muted-foreground',
        )}
      >
        {formatEffect(effect)}
      </span>
      <span className="sr-only">: {reason}</span>
    </span>
  );
}
