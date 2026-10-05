import { RISK_GRADES, type ScanSummary } from '@vibesec/shared';
import { Download, Info } from 'lucide-react';
import { GradeBadge } from '@/components/security/GradeBadge';
import { Button } from '@/components/ui/button';
import { exportUrl } from '@/lib/api';
import { GRADE_CLASSES } from '@/lib/taxonomy';
import { cn } from '@/lib/utils';

const GRADE_MEANING: Record<ScanSummary['riskGrade'], string> = {
  A: 'Low risk',
  B: 'Guarded',
  C: 'Elevated',
  D: 'High risk',
  F: 'Critical risk',
};

/** First thing on the results screen: the grade, the one-line verdict and the overview paragraph. */
export function GradeHero({ summary, scanId }: { summary: ScanSummary; scanId: string }) {
  const grade = summary.riskGrade;
  return (
    <section
      aria-labelledby="overview-headline"
      className="relative overflow-hidden rounded-xl border bg-card"
    >
      <div aria-hidden className="bg-grid pointer-events-none absolute inset-0 [mask-image:linear-gradient(to_right,black,transparent_70%)]" />
      <div className="relative flex flex-col gap-6 p-5 sm:flex-row sm:items-stretch sm:p-6">
        {/* Grade dial */}
        <div className="flex shrink-0 items-center gap-4 sm:flex-col sm:items-start sm:justify-between sm:border-r sm:pr-6">
          <div className="space-y-2">
            <p className="eyebrow">Risk grade</p>
            <GradeBadge grade={grade} size="lg" className="shadow-[0_0_0_6px_var(--background)]" />
          </div>
          <div className="space-y-1.5">
            <p className={cn('font-mono text-xs font-medium tracking-wide uppercase', GRADE_CLASSES[grade].text)}>
              {GRADE_MEANING[grade]}
            </p>
            <ol aria-label="Grade scale, A best to F worst" className="flex gap-1">
              {RISK_GRADES.map((g) => (
                <li
                  key={g}
                  aria-current={g === grade ? 'true' : undefined}
                  className={cn(
                    'grid size-5 place-items-center rounded-[4px] border font-mono text-[10px]',
                    g === grade
                      ? cn(GRADE_CLASSES[g].soft, GRADE_CLASSES[g].border, GRADE_CLASSES[g].text, 'font-semibold')
                      : 'border-border text-muted-foreground/60',
                  )}
                >
                  {g}
                </li>
              ))}
            </ol>
          </div>
        </div>

        {/* Verdict */}
        <div className="flex min-w-0 flex-1 flex-col gap-3">
          <h1 id="overview-headline" className="text-xl leading-snug font-semibold tracking-tight text-balance sm:text-2xl">
            {summary.headline}
          </h1>
          <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground text-pretty">{summary.overview}</p>
          <div className="mt-auto flex flex-wrap items-center gap-2 pt-2">
            <Button asChild size="sm" variant="outline">
              <a href={exportUrl(scanId, 'sarif')} download>
                <Download /> SARIF
              </a>
            </Button>
            <Button asChild size="sm" variant="outline">
              <a href={exportUrl(scanId, 'cyclonedx')} download>
                <Download /> CycloneDX SBOM
              </a>
            </Button>
            {summary.generatedBy === 'fallback' ? (
              <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground" title="The AI summary step was unavailable; this summary was built deterministically from the findings.">
                <Info aria-hidden className="size-3.5" />
                Rule-based summary (AI synthesis unavailable)
              </span>
            ) : (
              summary.model && (
                <span className="font-mono text-[11px] text-muted-foreground/80">summarized by {summary.model}</span>
              )
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
