import type { RiskGrade } from '@vibesec/shared';
import { cn } from '@/lib/utils';
import { GRADE_CLASSES } from '@/lib/taxonomy';

const SIZES = {
  sm: 'size-6 text-xs rounded-[5px]',
  md: 'size-9 text-lg rounded-md',
  lg: 'size-20 text-5xl rounded-xl',
} as const;

/** Letter risk grade A (best) … F (worst). */
export function GradeBadge({ grade, size = 'md', className }: { grade: RiskGrade; size?: keyof typeof SIZES; className?: string }) {
  const c = GRADE_CLASSES[grade];
  return (
    <span
      role="img"
      aria-label={`Risk grade ${grade}`}
      className={cn('inline-grid shrink-0 place-items-center border font-mono font-semibold', SIZES[size], c.soft, c.border, c.text, className)}
    >
      {grade}
    </span>
  );
}
