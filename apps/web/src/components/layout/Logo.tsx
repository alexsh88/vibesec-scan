import { cn } from '@/lib/utils';

/** Shield-check mark in the signal colour. */
export function LogoMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" aria-hidden className={cn('size-6', className)}>
      <rect width="32" height="32" rx="7" className="fill-foreground" />
      <path
        d="M8 9.5 16 6l8 3.5v6.2c0 5-3.4 8.9-8 10.3-4.6-1.4-8-5.3-8-10.3z"
        fill="none"
        className="stroke-signal dark:stroke-background"
        strokeWidth="2.2"
        strokeLinejoin="round"
      />
      <path d="m12 15.5 3 3 5.5-6" fill="none" className="stroke-signal" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** "vibesec" wordmark: lowercase, tight, with the "sec" in the signal colour. */
export function Logo({ className }: { className?: string }) {
  return (
    <span className={cn('inline-flex items-center gap-2', className)}>
      <LogoMark />
      <span className="text-[15px] font-semibold tracking-[-0.03em]">
        vibe<span className="text-signal">sec</span>
      </span>
      <span className="hidden rounded-[4px] border px-1 py-px font-mono text-[10px] tracking-wider text-muted-foreground uppercase sm:inline">
        scan review
      </span>
    </span>
  );
}
