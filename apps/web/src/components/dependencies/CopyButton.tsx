import { Check, Copy } from 'lucide-react';
import { useState } from 'react';
import { cn } from '@/lib/utils';

/** Icon button that copies `text`; flips to a check for 1.5s. */
export function CopyButton({ text, label = 'Copy', className }: { text: string; label?: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1_500);
    } catch {
      /* clipboard blocked (insecure context / permissions) */
    }
  };
  return (
    <button
      type="button"
      onClick={copy}
      aria-label={copied ? 'Copied' : label}
      title={copied ? 'Copied' : label}
      className={cn(
        'inline-flex size-7 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
        copied && 'text-signal',
        className,
      )}
    >
      {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
    </button>
  );
}

/** A copyable single command / snippet line in the instrument-panel mono style. */
export function CommandLine({ text, prompt = '$', className }: { text: string; prompt?: string | null; className?: string }) {
  return (
    <div className={cn('flex min-w-0 items-start gap-2 rounded-md border bg-surface-raised py-1 pr-1 pl-3', className)}>
      {prompt && (
        <span aria-hidden className="mt-1 font-mono text-xs text-signal select-none">
          {prompt}
        </span>
      )}
      <code className="min-w-0 flex-1 py-1 font-mono text-xs break-all whitespace-pre-wrap">{text}</code>
      <CopyButton text={text} label="Copy command" />
    </div>
  );
}
