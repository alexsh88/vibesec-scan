import type { Finding } from '@vibesec/shared';
import { CircleCheck, CircleHelp, CircleOff, GitCommitHorizontal, History, Zap, type LucideIcon } from 'lucide-react';
import { formatDateTime, formatRelative, shortSha } from '@/lib/format';
import { cn } from '@/lib/utils';
import { commitUrl } from './meta';

type Cred = NonNullable<Finding['secret']>;

const LIVENESS: Record<Cred['liveness'], { label: string; icon: LucideIcon; cls: string; hint: string }> = {
  live: { label: 'Live', icon: Zap, cls: 'border-sev-critical/40 bg-sev-critical/10 text-sev-critical', hint: 'The provider accepted this credential' },
  revoked: { label: 'Revoked', icon: CircleOff, cls: 'border-status-fixed/40 bg-status-fixed/10 text-status-fixed', hint: 'The provider rejected this credential' },
  unknown: { label: 'Unknown', icon: CircleHelp, cls: 'border-sev-medium/40 bg-sev-medium/10 text-sev-medium', hint: 'Verification was inconclusive' },
  not_checked: { label: 'Not checked', icon: CircleCheck, cls: 'border-border bg-muted text-muted-foreground', hint: 'Verification was not run for this scan' },
};

export function LivenessBadge({ liveness }: { liveness: Cred['liveness'] }) {
  const m = LIVENESS[liveness];
  return (
    <span className={cn('inline-flex h-5.5 items-center gap-1 rounded-full border px-2 text-[11px] font-medium', m.cls)} title={m.hint}>
      <m.icon aria-hidden className="size-3" />
      {m.label}
    </span>
  );
}

/**
 * Credential metadata. Only the redacted value the API returns is ever rendered: the raw value is
 * never sent to the browser and nothing here tries to reconstruct it.
 */
export function CredentialDetails({ cred, permalinkBase }: { cred: Cred; permalinkBase: string }) {
  const commitHref = cred.commit ? commitUrl(permalinkBase, cred.commit) : null;
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2.5 text-sm">
      <dt className="eyebrow pt-0.5">Type</dt>
      <dd className="font-medium">{cred.type}</dd>

      <dt className="eyebrow pt-0.5">Value</dt>
      <dd>
        <code className="code-ref break-all select-all" aria-label="Redacted credential value">
          {cred.redacted}
        </code>
        <span className="ml-2 text-xs text-muted-foreground">redacted</span>
      </dd>

      <dt className="eyebrow pt-1">Liveness</dt>
      <dd className="flex flex-wrap items-center gap-2">
        <LivenessBadge liveness={cred.liveness} />
        {cred.checkedAt && (
          <span className="text-xs text-muted-foreground" title={formatDateTime(cred.checkedAt)}>
            checked {formatRelative(cred.checkedAt)}
          </span>
        )}
      </dd>

      <dt className="eyebrow pt-0.5">Where</dt>
      <dd className="flex flex-wrap items-center gap-2 text-sm">
        {cred.inHistoryOnly ? (
          <span className="inline-flex items-center gap-1.5">
            <History aria-hidden className="size-3.5 text-muted-foreground" /> Git history only (removed from current code; still needs rotation)
          </span>
        ) : (
          <span>Present in the current code</span>
        )}
        {cred.commit &&
          (commitHref ? (
            <a
              href={commitHref}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 font-mono text-xs text-muted-foreground hover:text-foreground hover:underline"
            >
              <GitCommitHorizontal aria-hidden className="size-3.5" />
              {shortSha(cred.commit)}
            </a>
          ) : (
            <span className="font-mono text-xs text-muted-foreground">{shortSha(cred.commit)}</span>
          ))}
      </dd>
    </dl>
  );
}
