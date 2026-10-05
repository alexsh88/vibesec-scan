import { History } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { AuditTimeline } from "@/components/activity/AuditTimeline";
import {
  ACTION_META,
  GROUPS,
  type ActionGroup,
} from "@/components/activity/auditMeta";
import { ChainStatus } from "@/components/activity/ChainStatus";
import { EmptyState } from "@/components/feedback/EmptyState";
import { ErrorState } from "@/components/feedback/ErrorState";
import { Page, PageHeader } from "@/components/layout/Page";
import { Skeleton } from "@/components/ui/skeleton";
import { useAudit } from "@/hooks/queries";
import { useScanContext } from "@/hooks/useScanContext";
import type { AuditEntry } from "@/lib/api";
import { formatInt } from "@/lib/format";
import { cn } from "@/lib/utils";

const PAGE = 200;
/** Safety valve: never walk more than this many pages of the global log for one scan. */
const MAX_PAGES = 25;

/**
 * Spec screen 7b — the scan's slice of the append-only, hash-chained audit log. The API has no scanId
 * filter, so we page the global log (newest first) and keep entries whose scanId is this scan, stopping
 * once we're past the scan's creation time (nothing older can belong to it).
 */
export default function ActivityPage() {
  const { scanId, scan } = useScanContext();
  const audit = useAudit({ limit: PAGE });
  const [group, setGroup] = useState<"all" | ActionGroup>("all");

  const pages = audit.data?.pages;
  const oldest = pages?.at(-1)?.items.at(-1)?.at;
  const createdMs = Date.parse(scan.createdAt) - 60_000;
  const needMore =
    !!audit.hasNextPage &&
    (pages?.length ?? 0) < MAX_PAGES &&
    (oldest === undefined || Date.parse(oldest) >= createdMs);
  const { isFetchingNextPage, fetchNextPage } = audit;
  useEffect(() => {
    if (needMore && !isFetchingNextPage) void fetchNextPage();
  }, [needMore, isFetchingNextPage, fetchNextPage]);

  const mine = useMemo<AuditEntry[]>(
    () =>
      (pages ?? [])
        .flatMap((p) => p.items)
        .filter(
          (e) =>
            e.scanId === scanId ||
            (e.targetType === "scan" && e.targetId === scanId),
        ),
    [pages, scanId],
  );
  const counts = useMemo(() => {
    const c: Record<string, number> = { all: mine.length };
    for (const e of mine) {
      const g = ACTION_META[e.action]?.group ?? "access";
      c[g] = (c[g] ?? 0) + 1;
    }
    return c;
  }, [mine]);
  const shown =
    group === "all"
      ? mine
      : mine.filter(
          (e) => (ACTION_META[e.action]?.group ?? "access") === group,
        );

  return (
    <Page>
      <PageHeader
        eyebrow="Activity"
        title="Audit trail"
        description="Every security-relevant action on this scan — creation, lifecycle, credential liveness checks, triage decisions and exports — from the tamper-evident, hash-chained audit log."
      />

      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <div
          role="radiogroup"
          aria-label="Filter by action type"
          className="flex flex-wrap gap-1.5"
        >
          {GROUPS.map((g) => {
            const n = counts[g.id] ?? 0;
            const on = group === g.id;
            return (
              <button
                key={g.id}
                type="button"
                role="radio"
                aria-checked={on}
                onClick={() => setGroup(g.id)}
                disabled={g.id !== "all" && n === 0}
                className={cn(
                  "inline-flex h-7 items-center gap-1.5 rounded-full border px-3 text-xs transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none disabled:opacity-40",
                  on
                    ? "border-primary bg-primary text-primary-foreground"
                    : "hover:bg-accent",
                )}
              >
                {g.label}
                <span
                  className={cn(
                    "font-mono text-[10.5px] tabular",
                    on ? "opacity-80" : "text-muted-foreground",
                  )}
                >
                  {formatInt(n)}
                </span>
              </button>
            );
          })}
        </div>
        <ChainStatus />
      </div>

      {audit.isError ? (
        <ErrorState
          error={audit.error}
          onRetry={() => void audit.refetch()}
          title="Couldn’t load the audit log"
        />
      ) : audit.isPending ? (
        <div
          className="space-y-3"
          aria-busy="true"
          aria-label="Loading activity"
        >
          {[0, 1, 2, 3].map((i) => (
            <Skeleton key={i} className="ml-11 h-16" />
          ))}
        </div>
      ) : shown.length === 0 ? (
        <EmptyState
          icon={History}
          title={
            mine.length === 0
              ? "No activity recorded for this scan yet"
              : "Nothing of this type"
          }
          description={
            mine.length === 0
              ? "Entries appear as the scan runs, findings are triaged and reports are exported."
              : undefined
          }
        />
      ) : (
        <>
          <AuditTimeline scanId={scanId} entries={shown} />
          {(needMore || isFetchingNextPage) && (
            <p className="mt-2 font-mono text-[11px] text-muted-foreground">
              Loading older entries…
            </p>
          )}
        </>
      )}
    </Page>
  );
}
