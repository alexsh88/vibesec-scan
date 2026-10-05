import { ChevronRight, Hash } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import type { AuditEntry } from "@/lib/api";
import { formatRelative } from "@/lib/format";
import { cn } from "@/lib/utils";
import { ACTION_META, entrySummary, entryTone, TONE_CLS } from "./auditMeta";

const dayFmt = new Intl.DateTimeFormat(undefined, {
  weekday: "short",
  month: "short",
  day: "numeric",
  year: "numeric",
});
const timeFmt = new Intl.DateTimeFormat(undefined, {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});

function dayLabel(iso: string): string {
  const d = new Date(iso);
  const today = new Date();
  const yesterday = new Date(Date.now() - 86_400_000);
  if (d.toDateString() === today.toDateString()) return "Today";
  if (d.toDateString() === yesterday.toDateString()) return "Yesterday";
  return dayFmt.format(d);
}

/** Newest-first entries grouped by calendar day, rendered as a vertical timeline. */
export function AuditTimeline({
  scanId,
  entries,
}: {
  scanId: string;
  entries: AuditEntry[];
}) {
  const groups: Array<{ day: string; items: AuditEntry[] }> = [];
  for (const e of entries) {
    const day = dayLabel(e.at);
    const last = groups[groups.length - 1];
    if (last && last.day === day) last.items.push(e);
    else groups.push({ day, items: [e] });
  }
  return (
    <div className="space-y-6">
      {groups.map((g) => (
        <section key={g.day} aria-label={g.day}>
          <h3 className="eyebrow mb-2">{g.day}</h3>
          <ol className="relative">
            {g.items.map((e, i) => (
              <TimelineItem
                key={e.seq}
                scanId={scanId}
                e={e}
                last={i === g.items.length - 1}
              />
            ))}
          </ol>
        </section>
      ))}
    </div>
  );
}

function TimelineItem({
  scanId,
  e,
  last,
}: {
  scanId: string;
  e: AuditEntry;
  last: boolean;
}) {
  const [open, setOpen] = useState(false);
  const meta = ACTION_META[e.action] ?? {
    label: e.action,
    icon: Hash,
    tone: "muted" as const,
  };
  const tone = entryTone(e);
  const summary = entrySummary(e);
  const isFinding = e.targetType === "finding";

  return (
    <li className="relative grid grid-cols-[2rem_1fr] gap-x-3 pb-4">
      {!last && (
        <span
          aria-hidden
          className="absolute top-8 bottom-0 left-[15px] w-px bg-border"
        />
      )}
      <span
        className={cn(
          "relative z-[1] grid size-8 place-items-center rounded-full border",
          TONE_CLS[tone],
        )}
      >
        <meta.icon aria-hidden className="size-3.5" />
      </span>
      <div className="min-w-0 rounded-lg border bg-card">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-3 pt-2.5">
          <span className="text-sm font-medium">{meta.label}</span>
          <time
            dateTime={e.at}
            title={new Date(e.at).toLocaleString()}
            className="font-mono text-[11px] text-muted-foreground tabular"
          >
            {timeFmt.format(new Date(e.at))} · {formatRelative(e.at)}
          </time>
          <span className="ml-auto font-mono text-[10.5px] text-muted-foreground/80 tabular">
            #{e.seq}
          </span>
        </div>
        <div className="space-y-1.5 px-3 pt-1 pb-2.5">
          {e.action === "secret.verification_attempted" ? (
            <SecretCheck e={e} />
          ) : (
            summary && (
              <p className="text-sm text-muted-foreground">{summary}</p>
            )
          )}
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
            {isFinding && (
              <Link
                to={`/scans/${scanId}/findings/${e.targetId}`}
                className="font-mono text-[11px] text-foreground hover:underline"
              >
                open finding {e.targetId.slice(0, 10)} →
              </Link>
            )}
            <button
              type="button"
              onClick={() => setOpen((v) => !v)}
              aria-expanded={open}
              className="inline-flex items-center gap-1 font-mono text-[10.5px] text-muted-foreground hover:text-foreground"
            >
              <ChevronRight
                aria-hidden
                className={cn(
                  "size-3 transition-transform",
                  open && "rotate-90",
                )}
              />
              {e.actor}
              {e.actorIp ? ` · ${e.actorIp}` : ""} · hash {e.hash.slice(0, 10)}
            </button>
          </div>
          {open && (
            <dl className="grid grid-cols-[6.5rem_1fr] gap-x-3 gap-y-1 rounded-md border bg-surface-raised p-2 font-mono text-[10.5px]">
              <Row k="target" v={`${e.targetType} ${e.targetId}`} />
              {e.userAgent && <Row k="user agent" v={e.userAgent} />}
              <Row k="hash" v={e.hash} />
              <Row k="prev hash" v={e.prevHash} />
              {Object.keys(e.details).length > 0 && (
                <Row k="details" v={JSON.stringify(e.details, null, 1)} />
              )}
            </dl>
          )}
        </div>
      </div>
    </li>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <>
      <dt className="text-muted-foreground">{k}</dt>
      <dd className="break-all whitespace-pre-wrap">{v}</dd>
    </>
  );
}

const RESULT_CLS: Record<string, string> = {
  live: "border-sev-critical/40 bg-sev-critical/10 text-sev-critical",
  revoked: "border-status-fixed/40 bg-status-fixed/10 text-status-fixed",
  unknown: "border-border bg-muted text-muted-foreground",
};

/** provider + redacted value + result — the redacted string is all the API ever stores. */
function SecretCheck({ e }: { e: AuditEntry }) {
  const d = e.details;
  const result = typeof d.result === "string" ? d.result : "unknown";
  return (
    <div className="flex flex-wrap items-center gap-2 text-sm">
      <span className="text-muted-foreground">Checked</span>
      {typeof d.secretType === "string" && (
        <span className="font-medium">{d.secretType}</span>
      )}
      {typeof d.redacted === "string" && (
        <code className="code-ref">{d.redacted}</code>
      )}
      {typeof d.provider === "string" && (
        <span className="text-muted-foreground">against {d.provider}</span>
      )}
      <span
        className={cn(
          "rounded-full border px-2 font-mono text-[10.5px] leading-5 uppercase",
          RESULT_CLS[result] ?? RESULT_CLS.unknown,
        )}
      >
        {result}
      </span>
      {typeof d.httpStatus === "number" && (
        <span className="font-mono text-[11px] text-muted-foreground">
          HTTP {d.httpStatus}
        </span>
      )}
      {d.aborted === true && (
        <span className="font-mono text-[11px] text-sev-medium">aborted</span>
      )}
    </div>
  );
}
