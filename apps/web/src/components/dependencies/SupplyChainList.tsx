import type { Finding } from '@vibesec/shared';
import { Globe, PackageX, ScrollText, SpellCheck2, type LucideIcon } from 'lucide-react';
import { Link } from 'react-router';
import { SeverityBadge } from '@/components/security/SeverityBadge';
import { TriagePill } from '@/components/security/StatusPill';

const RULES: Record<string, { label: string; icon: LucideIcon }> = {
  'supply-chain/malicious-package': { label: 'Malicious package', icon: PackageX },
  'supply-chain/typosquat': { label: 'Possible typosquat', icon: SpellCheck2 },
  'supply-chain/install-script': { label: 'Install script', icon: ScrollText },
  'supply-chain/non-registry-source': { label: 'Non-registry source', icon: Globe },
};

/** Supply-chain signals (no CVE involved): malicious, typosquat, install scripts, non-registry sources. */
export function SupplyChainList({ scanId, items }: { scanId: string; items: Finding[] }) {
  return (
    <ul className="divide-y overflow-hidden rounded-lg border bg-card">
      {items.map((f) => {
        const rule = RULES[f.ruleId] ?? { label: f.ruleId, icon: Globe };
        return (
          <li key={f.id}>
            <Link
              to={`/scans/${scanId}/findings/${f.id}`}
              className="flex items-start gap-3 px-3 py-3 hover:bg-accent/40 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none sm:px-4"
            >
              <span className="mt-0.5 grid size-7 shrink-0 place-items-center rounded-md border bg-surface-raised">
                <rule.icon aria-hidden className="size-3.5 text-muted-foreground" />
              </span>
              <span className="min-w-0 flex-1 space-y-1">
                <span className="flex flex-wrap items-center gap-2">
                  <span className="eyebrow">{rule.label}</span>
                  {f.dependency && (
                    <span className="font-mono text-[11px] text-muted-foreground">
                      {f.dependency.direct ? 'direct' : 'transitive'} · {f.dependency.scope}
                    </span>
                  )}
                  {f.triage && <TriagePill triage={f.triage} />}
                </span>
                <span className="block text-sm font-medium break-words">{f.title}</span>
                {f.impact && <span className="line-clamp-2 block text-xs text-muted-foreground">{f.impact}</span>}
              </span>
              <SeverityBadge severity={f.severity} className="shrink-0" />
            </Link>
          </li>
        );
      })}
    </ul>
  );
}
