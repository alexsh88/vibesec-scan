import { FolderTree } from 'lucide-react';
import type { IndexStats, ScanIndex } from '@/lib/api';
import { formatInt } from '@/lib/format';
import { Panel } from './primitives';

const SKIP_LABEL: Record<string, string> = {
  vendor: 'Vendored (node_modules, vendor/)',
  binary: 'Binary',
  too_large: 'Too large',
  minified: 'Minified',
  generated: 'Generated',
  symlink: 'Symlink',
  submodule: 'Submodule',
  file_limit: 'Over file limit',
};

/** Repository index stats: files by language, why files were skipped, import/entrypoint counts. */
export function IndexPanel({ stats, index }: { stats: IndexStats | null; index: ScanIndex | undefined }) {
  if (!stats) {
    return (
      <Panel id="index-h" icon={FolderTree} title="Repository index">
        <p className="text-sm text-muted-foreground">The repository hasn’t been indexed (yet).</p>
      </Panel>
    );
  }
  const langs = Object.entries(stats.byLanguage)
    .map(([k, v]) => [k, v ?? 0] as const)
    .sort((a, b) => b[1] - a[1]);
  const maxLang = Math.max(1, ...langs.map(([, v]) => v));
  const skipped = Object.entries(stats.skipped)
    .map(([k, v]) => [k, v ?? 0] as const)
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1]);
  const skippedTotal = skipped.reduce((s, [, v]) => s + v, 0);
  const truncated = (stats as IndexStats & { truncated?: boolean }).truncated === true;

  return (
    <Panel
      id="index-h"
      icon={FolderTree}
      title="Repository index"
      readout={`${formatInt(stats.indexedFiles)} / ${formatInt(stats.totalFiles)} files indexed`}
    >
      <div className="space-y-5">
        <dl className="grid grid-cols-3 gap-3">
          <Fact k="Imports" v={stats.imports} />
          <Fact k="Entrypoints" v={stats.entrypoints} />
          <Fact k="Packages used" v={index?.packages.length ?? null} />
        </dl>
        {truncated && (
          <p className="rounded-md border border-sev-medium/35 bg-sev-medium/5 px-3 py-2 text-xs">Index truncated — the repository exceeded the file cap.</p>
        )}

        <div className="space-y-2">
          <p className="eyebrow text-[10px]">Files by language</p>
          <ul className="space-y-1.5">
            {langs.map(([lang, n]) => (
              <li key={lang} className="grid grid-cols-[6.5rem_1fr_2.5rem] items-center gap-2">
                <span className="truncate font-mono text-xs">{lang}</span>
                <span className="h-1.5 overflow-hidden rounded-full bg-muted">
                  <span className="block h-full rounded-full bg-foreground/55" style={{ width: `${(n / maxLang) * 100}%` }} />
                </span>
                <span className="text-right font-mono text-xs tabular">{formatInt(n)}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="space-y-2">
          <p className="eyebrow text-[10px]">Skipped · {formatInt(skippedTotal)}</p>
          {skipped.length === 0 ? (
            <p className="font-mono text-[11px] text-muted-foreground">Nothing skipped.</p>
          ) : (
            <ul className="flex flex-wrap gap-1.5">
              {skipped.map(([k, v]) => (
                <li key={k} className="inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs">
                  {SKIP_LABEL[k] ?? k}
                  <span className="font-mono text-muted-foreground tabular">{formatInt(v)}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </Panel>
  );
}

function Fact({ k, v }: { k: string; v: number | null }) {
  return (
    <div className="rounded-md border bg-surface-raised px-3 py-2">
      <dt className="eyebrow text-[10px]">{k}</dt>
      <dd className="font-mono text-lg font-semibold tabular">{v === null ? '—' : formatInt(v)}</dd>
    </div>
  );
}
