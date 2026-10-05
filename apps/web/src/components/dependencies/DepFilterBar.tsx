import { RotateCcw } from 'lucide-react';
import { cn } from '@/lib/utils';
import { DEFAULT_FILTERS, type DepFilters } from './depModel';

type Option<V extends string> = { value: V; label: string };

/** Compact segmented control (radio group semantics). */
export function Segmented<V extends string>({
  label, value, options, onChange,
}: { label: string; value: V; options: ReadonlyArray<Option<V>>; onChange: (v: V) => void }) {
  return (
    <div role="radiogroup" aria-label={label} className="flex min-w-0 flex-col gap-1">
      <span className="eyebrow text-[10px]">{label}</span>
      <div className="flex flex-wrap rounded-md border bg-card p-0.5">
        {options.map((o) => (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={value === o.value}
            onClick={() => onChange(o.value)}
            className={cn(
              'h-6 rounded-[5px] px-2 font-mono text-[11px] whitespace-nowrap transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
              value === o.value ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground',
            )}
          >
            {o.label}
          </button>
        ))}
      </div>
    </div>
  );
}

export function DepFilterBar({ value, onChange }: { value: DepFilters; onChange: (v: DepFilters) => void }) {
  const set = <K extends keyof DepFilters>(k: K) => (v: DepFilters[K]) => onChange({ ...value, [k]: v });
  const dirty = (Object.keys(DEFAULT_FILTERS) as Array<keyof DepFilters>).some((k) => k !== 'sort' && value[k] !== DEFAULT_FILTERS[k]);
  return (
    <div className="flex flex-wrap items-end gap-x-4 gap-y-3">
      <Segmented
        label="Reachability"
        value={value.reachability}
        onChange={set('reachability')}
        options={[
          { value: 'all', label: 'All' },
          { value: 'reachable', label: 'Reachable' },
          { value: 'imported', label: 'Imported' },
          { value: 'unknown', label: 'Unknown' },
          { value: 'unreachable', label: 'Unreachable' },
        ]}
      />
      <Segmented
        label="Relation"
        value={value.relation}
        onChange={set('relation')}
        options={[
          { value: 'all', label: 'All' },
          { value: 'direct', label: 'Direct' },
          { value: 'transitive', label: 'Transitive' },
        ]}
      />
      <Segmented
        label="Scope"
        value={value.scope}
        onChange={set('scope')}
        options={[
          { value: 'all', label: 'All' },
          { value: 'prod', label: 'Prod' },
          { value: 'dev', label: 'Dev' },
        ]}
      />
      <Segmented
        label="Severity"
        value={value.minSeverity}
        onChange={set('minSeverity')}
        options={[
          { value: 'all', label: 'All' },
          { value: 'critical', label: 'Crit' },
          { value: 'high', label: '≥ High' },
          { value: 'medium', label: '≥ Med' },
        ]}
      />
      <Segmented
        label="Sort"
        value={value.sort}
        onChange={set('sort')}
        options={[
          { value: 'risk', label: 'Risk' },
          { value: 'cvss', label: 'CVSS' },
          { value: 'advisories', label: 'Count' },
          { value: 'name', label: 'A–Z' },
        ]}
      />
      {dirty && (
        <button
          type="button"
          onClick={() => onChange({ ...DEFAULT_FILTERS, sort: value.sort })}
          className="inline-flex h-7 items-center gap-1 rounded-md px-2 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
        >
          <RotateCcw className="size-3" /> Reset
        </button>
      )}
    </div>
  );
}
