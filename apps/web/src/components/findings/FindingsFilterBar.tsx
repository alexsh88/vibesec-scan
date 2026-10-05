import { SEVERITIES, type Severity } from '@vibesec/shared';
import { ChevronDown, FileCode2, Search, SlidersHorizontal, X } from 'lucide-react';
import { forwardRef, useEffect, useId, useState, type ReactNode } from 'react';
import { CategoryLabel } from '@/components/security/CategoryIcon';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import type { FindingCounts } from '@/lib/api';
import { SEVERITY_CLASSES, SEVERITY_LABEL } from '@/lib/taxonomy';
import { cn } from '@/lib/utils';
import { activeFilterCount, type ListState, type StatusFilter, type TriageFilter } from './filters';

type Props = {
  state: ListState;
  counts: FindingCounts | undefined;
  knownFiles: string[];
  onChange: (patch: Partial<ListState>) => void;
  onReset: () => void;
};

/** Filter bar for the findings list; every control writes straight to the URL (via onChange). */
export const FindingsFilterBar = forwardRef<HTMLInputElement, Props>(function FindingsFilterBar(
  { state, counts, knownFiles, onChange, onReset },
  searchRef,
) {
  const active = activeFilterCount(state);
  return (
    <div className="flex flex-wrap items-center gap-2">
      <SearchInput ref={searchRef} value={state.q} onCommit={(q) => onChange({ q })} />
      <SeverityFilter value={state.severities} counts={counts?.bySeverity} onChange={(severities) => onChange({ severities })} />
      <Segmented<StatusFilter>
        label="Status"
        value={state.status}
        onChange={(status) => onChange({ status })}
        options={[
          { value: 'current', label: 'Current' },
          { value: 'new', label: 'New', count: counts?.byScanStatus.new },
          { value: 'existing', label: 'Existing', count: counts?.byScanStatus.existing },
          { value: 'fixed', label: 'Fixed', count: counts?.byScanStatus.fixed },
        ]}
      />
      <Segmented<TriageFilter>
        label="Triage"
        value={state.triage}
        onChange={(triage) => onChange({ triage })}
        options={[
          { value: 'open', label: 'Open' },
          { value: 'suppressed', label: 'Suppressed' },
          { value: 'all', label: 'All' },
        ]}
      />
      <FileFilter value={state.file} knownFiles={knownFiles} onCommit={(file) => onChange({ file })} />
      {state.category && (
        <span className="inline-flex h-8 items-center gap-1.5 rounded-md border border-signal/50 bg-card pr-1 pl-2.5 text-xs">
          <CategoryLabel category={state.category} className="text-foreground" />
          <button
            type="button"
            aria-label="Clear category filter"
            onClick={() => onChange({ category: null })}
            className="grid size-5 place-items-center rounded text-muted-foreground hover:bg-accent hover:text-foreground"
          >
            <X className="size-3" />
          </button>
        </span>
      )}
      {active > 0 && (
        <Button size="sm" variant="ghost" className="h-8 text-muted-foreground" onClick={onReset}>
          <X /> Reset {active > 1 ? `${active} filters` : 'filter'}
        </Button>
      )}
    </div>
  );
});

// ---------------------------------------------------------------------------------------------

const SearchInput = forwardRef<HTMLInputElement, { value: string; onCommit: (v: string) => void }>(function SearchInput(
  { value, onCommit },
  ref,
) {
  const [draft, setDraft] = useState(value);
  // Follow external changes (back/forward, reset) without clobbering what is being typed.
  useEffect(() => setDraft(value), [value]);
  useEffect(() => {
    if (draft.trim() === value) return;
    const t = setTimeout(() => onCommit(draft), 300);
    return () => clearTimeout(t);
  }, [draft, value, onCommit]);

  return (
    <label className="relative flex h-8 min-w-0 flex-1 basis-56 items-center sm:max-w-xs">
      <Search aria-hidden className="pointer-events-none absolute left-2.5 size-3.5 text-muted-foreground" />
      <input
        ref={ref}
        type="search"
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') onCommit(draft);
          if (e.key === 'Escape') {
            if (draft) setDraft('');
            else (e.target as HTMLInputElement).blur();
          }
        }}
        placeholder="Search title, file, rule…"
        aria-label="Search findings"
        className="h-full w-full rounded-md border bg-card pr-8 pl-8 text-sm outline-none placeholder:text-muted-foreground/70 focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/30 [&::-webkit-search-cancel-button]:hidden"
      />
      <kbd className="pointer-events-none absolute right-2 hidden rounded border bg-muted px-1 font-mono text-[10px] text-muted-foreground sm:block">/</kbd>
    </label>
  );
});

function SeverityFilter({
  value,
  counts,
  onChange,
}: {
  value: Severity[];
  counts: Partial<Record<Severity, number>> | undefined;
  onChange: (v: Severity[]) => void;
}) {
  const toggle = (s: Severity, on: boolean) => onChange(SEVERITIES.filter((x) => (x === s ? on : value.includes(x))));
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className={cn('h-8 gap-1.5 bg-card font-normal', value.length > 0 && 'border-signal/50')}>
          <SlidersHorizontal className="text-muted-foreground" />
          Severity
          {value.length > 0 && (
            <span className="ml-0.5 inline-flex items-center gap-0.5" aria-label={value.map((s) => SEVERITY_LABEL[s]).join(', ')}>
              {value.map((s) => (
                <span key={s} className={cn('size-2 rounded-full', SEVERITY_CLASSES[s].dot)} />
              ))}
            </span>
          )}
          <ChevronDown className="text-muted-foreground" />
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-56 p-1.5">
        <p className="eyebrow px-2 pt-1 pb-1.5">Severity</p>
        {SEVERITIES.map((s) => {
          const id = `sev-${s}`;
          return (
            <label
              key={s}
              htmlFor={id}
              className="flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-1.5 text-sm hover:bg-accent"
            >
              <Checkbox id={id} checked={value.includes(s)} onCheckedChange={(c) => toggle(s, c === true)} />
              <span className={cn('size-2 rounded-full', SEVERITY_CLASSES[s].dot)} aria-hidden />
              <span className="flex-1">{SEVERITY_LABEL[s]}</span>
              <span className="font-mono text-xs text-muted-foreground tabular">{counts?.[s] ?? 0}</span>
            </label>
          );
        })}
        {value.length > 0 && (
          <button
            type="button"
            onClick={() => onChange([])}
            className="mt-1 w-full rounded-md px-2 py-1.5 text-left text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
          >
            Clear selection
          </button>
        )}
      </PopoverContent>
    </Popover>
  );
}

function Segmented<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: Array<{ value: T; label: ReactNode; count?: number }>;
  onChange: (v: T) => void;
}) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex h-8 items-center rounded-md border bg-card p-0.5">
      {options.map((o) => {
        const on = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={on}
            onClick={() => onChange(o.value)}
            className={cn(
              'inline-flex h-full items-center gap-1.5 rounded-[5px] px-2.5 text-xs whitespace-nowrap text-muted-foreground transition-colors hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
              on && 'bg-accent font-medium text-foreground shadow-[inset_0_-1.5px_0_var(--signal)]',
            )}
          >
            {o.label}
            {o.count !== undefined && <span className="font-mono text-[10px] tabular opacity-70">{o.count}</span>}
          </button>
        );
      })}
    </div>
  );
}

function FileFilter({ value, knownFiles, onCommit }: { value: string; knownFiles: string[]; onCommit: (v: string) => void }) {
  const [draft, setDraft] = useState(value);
  const listId = useId();
  useEffect(() => setDraft(value), [value]);
  const commit = (v: string) => {
    if (v.trim() !== value) onCommit(v.trim());
  };
  return (
    <label className="relative flex h-8 min-w-0 basis-48 items-center">
      <FileCode2 aria-hidden className="pointer-events-none absolute left-2.5 size-3.5 text-muted-foreground" />
      <input
        value={draft}
        list={listId}
        onChange={(e) => {
          setDraft(e.target.value);
          // Picking a suggestion applies it immediately.
          if (knownFiles.includes(e.target.value)) commit(e.target.value);
        }}
        onKeyDown={(e) => e.key === 'Enter' && commit(draft)}
        onBlur={() => commit(draft)}
        placeholder="Exact file path"
        aria-label="Filter by file"
        className={cn(
          'h-full w-full rounded-md border bg-card pr-7 pl-8 font-mono text-xs outline-none placeholder:font-sans placeholder:text-muted-foreground/70 focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/30',
          value && 'border-signal/50',
        )}
      />
      <datalist id={listId}>
        {knownFiles.map((f) => (
          <option key={f} value={f} />
        ))}
      </datalist>
      {value && (
        <button
          type="button"
          aria-label="Clear file filter"
          onClick={() => onCommit('')}
          className="absolute right-1.5 grid size-5 place-items-center rounded text-muted-foreground hover:bg-accent hover:text-foreground"
        >
          <X className="size-3" />
        </button>
      )}
    </label>
  );
}
