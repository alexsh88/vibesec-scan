/**
 * Findings list state, kept entirely in the URL search params so a filtered view is shareable,
 * survives reloads and is preserved when the finding drawer (a nested route) opens and closes.
 *
 *   ?tab=code|credentials|dependencies|config|quality   (default: derived from `category`, else code)
 *   &category=taint                                      one category (narrows the tab; selects it if no `tab`)
 *   &severity=critical,high                              severity multi-select (empty = all)
 *   &scanStatus=new|existing|fixed                       (absent = current: new + existing)
 *   &triage=open|suppressed|all                          (absent = open)
 *   &file=src/app.js                                     exact file path
 *   &q=sql                                               free text (title, file, rule id)
 *   &info=1                                              show info-severity ("low-signal") findings
 *
 * `severity`, `category` and `scanStatus` are named like the API's FindingFilters keys, so deep links
 * from other pages (components/overview/links.ts) land on the right tab + filters.
 *
 * The API filters by ONE category and ONE severity, so multi-valued filters (the Code tab's
 * sast+taint, several severities, hiding info) are applied client-side on top of the server query.
 */
import { CATEGORIES, SEVERITIES, type Category, type Finding, type Severity } from '@vibesec/shared';
import type { FindingFilters } from '@/lib/api';
import { FINDING_TABS } from '@/lib/taxonomy';

export type TabId = (typeof FINDING_TABS)[number]['id'];
export type TriageFilter = NonNullable<FindingFilters['triage']>;
export type StatusFilter = Finding['scanStatus'] | 'current';

export type ListState = {
  tab: TabId;
  /** Optional narrowing to one category of the tab (e.g. taint inside Code). */
  category: Category | null;
  severities: Severity[];
  status: StatusFilter;
  triage: TriageFilter;
  file: string;
  q: string;
  showInfo: boolean;
};

const TAB_IDS = FINDING_TABS.map((t) => t.id) as readonly string[];

export function tabFor(id: TabId) {
  return FINDING_TABS.find((t) => t.id === id) ?? FINDING_TABS[0];
}

export function tabOfCategory(c: Category): TabId {
  return (FINDING_TABS.find((t) => (t.categories as readonly Category[]).includes(c)) ?? FINDING_TABS[0]).id;
}

export function readListState(sp: URLSearchParams): ListState {
  const rawTab = sp.get('tab');
  const rawCat = sp.get('category');
  const category = rawCat && (CATEGORIES as readonly string[]).includes(rawCat) ? (rawCat as Category) : null;
  const tab: TabId = rawTab && TAB_IDS.includes(rawTab) ? (rawTab as TabId) : category ? tabOfCategory(category) : 'code';
  const status = sp.get('scanStatus');
  const triage = sp.get('triage');
  const sev = (sp.get('severity') ?? '')
    .split(',')
    .filter((s): s is Severity => (SEVERITIES as readonly string[]).includes(s));
  return {
    tab,
    // Only meaningful when it narrows a multi-category tab (taint inside Code); otherwise ignored.
    category:
      category && tabFor(tab).categories.length > 1 && (tabFor(tab).categories as readonly Category[]).includes(category) ? category : null,
    severities: SEVERITIES.filter((s) => sev.includes(s)),
    status: status === 'new' || status === 'existing' || status === 'fixed' ? status : 'current',
    triage: triage === 'suppressed' || triage === 'all' ? triage : 'open',
    file: sp.get('file') ?? '',
    q: sp.get('q') ?? '',
    showInfo: sp.get('info') === '1',
  };
}

/** Returns a copy of `sp` with `patch` applied; defaults are removed to keep URLs short. */
export function writeListState(sp: URLSearchParams, patch: Partial<ListState>): URLSearchParams {
  const next = new URLSearchParams(sp);
  const set = (k: string, v: string | null) => (v ? next.set(k, v) : next.delete(k));
  if ('tab' in patch) {
    set('tab', patch.tab === 'code' ? null : patch.tab!);
    if (!('category' in patch)) next.delete('category'); // switching tabs drops the narrowing
  }
  if ('category' in patch) set('category', patch.category ?? null);
  if ('severities' in patch) set('severity', patch.severities!.join(',') || null);
  if ('status' in patch) set('scanStatus', patch.status === 'current' ? null : patch.status!);
  if ('triage' in patch) set('triage', patch.triage === 'open' ? null : patch.triage!);
  if ('file' in patch) set('file', patch.file || null);
  if ('q' in patch) set('q', patch.q?.trim() || null);
  if ('showInfo' in patch) set('info', patch.showInfo ? '1' : null);
  return next;
}

/** What the server can filter. */
export function serverFilters(s: ListState): FindingFilters {
  const cats = tabFor(s.tab).categories as readonly Category[];
  return {
    category: s.category ?? (cats.length === 1 ? cats[0] : undefined),
    severity: s.severities.length === 1 ? s.severities[0] : undefined,
    file: s.file || undefined,
    q: s.q || undefined,
    triage: s.triage,
    scanStatus: s.status === 'current' ? undefined : s.status,
    limit: 100,
  };
}

/** Info is "low-signal": hidden unless toggled on or explicitly selected in the severity filter. */
export function infoHidden(s: ListState): boolean {
  return !s.showInfo && !s.severities.includes('info');
}

/** The client-side part of the filter (applied to the server's pages). */
export function matchesClient(f: Finding, s: ListState, opts: { ignoreInfoToggle?: boolean } = {}): boolean {
  const cats = tabFor(s.tab).categories as readonly Category[];
  if (!cats.includes(f.category)) return false;
  if (s.category && f.category !== s.category) return false;
  if (s.severities.length > 0 && !s.severities.includes(f.severity)) return false;
  if (!opts.ignoreInfoToggle && infoHidden(s) && f.severity === 'info') return false;
  return true;
}

export function activeFilterCount(s: ListState): number {
  return (
    (s.category ? 1 : 0) +
    (s.severities.length ? 1 : 0) + (s.status !== 'current' ? 1 : 0) + (s.triage !== 'open' ? 1 : 0) + (s.file ? 1 : 0) + (s.q ? 1 : 0)
  );
}

/** Shared with the drawer (via <Outlet context>) for previous/next navigation in the list order. */
export type FindingsOutletContext = {
  ids: string[];
  hasMore: boolean;
  loadMore: () => void;
  loadingMore: boolean;
  /** Lets the list follow the drawer, so closing it leaves the cursor on the last viewed finding. */
  onViewed: (id: string) => void;
};
