import { CATEGORIES, isTerminalState, type Category } from '@vibesec/shared';
import {
  ArrowRight,
  ChevronDown,
  Eye,
  EyeOff,
  GitBranch,

  KeyRound,
  LoaderCircle,
  Lock,
  ShieldCheck,
} from 'lucide-react';
import { forwardRef, useId, useImperativeHandle, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { useNavigate } from 'react-router';
import { toast } from 'sonner';
import { ErrorState } from '@/components/feedback/ErrorState';
import { CategoryIcon } from '@/components/security/CategoryIcon';
import { GithubMark } from '@/components/security/GithubMark';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { useStartScan } from '@/hooks/queries';
import { isApiError } from '@/lib/api';
import { CATEGORY_META } from '@/lib/taxonomy';
import { cn } from '@/lib/utils';
import {
  DEFAULT_BUDGET_USD,
  INITIAL_VALUES,
  normalizeRepoUrl,
  toRequest,
  validate,
  type FieldErrors,
  type ScanFormValues,
} from './validation';

export type ScanFormHandle = { fillRepo: (url: string) => void };

const SAMPLES = ['expressjs/cors', 'OWASP/NodeGoat', 'juice-shop/juice-shop'];

export const ScanForm = forwardRef<ScanFormHandle>(function ScanForm(_props, ref) {
  const [values, setValues] = useState<ScanFormValues>(INITIAL_VALUES);
  const [touched, setTouched] = useState<Partial<Record<keyof FieldErrors, boolean>>>({});
  const [submitted, setSubmitted] = useState(false);
  const [showToken, setShowToken] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [serverFieldErrors, setServerFieldErrors] = useState<FieldErrors>({});
  const repoInput = useRef<HTMLInputElement>(null);
  const tokenInput = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const start = useStartScan();
  const ids = { repo: useId(), ref: useId(), priv: useId(), token: useId(), verify: useId(), depth: useId(), budget: useId(), adv: useId() };

  const clientErrors = validate(values);
  const errors: FieldErrors = { ...serverFieldErrors, ...clientErrors };
  const show = (f: keyof FieldErrors) => (submitted || touched[f]) && errors[f];

  useImperativeHandle(ref, () => ({
    fillRepo: (url: string) => {
      setValues((v) => ({ ...v, repoUrl: url }));
      setTouched((t) => ({ ...t, repoUrl: true }));
      repoInput.current?.focus();
    },
  }));

  const set = <K extends keyof ScanFormValues>(key: K, value: ScanFormValues[K]) => {
    setValues((v) => ({ ...v, [key]: value }));
    if (key in serverFieldErrors) setServerFieldErrors((e) => ({ ...e, [key]: undefined }));
    if (start.isError) start.reset();
  };
  const touch = (f: keyof FieldErrors) => setTouched((t) => ({ ...t, [f]: true }));

  const toggleCategory = (c: Category, on: boolean) =>
    set('categories', on ? [...values.categories, c] : values.categories.filter((x) => x !== c));

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (start.isPending) return;
    setSubmitted(true);
    if (Object.keys(clientErrors).length > 0) {
      if (clientErrors.repoUrl) repoInput.current?.focus();
      else if (clientErrors.token) tokenInput.current?.focus();
      else if (clientErrors.historyDepth || clientErrors.categories || clientErrors.budgetUsd) setAdvancedOpen(true);
      return;
    }
    // Fresh Idempotency-Key per submit (generated in useStartScan).
    start.mutate(
      { body: toRequest(values) },
      {
        onSuccess: (res) => {
          const { scan } = res;
          const finished = isTerminalState(scan.state);
          if (scan.cacheHit === 'full' && finished) {
            toast.success('Served from cache — $0', { description: 'Same commit and settings as an earlier scan.' });
            navigate(`/scans/${res.scanId}/overview`);
          } else if (res.deduplicated && finished) {
            toast.success('Already scanned', { description: 'Showing the existing result.' });
            navigate(`/scans/${res.scanId}/overview`);
          } else if (res.deduplicated) {
            toast('Joined the scan already in progress', { description: 'The same repo and settings were being scanned.' });
            navigate(`/scans/${res.scanId}/live`);
          } else {
            navigate(`/scans/${res.scanId}/live`);
          }
        },
        onError: (err) => {
          if (!isApiError(err)) return;
          const fe: FieldErrors = {};
          for (const i of err.issues) {
            if (i.path === 'repoUrl') fe.repoUrl = i.message;
            else if (i.path === 'ref') fe.ref = i.message;
            else if (i.path.startsWith('auth')) fe.token = i.message;
            else if (i.path === 'options.historyDepth') fe.historyDepth = i.message;
            else if (i.path.startsWith('options.categories')) fe.categories = i.message;
            else if (i.path === 'options.budgetUsd') fe.budgetUsd = i.message;
          }
          if (err.code === 'AUTH_REQUIRED' || err.code === 'AUTH_INVALID') {
            setValues((v) => ({ ...v, isPrivate: true }));
            setTimeout(() => tokenInput.current?.focus(), 0);
          }
          setServerFieldErrors(fe);
        },
      },
    );
  };

  const advancedSummary = [
    values.verifySecrets ? 'verify credentials' : null,
    `${values.historyDepth || '?'} commits`,
    values.categories.length === CATEGORIES.length ? 'all categories' : `${values.categories.length}/${CATEGORIES.length} categories`,
    `$${values.budgetUsd || DEFAULT_BUDGET_USD} budget`,
  ]
    .filter(Boolean)
    .join(' · ');

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-5" aria-describedby={start.isError ? 'scan-form-error' : undefined}>
      {/* Repository */}
      <Field id={ids.repo} label="Repository" error={show('repoUrl') ? errors.repoUrl : undefined}>
        <div className="relative">
          <GithubMark className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            ref={repoInput}
            id={ids.repo}
            name="repoUrl"
            inputMode="url"
            autoComplete="off"
            spellCheck={false}
            autoFocus
            placeholder="https://github.com/owner/repo"
            value={values.repoUrl}
            onChange={(e) => set('repoUrl', e.target.value)}
            onBlur={() => {
              // An empty field only errors on submit — blurring it (e.g. to click a sample) must not.
              if (values.repoUrl.trim()) touch('repoUrl');
              const n = normalizeRepoUrl(values.repoUrl);
              if (n !== values.repoUrl) set('repoUrl', n);
            }}
            aria-invalid={!!show('repoUrl')}
            aria-describedby={show('repoUrl') ? `${ids.repo}-err` : `${ids.repo}-hint`}
            className="h-11 pl-9 font-mono text-[13px]"
          />
        </div>
        {!show('repoUrl') && (
          <p id={`${ids.repo}-hint`} className="flex flex-wrap items-center gap-x-1.5 gap-y-1 text-xs text-muted-foreground">
            Try
            {SAMPLES.map((s, i) => (
              <span key={s} className="inline-flex items-center gap-1.5">
                <button
                  type="button"
                  onMouseDown={(e) => e.preventDefault()}
                  className="rounded font-mono text-foreground/80 underline decoration-border underline-offset-4 hover:text-foreground hover:decoration-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                  onClick={() => {
                    set('repoUrl', `https://github.com/${s}`);
                    touch('repoUrl');
                  }}
                >
                  {s}
                </button>
                {i < SAMPLES.length - 1 && <span aria-hidden>·</span>}
              </span>
            ))}
          </p>
        )}
      </Field>

      {/* Ref + private toggle */}
      <div className="grid gap-4 sm:grid-cols-[1fr_auto] sm:items-start">
        <Field id={ids.ref} label="Branch, tag or commit" optional error={show('ref') ? errors.ref : undefined}>
          <div className="relative">
            <GitBranch aria-hidden className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              id={ids.ref}
              name="ref"
              autoComplete="off"
              spellCheck={false}
              placeholder="default branch"
              value={values.ref}
              onChange={(e) => set('ref', e.target.value)}
              onBlur={() => touch('ref')}
              aria-invalid={!!show('ref')}
              aria-describedby={show('ref') ? `${ids.ref}-err` : undefined}
              className="pl-9 font-mono text-[13px]"
            />
          </div>
        </Field>
        <div className="space-y-2">
          <span className="block text-sm font-medium sm:invisible" aria-hidden>
            Access
          </span>
          <label
            htmlFor={ids.priv}
            className={cn(
              'flex h-9 cursor-pointer items-center gap-2.5 rounded-md border px-3 text-sm transition-colors hover:bg-accent/60',
              values.isPrivate && 'border-signal/50 bg-signal-soft',
            )}
          >
            <Lock aria-hidden className="size-3.5 text-muted-foreground" />
            Private repo
            <Switch
              id={ids.priv}
              checked={values.isPrivate}
              onCheckedChange={(on) => {
                set('isPrivate', on);
                if (on) setTimeout(() => tokenInput.current?.focus(), 0);
              }}
            />
          </label>
        </div>
      </div>

      {/* PAT */}
      {values.isPrivate && (
        <div className="animate-rise rounded-lg border border-signal/30 bg-signal-soft/50 p-4">
          <Field id={ids.token} label="GitHub personal access token" error={show('token') ? errors.token : undefined}>
            <div className="relative">
              <KeyRound aria-hidden className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                ref={tokenInput}
                id={ids.token}
                name="token"
                type={showToken ? 'text' : 'password'}
                autoComplete="off"
                spellCheck={false}
                placeholder="github_pat_…"
                value={values.token}
                onChange={(e) => set('token', e.target.value)}
                onBlur={() => touch('token')}
                aria-invalid={!!show('token')}
                aria-describedby={`${ids.token}-hint${show('token') ? ` ${ids.token}-err` : ''}`}
                className="bg-background pr-10 pl-9 font-mono text-[13px]"
                data-1p-ignore
              />
              <button
                type="button"
                onClick={() => setShowToken((s) => !s)}
                className="absolute top-1/2 right-1.5 inline-flex size-7 -translate-y-1/2 items-center justify-center rounded text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                aria-label={showToken ? 'Hide token' : 'Show token'}
                aria-pressed={showToken}
              >
                {showToken ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
              </button>
            </div>
            <p id={`${ids.token}-hint`} className="flex items-start gap-1.5 text-xs text-muted-foreground">
              <ShieldCheck aria-hidden className="mt-px size-3.5 shrink-0 text-signal" />
              <span>
                Fine-grained token with <b className="font-medium text-foreground">Contents: read</b> · used only for this scan ·
                never stored or logged
              </span>
            </p>
          </Field>
        </div>
      )}

      {/* Advanced */}
      <div className="rounded-lg border">
        <button
          type="button"
          onClick={() => setAdvancedOpen((o) => !o)}
          aria-expanded={advancedOpen}
          aria-controls={ids.adv}
          className="flex w-full items-center gap-3 rounded-lg px-4 py-3 text-left transition-colors hover:bg-accent/40 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        >
          <span className="text-sm font-medium">Scan options</span>
          <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-muted-foreground">{advancedSummary}</span>
          <ChevronDown aria-hidden className={cn('size-4 text-muted-foreground transition-transform', advancedOpen && 'rotate-180')} />
        </button>
        {advancedOpen && (
          <div id={ids.adv} className="animate-rise space-y-5 border-t px-4 py-4">
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-1">
                <Label htmlFor={ids.verify}>Verify found credentials</Label>
                <p className="text-xs text-muted-foreground">
                  Checks whether leaked keys are still live by calling the provider’s API with a read-only request (e.g. “who am I”).
                  Nothing is written; each attempt is recorded in the audit log.
                </p>
              </div>
              <Switch id={ids.verify} checked={values.verifySecrets} onCheckedChange={(on) => set('verifySecrets', on)} />
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <Field
                id={ids.depth}
                label="History depth"
                hint="Commits of git history searched for credentials (0–500)."
                error={show('historyDepth') || errors.historyDepth ? errors.historyDepth : undefined}
              >
                <div className="relative">
                  <Input
                    id={ids.depth}
                    type="number"
                    inputMode="numeric"
                    min={0}
                    max={500}
                    step={1}
                    value={values.historyDepth}
                    onChange={(e) => set('historyDepth', e.target.value)}
                    onBlur={() => touch('historyDepth')}
                    aria-invalid={!!errors.historyDepth}
                    className="pr-20 font-mono tabular"
                  />
                  <span className="pointer-events-none absolute top-1/2 right-3 -translate-y-1/2 text-xs text-muted-foreground">commits</span>
                </div>
              </Field>
              <Field
                id={ids.budget}
                label="AI budget"
                hint={`Hard cap on Claude spend for this scan. Server default $${DEFAULT_BUDGET_USD}.`}
                error={errors.budgetUsd}
              >
                <div className="relative">
                  <span className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 font-mono text-sm text-muted-foreground">$</span>
                  <Input
                    id={ids.budget}
                    type="number"
                    inputMode="decimal"
                    min={0.5}
                    max={100}
                    step={0.5}
                    placeholder={DEFAULT_BUDGET_USD.toFixed(2)}
                    value={values.budgetUsd}
                    onChange={(e) => set('budgetUsd', e.target.value)}
                    onBlur={() => touch('budgetUsd')}
                    aria-invalid={!!errors.budgetUsd}
                    className="pl-7 font-mono tabular"
                  />
                </div>
              </Field>
            </div>

            <fieldset className="space-y-2">
              <legend className="mb-2 text-sm font-medium">Categories</legend>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {CATEGORIES.map((c) => {
                  const checked = values.categories.includes(c);
                  const cid = `${ids.adv}-cat-${c}`;
                  return (
                    <label
                      key={c}
                      htmlFor={cid}
                      className={cn(
                        'flex cursor-pointer items-center gap-2.5 rounded-md border px-3 py-2 text-sm transition-colors hover:bg-accent/50',
                        checked ? 'border-foreground/20 bg-accent/40' : 'text-muted-foreground',
                      )}
                      title={CATEGORY_META[c].description}
                    >
                      <Checkbox id={cid} checked={checked} onCheckedChange={(on) => toggleCategory(c, on === true)} />
                      <CategoryIcon category={c} className="size-3.5" />
                      {CATEGORY_META[c].label}
                    </label>
                  );
                })}
              </div>
              {errors.categories && (
                <p role="alert" className="text-xs text-destructive">
                  {errors.categories}
                </p>
              )}
            </fieldset>
          </div>
        )}
      </div>

      {start.isError && (
        <div id="scan-form-error">
          <ErrorState error={start.error} title="Couldn’t start the scan" compact onRetry={() => start.reset()} />
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3">
        <Button type="submit" size="lg" disabled={start.isPending} className="h-11 min-w-40 px-5 text-[15px]">
          {start.isPending ? (
            <>
              <LoaderCircle className="animate-spin" /> Starting…
            </>
          ) : (
            <>
              Start scan <ArrowRight />
            </>
          )}
        </Button>
        <p className="text-xs text-muted-foreground">Read-only clone · results in minutes · same commit rescans are free</p>
      </div>
    </form>
  );
});

function Field({
  id,
  label,
  optional,
  hint,
  error,
  children,
}: {
  id: string;
  label: string;
  optional?: boolean;
  hint?: string;
  error?: string;
  children: ReactNode;
}) {
  return (
    <div className="space-y-2">
      <Label htmlFor={id} className="gap-1.5">
        {label}
        {optional && <span className="font-normal text-muted-foreground">optional</span>}
      </Label>
      {children}
      {error ? (
        <p id={`${id}-err`} role="alert" className="text-xs text-destructive">
          {error}
        </p>
      ) : (
        hint && <p className="text-xs text-muted-foreground">{hint}</p>
      )}
    </div>
  );
}
