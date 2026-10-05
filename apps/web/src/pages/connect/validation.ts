import { CATEGORIES, isValidRef, parseRepoUrl, type Category, type CreateScanRequest } from '@vibesec/shared';

export type ScanFormValues = {
  repoUrl: string;
  ref: string;
  isPrivate: boolean;
  token: string;
  verifySecrets: boolean;
  historyDepth: string;
  categories: Category[];
  /** Empty = server default (not sent, so it doesn't change the options hash used for caching). */
  budgetUsd: string;
};

export const DEFAULT_BUDGET_USD = 10;

export const INITIAL_VALUES: ScanFormValues = {
  repoUrl: '',
  ref: '',
  isPrivate: false,
  token: '',
  verifySecrets: false,
  historyDepth: '50',
  categories: [...CATEGORIES],
  budgetUsd: '',
};

export type FieldErrors = Partial<Record<'repoUrl' | 'ref' | 'token' | 'historyDepth' | 'categories' | 'budgetUsd', string>>;

/**
 * Lenient input → canonical URL: accepts `owner/repo`, `github.com/owner/repo` and http:// and
 * strips trailing slashes, then the shared rule (parseRepoUrl, same as CreateScanRequestSchema) decides.
 */
export function normalizeRepoUrl(input: string): string {
  let v = input.trim();
  if (!v) return v;
  if (/^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+\/?$/.test(v)) v = `https://github.com/${v}`;
  else if (/^(www\.)?github\.com\//i.test(v)) v = `https://${v.replace(/^www\./i, '')}`;
  else if (/^http:\/\/(www\.)?github\.com\//i.test(v)) v = v.replace(/^http:\/\/(www\.)?/i, 'https://');
  return v.replace(/\/+$/, '');
}

/** Same rules as the API's CreateScanRequestSchema / ScanOptionsSchema. */
export function validate(v: ScanFormValues): FieldErrors {
  const e: FieldErrors = {};
  const url = normalizeRepoUrl(v.repoUrl);
  if (!url) e.repoUrl = 'Enter a GitHub repository URL';
  else if (!parseRepoUrl(url)) e.repoUrl = 'Must be https://github.com/<owner>/<repo>';

  const ref = v.ref.trim();
  if (ref && (ref.length > 255 || !isValidRef(ref))) e.ref = 'Not a valid branch, tag or commit';

  if (v.isPrivate) {
    const t = v.token.trim();
    if (!t) e.token = 'A token is required to clone a private repository';
    else if (t.length < 10 || t.length > 255) e.token = 'That doesn’t look like a GitHub token (10–255 characters)';
  }

  const depth = Number(v.historyDepth);
  if (v.historyDepth.trim() === '' || !Number.isInteger(depth) || depth < 0 || depth > 500) {
    e.historyDepth = 'Whole number from 0 to 500';
  }

  if (v.categories.length === 0) e.categories = 'Pick at least one category';

  if (v.budgetUsd.trim() !== '') {
    const b = Number(v.budgetUsd);
    if (!Number.isFinite(b) || b < 0.5 || b > 100) e.budgetUsd = 'Between $0.50 and $100';
  }
  return e;
}

export function toRequest(v: ScanFormValues): CreateScanRequest {
  const ref = v.ref.trim();
  return {
    repoUrl: normalizeRepoUrl(v.repoUrl),
    ...(ref ? { ref } : {}),
    ...(v.isPrivate ? { auth: { type: 'pat' as const, token: v.token.trim() } } : {}),
    options: {
      verifySecrets: v.verifySecrets,
      historyDepth: Number(v.historyDepth),
      // Keep the canonical order so equal selections hash equally server-side.
      categories: CATEGORIES.filter((c) => v.categories.includes(c)),
      ...(v.budgetUsd.trim() !== '' ? { budgetUsd: Number(v.budgetUsd) } : {}),
    },
  };
}
