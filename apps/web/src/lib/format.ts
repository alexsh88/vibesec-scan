import type { ScanDto } from '@vibesec/shared';

const usdFmt = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: 2, maximumFractionDigits: 2 });
const usdSmallFmt = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: 3, maximumFractionDigits: 3 });
const intFmt = new Intl.NumberFormat('en-US');
const compactFmt = new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 });
const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });

/** $0.00; sub-cent amounts keep 3 decimals so "$0.004" isn't shown as "$0.00". */
export function formatUsd(v: number): string {
  if (v > 0 && v < 0.01) return usdSmallFmt.format(v);
  return usdFmt.format(v);
}

export const formatInt = (v: number): string => intFmt.format(v);
export const formatCompact = (v: number): string => compactFmt.format(v);

export function formatDuration(ms: number | null | undefined): string {
  if (ms == null) return '—';
  if (ms < 1_000) return `${ms} ms`;
  const s = Math.round(ms / 1_000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${String(s % 60).padStart(2, '0')}s`;
}

export function formatRelative(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return '—';
  const diff = (Date.parse(iso) - now) / 1_000;
  const abs = Math.abs(diff);
  if (abs < 45) return 'just now';
  if (abs < 3_600) return rtf.format(Math.round(diff / 60), 'minute');
  if (abs < 86_400) return rtf.format(Math.round(diff / 3_600), 'hour');
  if (abs < 86_400 * 30) return rtf.format(Math.round(diff / 86_400), 'day');
  return new Date(iso).toLocaleDateString();
}

export const formatDateTime = (iso: string | null | undefined): string => (iso ? new Date(iso).toLocaleString() : '—');

export const shortSha = (sha: string | null | undefined): string => (sha ? sha.slice(0, 7) : '—');

export const repoSlug = (scan: Pick<ScanDto, 'repo'>): string => `${scan.repo.owner}/${scan.repo.name}`;

export const githubUrl = (owner: string, name: string): string => `https://github.com/${owner}/${name}`;
