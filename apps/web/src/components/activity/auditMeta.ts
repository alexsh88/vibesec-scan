import {
  Ban,
  CircleCheck,
  CircleX,
  Download,
  FileCheck2,
  KeyRound,
  Lock,
  Play,
  RotateCw,
  Settings2,
  ShieldCheck,
  ShieldOff,
  Trash2,
  type LucideIcon,
} from 'lucide-react';
import type { AuditAction, AuditEntry } from '@/lib/api';
import { TRIAGE_LABEL } from '@/lib/taxonomy';

export type Tone = 'signal' | 'good' | 'bad' | 'warn' | 'info' | 'muted';

export const TONE_CLS: Record<Tone, string> = {
  signal: 'border-signal/50 bg-signal-soft text-signal',
  good: 'border-status-fixed/40 bg-status-fixed/10 text-status-fixed',
  bad: 'border-sev-critical/40 bg-sev-critical/10 text-sev-critical',
  warn: 'border-sev-medium/40 bg-sev-medium/10 text-sev-medium',
  info: 'border-status-triaged/40 bg-status-triaged/10 text-status-triaged',
  muted: 'border-border bg-muted text-muted-foreground',
};

export const ACTION_META: Record<AuditAction, { label: string; icon: LucideIcon; tone: Tone; group: ActionGroup }> = {
  'scan.created': { label: 'Scan created', icon: Play, tone: 'signal', group: 'scan' },
  'scan.resumed': { label: 'Scan resumed after restart', icon: RotateCw, tone: 'info', group: 'scan' },
  'scan.completed': { label: 'Scan completed', icon: CircleCheck, tone: 'good', group: 'scan' },
  'scan.failed': { label: 'Scan failed', icon: CircleX, tone: 'bad', group: 'scan' },
  'scan.cancelled': { label: 'Scan cancelled', icon: Ban, tone: 'muted', group: 'scan' },
  'repo.private_access': { label: 'Private repository accessed', icon: Lock, tone: 'warn', group: 'access' },
  'repo.deleted': { label: 'Scan history deleted', icon: Trash2, tone: 'warn', group: 'access' },
  'secret.verification_attempted': { label: 'Credential liveness check', icon: KeyRound, tone: 'warn', group: 'secrets' },
  'finding.triaged': { label: 'Finding triaged', icon: ShieldCheck, tone: 'info', group: 'triage' },
  'finding.untriaged': { label: 'Triage removed', icon: ShieldOff, tone: 'muted', group: 'triage' },
  'export.downloaded': { label: 'Report exported', icon: Download, tone: 'muted', group: 'exports' },
  'config.changed': { label: 'Configuration changed', icon: Settings2, tone: 'warn', group: 'access' },
  'audit.verified': { label: 'Audit chain verified', icon: FileCheck2, tone: 'good', group: 'access' },
};

export type ActionGroup = 'scan' | 'secrets' | 'triage' | 'exports' | 'access';

export const GROUPS: ReadonlyArray<{ id: 'all' | ActionGroup; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'scan', label: 'Lifecycle' },
  { id: 'secrets', label: 'Secret checks' },
  { id: 'triage', label: 'Triage' },
  { id: 'exports', label: 'Exports' },
  { id: 'access', label: 'Access' },
];

const str = (v: unknown): string | null => (typeof v === 'string' && v.length > 0 ? v : typeof v === 'number' ? String(v) : null);

const STATE_WORD: Record<string, string> = {
  COMPLETED: 'clean', COMPLETED_WITH_WARNINGS: 'with warnings',
};

/** Tone override for entries whose outcome lives in details (e.g. a LIVE credential is bad news). */
export function entryTone(e: AuditEntry): Tone {
  if (e.action === 'secret.verification_attempted') {
    const r = str(e.details.result);
    return r === 'live' ? 'bad' : r === 'revoked' ? 'good' : 'muted';
  }
  if (e.action === 'scan.completed' && e.details.state === 'COMPLETED_WITH_WARNINGS') return 'warn';
  return ACTION_META[e.action]?.tone ?? 'muted';
}

/** One-line human summary built from the entry's (already scrubbed) details. */
export function entrySummary(e: AuditEntry): string | null {
  const d = e.details;
  switch (e.action) {
    case 'scan.created': {
      const repo = str(d.repo);
      const ref = str(d.ref);
      return [repo, ref ? `@ ${ref}` : 'default branch', d.private ? '· private (token supplied)' : null].filter(Boolean).join(' ');
    }
    case 'scan.completed': {
      const s = str(d.state);
      return s ? `Finished ${STATE_WORD[s] ?? s.toLowerCase()}` : null;
    }
    case 'scan.failed':
      return str(d.code) ? `Error ${str(d.code)}` : null;
    case 'scan.resumed':
      return str(d.resumeCount) ? `Resume #${str(d.resumeCount)}` : null;
    case 'repo.private_access':
      return [str(d.tokenType) ? `${String(d.tokenType).toUpperCase()} token` : null, str(d.tokenFingerprint) ? `fingerprint ${str(d.tokenFingerprint)}` : null]
        .filter(Boolean).join(' · ');
    case 'finding.triaged':
    case 'finding.untriaged': {
      const st = str(d.status);
      const label = st && st in TRIAGE_LABEL ? TRIAGE_LABEL[st as keyof typeof TRIAGE_LABEL] : st;
      return label ? (e.action === 'finding.triaged' ? `Marked “${label}”` : `Was “${label}”`) : null;
    }
    case 'export.downloaded':
      return str(d.format) ? `${String(d.format).toUpperCase()} report downloaded` : null;
    default:
      return null;
  }
}
