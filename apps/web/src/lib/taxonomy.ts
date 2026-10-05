import type { Category, RiskGrade, Severity, TriageStatus } from '@vibesec/shared';
import { Bug, FileCog, KeyRound, Package, Sparkles, Waypoints, type LucideIcon } from 'lucide-react';

export const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info',
};

/**
 * Tailwind classes per severity, built from the --sev-* tokens. Full class strings (not
 * interpolated) so Tailwind's scanner picks them up.
 */
export const SEVERITY_CLASSES: Record<Severity, { text: string; bg: string; soft: string; border: string; dot: string }> = {
  critical: { text: 'text-sev-critical', bg: 'bg-sev-critical', soft: 'bg-sev-critical/12', border: 'border-sev-critical/35', dot: 'bg-sev-critical' },
  high: { text: 'text-sev-high', bg: 'bg-sev-high', soft: 'bg-sev-high/12', border: 'border-sev-high/35', dot: 'bg-sev-high' },
  medium: { text: 'text-sev-medium', bg: 'bg-sev-medium', soft: 'bg-sev-medium/12', border: 'border-sev-medium/35', dot: 'bg-sev-medium' },
  low: { text: 'text-sev-low', bg: 'bg-sev-low', soft: 'bg-sev-low/12', border: 'border-sev-low/35', dot: 'bg-sev-low' },
  info: { text: 'text-sev-info', bg: 'bg-sev-info', soft: 'bg-sev-info/12', border: 'border-sev-info/30', dot: 'bg-sev-info' },
};

export const CATEGORY_META: Record<Category, { label: string; short: string; icon: LucideIcon; description: string }> = {
  secret: { label: 'Credentials', short: 'Secret', icon: KeyRound, description: 'Hard-coded keys, tokens and passwords, including git history' },
  sast: { label: 'Code', short: 'SAST', icon: Bug, description: 'Insecure code patterns found by static analysis + AI review' },
  taint: { label: 'Data flow', short: 'Taint', icon: Waypoints, description: 'Untrusted input reaching a dangerous sink' },
  dependency: { label: 'Dependencies', short: 'Deps', icon: Package, description: 'Known CVEs in npm / PyPI packages, with reachability' },
  config: { label: 'Config', short: 'Config', icon: FileCog, description: 'Risky infrastructure, CI and framework configuration' },
  quality: { label: 'Quality', short: 'Quality', icon: Sparkles, description: 'Security-relevant code quality issues' },
};

/** Findings page tabs (spec screen 4): "Code" groups SAST + taint. */
export const FINDING_TABS = [
  { id: 'code', label: 'Code', categories: ['sast', 'taint'] },
  { id: 'credentials', label: 'Credentials', categories: ['secret'] },
  { id: 'dependencies', label: 'Dependencies', categories: ['dependency'] },
  { id: 'config', label: 'Config', categories: ['config'] },
  { id: 'quality', label: 'Quality', categories: ['quality'] },
] as const satisfies ReadonlyArray<{ id: string; label: string; categories: readonly Category[] }>;

export const TRIAGE_LABEL: Record<TriageStatus, string> = {
  false_positive: 'False positive',
  accepted_risk: 'Accepted risk',
  wont_fix: "Won't fix",
};

export const GRADE_CLASSES: Record<RiskGrade, { text: string; soft: string; border: string }> = {
  A: { text: 'text-grade-a', soft: 'bg-grade-a/12', border: 'border-grade-a/40' },
  B: { text: 'text-grade-b', soft: 'bg-grade-b/12', border: 'border-grade-b/40' },
  C: { text: 'text-grade-c', soft: 'bg-grade-c/12', border: 'border-grade-c/40' },
  D: { text: 'text-grade-d', soft: 'bg-grade-d/12', border: 'border-grade-d/40' },
  F: { text: 'text-grade-f', soft: 'bg-grade-f/12', border: 'border-grade-f/40' },
};
