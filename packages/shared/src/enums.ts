import { z } from 'zod';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export const SeveritySchema = z.enum(SEVERITIES);
export type Severity = z.infer<typeof SeveritySchema>;

export const CATEGORIES = ['secret', 'sast', 'taint', 'quality', 'dependency', 'config'] as const;
export const CategorySchema = z.enum(CATEGORIES);
export type Category = z.infer<typeof CategorySchema>;

export const SCAN_STATES = [
  'QUEUED', 'RESOLVING', 'CLONING', 'INDEXING', 'ANALYZING', 'VERIFYING', 'SCORING', 'SYNTHESIZING',
  'COMPLETED', 'COMPLETED_WITH_WARNINGS', 'FAILED', 'CANCELLED',
] as const;
export const ScanStateSchema = z.enum(SCAN_STATES);
export type ScanState = z.infer<typeof ScanStateSchema>;

const TERMINAL: ReadonlySet<ScanState> = new Set(['COMPLETED', 'COMPLETED_WITH_WARNINGS', 'FAILED', 'CANCELLED']);
export const isTerminalState = (s: ScanState): boolean => TERMINAL.has(s);

export const CONFIDENCES = ['high', 'medium', 'low'] as const;
export const ConfidenceSchema = z.enum(CONFIDENCES);
