import { describe, expect, it } from 'vitest';
import { classifyWarningLevel } from '../src/pipeline/warningLevels';

describe('classifyWarningLevel', () => {
  it('treats unverifiable AI claims rejected by the location verifier as info (coverage intact)', () => {
    expect(classifyWarningLevel('SAST_UNVERIFIED_DROPPED')).toBe('info');
    expect(classifyWarningLevel('TAINT_UNVERIFIED_DROPPED')).toBe('info');
  });

  it('keeps real degradation as warning', () => {
    expect(classifyWarningLevel('DEPENDENCY_FIX_PLAN_PARTIAL')).toBe('warning');
    expect(classifyWarningLevel('SAST_PARTIAL')).toBe('warning');
    expect(classifyWarningLevel('BUDGET_COVERAGE_PARTIAL')).toBe('warning');
  });

  it('defaults an unknown code to warning (fail safe)', () => {
    expect(classifyWarningLevel('SOMETHING_NEW')).toBe('warning');
  });
});
