import { describe, expect, it } from 'vitest';
import { cvssV3Score, cvssV4Score, severityFromScore } from '../src/analyzers/dependencies/osv/cvss';

describe('cvssV3Score', () => {
  it('computes the official base score for a textbook critical vector', () => {
    expect(cvssV3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(9.8);
  });

  it('computes the official base score for a medium vector with AC:H', () => {
    expect(cvssV3Score('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N')).toBe(5.9);
  });

  it('computes the official base score for a scope-changed (S:C) vector', () => {
    expect(cvssV3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')).toBe(10);
    expect(cvssV3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N')).toBe(6.1);
  });

  it('applies the 1.08 scope-changed multiplier (official FIRST calculator values)', () => {
    expect(cvssV3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H')).toBe(9.6);
    expect(cvssV3Score('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H')).toBe(9.9);
    expect(cvssV3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N')).toBe(7.2);
    expect(cvssV3Score('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N')).toBe(6.4);
    expect(cvssV3Score('CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(8.4);
  });

  it('accepts CVSS:3.0 vectors using the same metric weights', () => {
    expect(cvssV3Score('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(9.8);
  });

  it('returns 0 when the impact sub-score is zero', () => {
    expect(cvssV3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N')).toBe(0);
  });

  it('returns null for a v4 vector, a non-CVSS string, or a vector missing required metrics', () => {
    expect(cvssV3Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')).toBeNull();
    expect(cvssV3Score('not a vector')).toBeNull();
    expect(cvssV3Score('')).toBeNull();
    expect(cvssV3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H')).toBeNull();
    expect(cvssV3Score('CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBeNull();
  });
});

describe('cvssV4Score (documented approximation)', () => {
  it('returns a finite score in [0, 10] for a fully-specified v4 vector', () => {
    const score = cvssV4Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
    expect(score).not.toBeNull();
    expect(score as number).toBeGreaterThan(0);
    expect(score as number).toBeLessThanOrEqual(10);
  });

  it('is monotonic: a fully-local-low vector scores lower than a network-high vector', () => {
    const high = cvssV4Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
    const low = cvssV4Score('CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N');
    expect(low).toBe(0);
    expect((high as number) > (low as number)).toBe(true);
  });

  it('returns null for a v3 vector or a vector missing required v4 metrics', () => {
    expect(cvssV4Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBeNull();
    expect(cvssV4Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H')).toBeNull();
    expect(cvssV4Score('garbage')).toBeNull();
  });
});

describe('severityFromScore', () => {
  it('maps the documented buckets', () => {
    expect(severityFromScore(0)).toBe('info');
    expect(severityFromScore(0.1)).toBe('low');
    expect(severityFromScore(3.9)).toBe('low');
    expect(severityFromScore(4)).toBe('medium');
    expect(severityFromScore(6.9)).toBe('medium');
    expect(severityFromScore(7)).toBe('high');
    expect(severityFromScore(8.9)).toBe('high');
    expect(severityFromScore(9)).toBe('critical');
    expect(severityFromScore(10)).toBe('critical');
  });
});
