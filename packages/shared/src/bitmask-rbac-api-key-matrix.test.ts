import { describe, it, expect } from 'vitest';
import { evaluateGranularBitmaskRbac } from './bitmask-rbac-api-key-matrix.js';

describe('evaluateGranularBitmaskRbac', () => {
  it('computes normal severity and deterministic sha256 digest within nominal bounds', () => {
    const res = evaluateGranularBitmaskRbac({
      targetId: 'stellar-alert-01',
      grantedBitmask: 120,
      requiredBitmask: 80,
      scopeRestrictionCount: 25,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('normal');
    expect(res.scoreBps).toBe(2000);
    expect(res.digestHex).toHaveLength(64);
  });

  it('escalates to critical when metrics breach thresholdLimit', () => {
    const res = evaluateGranularBitmaskRbac({
      targetId: 'stellar-alert-02',
      grantedBitmask: 650,
      requiredBitmask: 300,
      scopeRestrictionCount: 1500,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('critical');
    expect(res.scoreBps).toBe(9500);
  });

  it('throws on blank targetId', () => {
    expect(() =>
      evaluateGranularBitmaskRbac({
        targetId: '   ',
        grantedBitmask: 1,
        requiredBitmask: 2,
        scopeRestrictionCount: 3,
      }),
    ).toThrow(/targetId must not be empty/);
  });
});
