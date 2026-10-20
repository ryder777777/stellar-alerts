import { describe, it, expect } from 'vitest';
import { generateCspDynamicNonceReport } from './csp-dynamic-nonce-pipeline.js';

describe('generateCspDynamicNonceReport', () => {
  it('computes normal severity and deterministic sha256 digest within nominal bounds', () => {
    const res = generateCspDynamicNonceReport({
      targetId: 'stellar-alert-01',
      directiveCount: 120,
      nonceEntropyBits: 80,
      inlineViolationCount: 25,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('normal');
    expect(res.scoreBps).toBe(2000);
    expect(res.digestHex).toHaveLength(64);
  });

  it('escalates to critical when metrics breach thresholdLimit', () => {
    const res = generateCspDynamicNonceReport({
      targetId: 'stellar-alert-02',
      directiveCount: 650,
      nonceEntropyBits: 300,
      inlineViolationCount: 1500,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('critical');
    expect(res.scoreBps).toBe(9500);
  });

  it('throws on blank targetId', () => {
    expect(() =>
      generateCspDynamicNonceReport({
        targetId: '   ',
        directiveCount: 1,
        nonceEntropyBits: 2,
        inlineViolationCount: 3,
      }),
    ).toThrow(/targetId must not be empty/);
  });
});
