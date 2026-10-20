import { describe, it, expect } from 'vitest';
import { inspectMultisigSignatureQuorum } from './multisig-proposal-aggregator.js';

describe('inspectMultisigSignatureQuorum', () => {
  it('computes normal severity and deterministic sha256 digest within nominal bounds', () => {
    const res = inspectMultisigSignatureQuorum({
      targetId: 'stellar-alert-01',
      collectedWeight: 120,
      requiredThreshold: 80,
      expiredSignerCount: 25,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('normal');
    expect(res.scoreBps).toBe(2000);
    expect(res.digestHex).toHaveLength(64);
  });

  it('escalates to critical when metrics breach thresholdLimit', () => {
    const res = inspectMultisigSignatureQuorum({
      targetId: 'stellar-alert-02',
      collectedWeight: 650,
      requiredThreshold: 300,
      expiredSignerCount: 1500,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('critical');
    expect(res.scoreBps).toBe(9500);
  });

  it('throws on blank targetId', () => {
    expect(() =>
      inspectMultisigSignatureQuorum({
        targetId: '   ',
        collectedWeight: 1,
        requiredThreshold: 2,
        expiredSignerCount: 3,
      }),
    ).toThrow(/targetId must not be empty/);
  });
});
