import { describe, it, expect } from 'vitest';
import { verifyEd25519MonotonicNonce } from './ed25519-monotonic-nonce-guard.js';

describe('verifyEd25519MonotonicNonce', () => {
  it('computes normal severity and deterministic sha256 digest within nominal bounds', () => {
    const res = verifyEd25519MonotonicNonce({
      targetId: 'stellar-alert-01',
      incomingNonce: 120,
      lastRecordedNonce: 80,
      timestampDriftSecs: 25,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('normal');
    expect(res.scoreBps).toBe(2000);
    expect(res.digestHex).toHaveLength(64);
  });

  it('escalates to critical when metrics breach thresholdLimit', () => {
    const res = verifyEd25519MonotonicNonce({
      targetId: 'stellar-alert-02',
      incomingNonce: 650,
      lastRecordedNonce: 300,
      timestampDriftSecs: 1500,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('critical');
    expect(res.scoreBps).toBe(9500);
  });

  it('throws on blank targetId', () => {
    expect(() =>
      verifyEd25519MonotonicNonce({
        targetId: '   ',
        incomingNonce: 1,
        lastRecordedNonce: 2,
        timestampDriftSecs: 3,
      }),
    ).toThrow(/targetId must not be empty/);
  });
});
