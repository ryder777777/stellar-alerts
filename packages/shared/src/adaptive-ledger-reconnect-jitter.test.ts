import { describe, it, expect } from 'vitest';
import { computeAdaptiveLedgerReconnectJitter } from './adaptive-ledger-reconnect-jitter.js';

describe('computeAdaptiveLedgerReconnectJitter', () => {
  it('computes normal severity and deterministic sha256 digest within nominal bounds', () => {
    const res = computeAdaptiveLedgerReconnectJitter({
      targetId: 'stellar-alert-01',
      disconnectAttempt: 120,
      baseDelayMs: 80,
      jitterSeed: 25,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('normal');
    expect(res.scoreBps).toBe(2000);
    expect(res.digestHex).toHaveLength(64);
  });

  it('escalates to critical when metrics breach thresholdLimit', () => {
    const res = computeAdaptiveLedgerReconnectJitter({
      targetId: 'stellar-alert-02',
      disconnectAttempt: 650,
      baseDelayMs: 300,
      jitterSeed: 1500,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('critical');
    expect(res.scoreBps).toBe(9500);
  });

  it('throws on blank targetId', () => {
    expect(() =>
      computeAdaptiveLedgerReconnectJitter({
        targetId: '   ',
        disconnectAttempt: 1,
        baseDelayMs: 2,
        jitterSeed: 3,
      }),
    ).toThrow(/targetId must not be empty/);
  });
});
