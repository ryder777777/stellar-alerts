import { describe, it, expect } from 'vitest';
import { evaluateSorobanStateTtlExpiration } from './soroban-state-ttl-sentinel.js';

describe('evaluateSorobanStateTtlExpiration', () => {
  it('computes normal severity and deterministic sha256 digest within nominal bounds', () => {
    const res = evaluateSorobanStateTtlExpiration({
      targetId: 'stellar-alert-01',
      currentLedger: 120,
      liveUntilLedger: 80,
      warningWindowLedgers: 25,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('normal');
    expect(res.scoreBps).toBe(2000);
    expect(res.digestHex).toHaveLength(64);
  });

  it('escalates to critical when metrics breach thresholdLimit', () => {
    const res = evaluateSorobanStateTtlExpiration({
      targetId: 'stellar-alert-02',
      currentLedger: 650,
      liveUntilLedger: 300,
      warningWindowLedgers: 1500,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('critical');
    expect(res.scoreBps).toBe(9500);
  });

  it('throws on blank targetId', () => {
    expect(() =>
      evaluateSorobanStateTtlExpiration({
        targetId: '   ',
        currentLedger: 1,
        liveUntilLedger: 2,
        warningWindowLedgers: 3,
      }),
    ).toThrow(/targetId must not be empty/);
  });
});
