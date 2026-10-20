import { describe, it, expect } from 'vitest';
import { scoreMultiHopCounterpartyRisk } from './counterparty-risk-graph-scorer.js';

describe('scoreMultiHopCounterpartyRisk', () => {
  it('computes normal severity and deterministic sha256 digest within nominal bounds', () => {
    const res = scoreMultiHopCounterpartyRisk({
      targetId: 'stellar-alert-01',
      hopCount: 120,
      flaggedNeighborCount: 80,
      volumeStroops: 25,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('normal');
    expect(res.scoreBps).toBe(2000);
    expect(res.digestHex).toHaveLength(64);
  });

  it('escalates to critical when metrics breach thresholdLimit', () => {
    const res = scoreMultiHopCounterpartyRisk({
      targetId: 'stellar-alert-02',
      hopCount: 650,
      flaggedNeighborCount: 300,
      volumeStroops: 1500,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('critical');
    expect(res.scoreBps).toBe(9500);
  });

  it('throws on blank targetId', () => {
    expect(() =>
      scoreMultiHopCounterpartyRisk({
        targetId: '   ',
        hopCount: 1,
        flaggedNeighborCount: 2,
        volumeStroops: 3,
      }),
    ).toThrow(/targetId must not be empty/);
  });
});
