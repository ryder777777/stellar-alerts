import { describe, it, expect } from 'vitest';
import { verifyDualGraceWebhookRotation } from './webhook-secret-grace-rotator.js';

describe('verifyDualGraceWebhookRotation', () => {
  it('computes normal severity and deterministic sha256 digest within nominal bounds', () => {
    const res = verifyDualGraceWebhookRotation({
      targetId: 'stellar-alert-01',
      primaryMatchFlag: 120,
      secondaryGraceRemainingSecs: 80,
      rotationEpoch: 25,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('normal');
    expect(res.scoreBps).toBe(2000);
    expect(res.digestHex).toHaveLength(64);
  });

  it('escalates to critical when metrics breach thresholdLimit', () => {
    const res = verifyDualGraceWebhookRotation({
      targetId: 'stellar-alert-02',
      primaryMatchFlag: 650,
      secondaryGraceRemainingSecs: 300,
      rotationEpoch: 1500,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('critical');
    expect(res.scoreBps).toBe(9500);
  });

  it('throws on blank targetId', () => {
    expect(() =>
      verifyDualGraceWebhookRotation({
        targetId: '   ',
        primaryMatchFlag: 1,
        secondaryGraceRemainingSecs: 2,
        rotationEpoch: 3,
      }),
    ).toThrow(/targetId must not be empty/);
  });
});
