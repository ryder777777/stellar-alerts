import { describe, it, expect } from 'vitest';
import { computeWebGlPaymentParticleBudget } from './webgl-payment-particle-budget.js';

describe('computeWebGlPaymentParticleBudget', () => {
  it('computes normal severity and deterministic sha256 digest within nominal bounds', () => {
    const res = computeWebGlPaymentParticleBudget({
      targetId: 'stellar-alert-01',
      paymentsPerSec: 120,
      activeParticles: 80,
      targetFps: 25,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('normal');
    expect(res.scoreBps).toBe(2000);
    expect(res.digestHex).toHaveLength(64);
  });

  it('escalates to critical when metrics breach thresholdLimit', () => {
    const res = computeWebGlPaymentParticleBudget({
      targetId: 'stellar-alert-02',
      paymentsPerSec: 650,
      activeParticles: 300,
      targetFps: 1500,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('critical');
    expect(res.scoreBps).toBe(9500);
  });

  it('throws on blank targetId', () => {
    expect(() =>
      computeWebGlPaymentParticleBudget({
        targetId: '   ',
        paymentsPerSec: 1,
        activeParticles: 2,
        targetFps: 3,
      }),
    ).toThrow(/targetId must not be empty/);
  });
});
