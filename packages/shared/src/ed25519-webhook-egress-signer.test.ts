import { describe, it, expect } from 'vitest';
import { evaluateEd25519WebhookEnvelope } from './ed25519-webhook-egress-signer.js';

describe('evaluateEd25519WebhookEnvelope', () => {
  it('computes normal severity and deterministic sha256 digest within nominal bounds', () => {
    const res = evaluateEd25519WebhookEnvelope({
      targetId: 'stellar-alert-01',
      payloadBytes: 120,
      timestampSkewSecs: 80,
      keyRotationEpoch: 25,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('normal');
    expect(res.scoreBps).toBe(2000);
    expect(res.digestHex).toHaveLength(64);
  });

  it('escalates to critical when metrics breach thresholdLimit', () => {
    const res = evaluateEd25519WebhookEnvelope({
      targetId: 'stellar-alert-02',
      payloadBytes: 650,
      timestampSkewSecs: 300,
      keyRotationEpoch: 1500,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('critical');
    expect(res.scoreBps).toBe(9500);
  });

  it('throws on blank targetId', () => {
    expect(() =>
      evaluateEd25519WebhookEnvelope({
        targetId: '   ',
        payloadBytes: 1,
        timestampSkewSecs: 2,
        keyRotationEpoch: 3,
      }),
    ).toThrow(/targetId must not be empty/);
  });
});
