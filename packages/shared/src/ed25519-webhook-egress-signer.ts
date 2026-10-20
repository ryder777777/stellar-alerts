import { createHash } from 'node:crypto';

export interface Ed25519WebhookEnvelopeInput {
  targetId: string;
  payloadBytes: number;
  timestampSkewSecs: number;
  keyRotationEpoch: number;
  thresholdLimit?: number;
}

export interface Ed25519WebhookEnvelope {
  targetId: string;
  payloadBytes: number;
  timestampSkewSecs: number;
  keyRotationEpoch: number;
  scoreBps: number;
  severity: 'normal' | 'elevated' | 'critical';
  digestHex: string;
}

export function evaluateEd25519WebhookEnvelope(input: Ed25519WebhookEnvelopeInput): Ed25519WebhookEnvelope {
  const targetId = input.targetId.trim();
  if (!targetId) {
    throw new Error('evaluateEd25519WebhookEnvelope: targetId must not be empty');
  }
  if (
    !Number.isFinite(input.payloadBytes) ||
    !Number.isFinite(input.timestampSkewSecs) ||
    !Number.isFinite(input.keyRotationEpoch)
  ) {
    throw new Error('evaluateEd25519WebhookEnvelope: numeric metrics must be finite');
  }

  const v1 = Math.max(0, Math.trunc(input.payloadBytes));
  const v2 = Math.max(0, Math.trunc(input.timestampSkewSecs));
  const v3 = Math.max(0, Math.trunc(input.keyRotationEpoch));
  const limit = Math.max(1, Math.trunc(input.thresholdLimit ?? 1000));

  const scoreBps = Math.min(10000, Math.round(((v1 + v2) * 10000) / limit));
  let severity: 'normal' | 'elevated' | 'critical' = 'normal';
  if (v3 > limit || scoreBps >= 8500) {
    severity = 'critical';
  } else if (scoreBps >= 4500) {
    severity = 'elevated';
  }

  const payload = JSON.stringify({ targetId, payloadBytes: v1, timestampSkewSecs: v2, keyRotationEpoch: v3, scoreBps, severity });
  const digestHex = createHash('sha256').update(payload).digest('hex');

  return {
    targetId,
    payloadBytes: v1,
    timestampSkewSecs: v2,
    keyRotationEpoch: v3,
    scoreBps,
    severity,
    digestHex,
  };
}
