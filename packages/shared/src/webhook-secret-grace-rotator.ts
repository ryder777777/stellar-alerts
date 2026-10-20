import { createHash } from 'node:crypto';

export interface SecretRotationVerificationInput {
  targetId: string;
  primaryMatchFlag: number;
  secondaryGraceRemainingSecs: number;
  rotationEpoch: number;
  thresholdLimit?: number;
}

export interface SecretRotationVerification {
  targetId: string;
  primaryMatchFlag: number;
  secondaryGraceRemainingSecs: number;
  rotationEpoch: number;
  scoreBps: number;
  severity: 'normal' | 'elevated' | 'critical';
  digestHex: string;
}

export function verifyDualGraceWebhookRotation(input: SecretRotationVerificationInput): SecretRotationVerification {
  const targetId = input.targetId.trim();
  if (!targetId) {
    throw new Error('verifyDualGraceWebhookRotation: targetId must not be empty');
  }
  if (
    !Number.isFinite(input.primaryMatchFlag) ||
    !Number.isFinite(input.secondaryGraceRemainingSecs) ||
    !Number.isFinite(input.rotationEpoch)
  ) {
    throw new Error('verifyDualGraceWebhookRotation: numeric metrics must be finite');
  }

  const v1 = Math.max(0, Math.trunc(input.primaryMatchFlag));
  const v2 = Math.max(0, Math.trunc(input.secondaryGraceRemainingSecs));
  const v3 = Math.max(0, Math.trunc(input.rotationEpoch));
  const limit = Math.max(1, Math.trunc(input.thresholdLimit ?? 1000));

  const scoreBps = Math.min(10000, Math.round(((v1 + v2) * 10000) / limit));
  let severity: 'normal' | 'elevated' | 'critical' = 'normal';
  if (v3 > limit || scoreBps >= 8500) {
    severity = 'critical';
  } else if (scoreBps >= 4500) {
    severity = 'elevated';
  }

  const payload = JSON.stringify({ targetId, primaryMatchFlag: v1, secondaryGraceRemainingSecs: v2, rotationEpoch: v3, scoreBps, severity });
  const digestHex = createHash('sha256').update(payload).digest('hex');

  return {
    targetId,
    primaryMatchFlag: v1,
    secondaryGraceRemainingSecs: v2,
    rotationEpoch: v3,
    scoreBps,
    severity,
    digestHex,
  };
}
