import { createHash } from 'node:crypto';

export interface CspDynamicNoncePolicyInput {
  targetId: string;
  directiveCount: number;
  nonceEntropyBits: number;
  inlineViolationCount: number;
  thresholdLimit?: number;
}

export interface CspDynamicNoncePolicy {
  targetId: string;
  directiveCount: number;
  nonceEntropyBits: number;
  inlineViolationCount: number;
  scoreBps: number;
  severity: 'normal' | 'elevated' | 'critical';
  digestHex: string;
}

export function generateCspDynamicNonceReport(input: CspDynamicNoncePolicyInput): CspDynamicNoncePolicy {
  const targetId = input.targetId.trim();
  if (!targetId) {
    throw new Error('generateCspDynamicNonceReport: targetId must not be empty');
  }
  if (
    !Number.isFinite(input.directiveCount) ||
    !Number.isFinite(input.nonceEntropyBits) ||
    !Number.isFinite(input.inlineViolationCount)
  ) {
    throw new Error('generateCspDynamicNonceReport: numeric metrics must be finite');
  }

  const v1 = Math.max(0, Math.trunc(input.directiveCount));
  const v2 = Math.max(0, Math.trunc(input.nonceEntropyBits));
  const v3 = Math.max(0, Math.trunc(input.inlineViolationCount));
  const limit = Math.max(1, Math.trunc(input.thresholdLimit ?? 1000));

  const scoreBps = Math.min(10000, Math.round(((v1 + v2) * 10000) / limit));
  let severity: 'normal' | 'elevated' | 'critical' = 'normal';
  if (v3 > limit || scoreBps >= 8500) {
    severity = 'critical';
  } else if (scoreBps >= 4500) {
    severity = 'elevated';
  }

  const payload = JSON.stringify({ targetId, directiveCount: v1, nonceEntropyBits: v2, inlineViolationCount: v3, scoreBps, severity });
  const digestHex = createHash('sha256').update(payload).digest('hex');

  return {
    targetId,
    directiveCount: v1,
    nonceEntropyBits: v2,
    inlineViolationCount: v3,
    scoreBps,
    severity,
    digestHex,
  };
}
