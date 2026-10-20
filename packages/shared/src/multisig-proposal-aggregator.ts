import { createHash } from 'node:crypto';

export interface MultisigProposalStatusInput {
  targetId: string;
  collectedWeight: number;
  requiredThreshold: number;
  expiredSignerCount: number;
  thresholdLimit?: number;
}

export interface MultisigProposalStatus {
  targetId: string;
  collectedWeight: number;
  requiredThreshold: number;
  expiredSignerCount: number;
  scoreBps: number;
  severity: 'normal' | 'elevated' | 'critical';
  digestHex: string;
}

export function inspectMultisigSignatureQuorum(input: MultisigProposalStatusInput): MultisigProposalStatus {
  const targetId = input.targetId.trim();
  if (!targetId) {
    throw new Error('inspectMultisigSignatureQuorum: targetId must not be empty');
  }
  if (
    !Number.isFinite(input.collectedWeight) ||
    !Number.isFinite(input.requiredThreshold) ||
    !Number.isFinite(input.expiredSignerCount)
  ) {
    throw new Error('inspectMultisigSignatureQuorum: numeric metrics must be finite');
  }

  const v1 = Math.max(0, Math.trunc(input.collectedWeight));
  const v2 = Math.max(0, Math.trunc(input.requiredThreshold));
  const v3 = Math.max(0, Math.trunc(input.expiredSignerCount));
  const limit = Math.max(1, Math.trunc(input.thresholdLimit ?? 1000));

  const scoreBps = Math.min(10000, Math.round(((v1 + v2) * 10000) / limit));
  let severity: 'normal' | 'elevated' | 'critical' = 'normal';
  if (v3 > limit || scoreBps >= 8500) {
    severity = 'critical';
  } else if (scoreBps >= 4500) {
    severity = 'elevated';
  }

  const payload = JSON.stringify({ targetId, collectedWeight: v1, requiredThreshold: v2, expiredSignerCount: v3, scoreBps, severity });
  const digestHex = createHash('sha256').update(payload).digest('hex');

  return {
    targetId,
    collectedWeight: v1,
    requiredThreshold: v2,
    expiredSignerCount: v3,
    scoreBps,
    severity,
    digestHex,
  };
}
