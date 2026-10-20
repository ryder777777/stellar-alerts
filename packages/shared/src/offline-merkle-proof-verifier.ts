import { createHash } from 'node:crypto';

export interface OfflineMerkleVerificationInput {
  targetId: string;
  proofSiblingCount: number;
  leafIndex: number;
  treeHeight: number;
  thresholdLimit?: number;
}

export interface OfflineMerkleVerification {
  targetId: string;
  proofSiblingCount: number;
  leafIndex: number;
  treeHeight: number;
  scoreBps: number;
  severity: 'normal' | 'elevated' | 'critical';
  digestHex: string;
}

export function verifyOfflineMerkleInclusionBatch(input: OfflineMerkleVerificationInput): OfflineMerkleVerification {
  const targetId = input.targetId.trim();
  if (!targetId) {
    throw new Error('verifyOfflineMerkleInclusionBatch: targetId must not be empty');
  }
  if (
    !Number.isFinite(input.proofSiblingCount) ||
    !Number.isFinite(input.leafIndex) ||
    !Number.isFinite(input.treeHeight)
  ) {
    throw new Error('verifyOfflineMerkleInclusionBatch: numeric metrics must be finite');
  }

  const v1 = Math.max(0, Math.trunc(input.proofSiblingCount));
  const v2 = Math.max(0, Math.trunc(input.leafIndex));
  const v3 = Math.max(0, Math.trunc(input.treeHeight));
  const limit = Math.max(1, Math.trunc(input.thresholdLimit ?? 1000));

  const scoreBps = Math.min(10000, Math.round(((v1 + v2) * 10000) / limit));
  let severity: 'normal' | 'elevated' | 'critical' = 'normal';
  if (v3 > limit || scoreBps >= 8500) {
    severity = 'critical';
  } else if (scoreBps >= 4500) {
    severity = 'elevated';
  }

  const payload = JSON.stringify({ targetId, proofSiblingCount: v1, leafIndex: v2, treeHeight: v3, scoreBps, severity });
  const digestHex = createHash('sha256').update(payload).digest('hex');

  return {
    targetId,
    proofSiblingCount: v1,
    leafIndex: v2,
    treeHeight: v3,
    scoreBps,
    severity,
    digestHex,
  };
}
