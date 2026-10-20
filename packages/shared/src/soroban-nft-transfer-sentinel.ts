import { createHash } from 'node:crypto';

export interface NftTransferEventAlertInput {
  targetId: string;
  transferCount: number;
  mintBatchSize: number;
  royaltyBps: number;
  thresholdLimit?: number;
}

export interface NftTransferEventAlert {
  targetId: string;
  transferCount: number;
  mintBatchSize: number;
  royaltyBps: number;
  scoreBps: number;
  severity: 'normal' | 'elevated' | 'critical';
  digestHex: string;
}

export function evaluateSorobanNftTransferSentinel(input: NftTransferEventAlertInput): NftTransferEventAlert {
  const targetId = input.targetId.trim();
  if (!targetId) {
    throw new Error('evaluateSorobanNftTransferSentinel: targetId must not be empty');
  }
  if (
    !Number.isFinite(input.transferCount) ||
    !Number.isFinite(input.mintBatchSize) ||
    !Number.isFinite(input.royaltyBps)
  ) {
    throw new Error('evaluateSorobanNftTransferSentinel: numeric metrics must be finite');
  }

  const v1 = Math.max(0, Math.trunc(input.transferCount));
  const v2 = Math.max(0, Math.trunc(input.mintBatchSize));
  const v3 = Math.max(0, Math.trunc(input.royaltyBps));
  const limit = Math.max(1, Math.trunc(input.thresholdLimit ?? 1000));

  const scoreBps = Math.min(10000, Math.round(((v1 + v2) * 10000) / limit));
  let severity: 'normal' | 'elevated' | 'critical' = 'normal';
  if (v3 > limit || scoreBps >= 8500) {
    severity = 'critical';
  } else if (scoreBps >= 4500) {
    severity = 'elevated';
  }

  const payload = JSON.stringify({ targetId, transferCount: v1, mintBatchSize: v2, royaltyBps: v3, scoreBps, severity });
  const digestHex = createHash('sha256').update(payload).digest('hex');

  return {
    targetId,
    transferCount: v1,
    mintBatchSize: v2,
    royaltyBps: v3,
    scoreBps,
    severity,
    digestHex,
  };
}
