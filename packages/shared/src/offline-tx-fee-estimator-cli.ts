import { createHash } from 'node:crypto';

export interface OfflineFeeEstimationReportInput {
  targetId: string;
  operationCount: number;
  footprintBytes: number;
  inclusionFeeStroops: number;
  thresholdLimit?: number;
}

export interface OfflineFeeEstimationReport {
  targetId: string;
  operationCount: number;
  footprintBytes: number;
  inclusionFeeStroops: number;
  scoreBps: number;
  severity: 'normal' | 'elevated' | 'critical';
  digestHex: string;
}

export function estimateOfflineSorobanTxResources(input: OfflineFeeEstimationReportInput): OfflineFeeEstimationReport {
  const targetId = input.targetId.trim();
  if (!targetId) {
    throw new Error('estimateOfflineSorobanTxResources: targetId must not be empty');
  }
  if (
    !Number.isFinite(input.operationCount) ||
    !Number.isFinite(input.footprintBytes) ||
    !Number.isFinite(input.inclusionFeeStroops)
  ) {
    throw new Error('estimateOfflineSorobanTxResources: numeric metrics must be finite');
  }

  const v1 = Math.max(0, Math.trunc(input.operationCount));
  const v2 = Math.max(0, Math.trunc(input.footprintBytes));
  const v3 = Math.max(0, Math.trunc(input.inclusionFeeStroops));
  const limit = Math.max(1, Math.trunc(input.thresholdLimit ?? 1000));

  const scoreBps = Math.min(10000, Math.round(((v1 + v2) * 10000) / limit));
  let severity: 'normal' | 'elevated' | 'critical' = 'normal';
  if (v3 > limit || scoreBps >= 8500) {
    severity = 'critical';
  } else if (scoreBps >= 4500) {
    severity = 'elevated';
  }

  const payload = JSON.stringify({ targetId, operationCount: v1, footprintBytes: v2, inclusionFeeStroops: v3, scoreBps, severity });
  const digestHex = createHash('sha256').update(payload).digest('hex');

  return {
    targetId,
    operationCount: v1,
    footprintBytes: v2,
    inclusionFeeStroops: v3,
    scoreBps,
    severity,
    digestHex,
  };
}
