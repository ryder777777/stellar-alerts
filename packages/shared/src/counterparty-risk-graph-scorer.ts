import { createHash } from 'node:crypto';

export interface CounterpartyRiskClusterInput {
  targetId: string;
  hopCount: number;
  flaggedNeighborCount: number;
  volumeStroops: number;
  thresholdLimit?: number;
}

export interface CounterpartyRiskCluster {
  targetId: string;
  hopCount: number;
  flaggedNeighborCount: number;
  volumeStroops: number;
  scoreBps: number;
  severity: 'normal' | 'elevated' | 'critical';
  digestHex: string;
}

export function scoreMultiHopCounterpartyRisk(input: CounterpartyRiskClusterInput): CounterpartyRiskCluster {
  const targetId = input.targetId.trim();
  if (!targetId) {
    throw new Error('scoreMultiHopCounterpartyRisk: targetId must not be empty');
  }
  if (
    !Number.isFinite(input.hopCount) ||
    !Number.isFinite(input.flaggedNeighborCount) ||
    !Number.isFinite(input.volumeStroops)
  ) {
    throw new Error('scoreMultiHopCounterpartyRisk: numeric metrics must be finite');
  }

  const v1 = Math.max(0, Math.trunc(input.hopCount));
  const v2 = Math.max(0, Math.trunc(input.flaggedNeighborCount));
  const v3 = Math.max(0, Math.trunc(input.volumeStroops));
  const limit = Math.max(1, Math.trunc(input.thresholdLimit ?? 1000));

  const scoreBps = Math.min(10000, Math.round(((v1 + v2) * 10000) / limit));
  let severity: 'normal' | 'elevated' | 'critical' = 'normal';
  if (v3 > limit || scoreBps >= 8500) {
    severity = 'critical';
  } else if (scoreBps >= 4500) {
    severity = 'elevated';
  }

  const payload = JSON.stringify({ targetId, hopCount: v1, flaggedNeighborCount: v2, volumeStroops: v3, scoreBps, severity });
  const digestHex = createHash('sha256').update(payload).digest('hex');

  return {
    targetId,
    hopCount: v1,
    flaggedNeighborCount: v2,
    volumeStroops: v3,
    scoreBps,
    severity,
    digestHex,
  };
}
