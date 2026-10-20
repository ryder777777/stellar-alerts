import { createHash } from 'node:crypto';

export interface ReplicaFailoverDecisionInput {
  targetId: string;
  replicationLagMs: number;
  consecutiveProbeFailures: number;
  healthyReplicaCount: number;
  thresholdLimit?: number;
}

export interface ReplicaFailoverDecision {
  targetId: string;
  replicationLagMs: number;
  consecutiveProbeFailures: number;
  healthyReplicaCount: number;
  scoreBps: number;
  severity: 'normal' | 'elevated' | 'critical';
  digestHex: string;
}

export function probeReadReplicaFailoverHealth(input: ReplicaFailoverDecisionInput): ReplicaFailoverDecision {
  const targetId = input.targetId.trim();
  if (!targetId) {
    throw new Error('probeReadReplicaFailoverHealth: targetId must not be empty');
  }
  if (
    !Number.isFinite(input.replicationLagMs) ||
    !Number.isFinite(input.consecutiveProbeFailures) ||
    !Number.isFinite(input.healthyReplicaCount)
  ) {
    throw new Error('probeReadReplicaFailoverHealth: numeric metrics must be finite');
  }

  const v1 = Math.max(0, Math.trunc(input.replicationLagMs));
  const v2 = Math.max(0, Math.trunc(input.consecutiveProbeFailures));
  const v3 = Math.max(0, Math.trunc(input.healthyReplicaCount));
  const limit = Math.max(1, Math.trunc(input.thresholdLimit ?? 1000));

  const scoreBps = Math.min(10000, Math.round(((v1 + v2) * 10000) / limit));
  let severity: 'normal' | 'elevated' | 'critical' = 'normal';
  if (v3 > limit || scoreBps >= 8500) {
    severity = 'critical';
  } else if (scoreBps >= 4500) {
    severity = 'elevated';
  }

  const payload = JSON.stringify({ targetId, replicationLagMs: v1, consecutiveProbeFailures: v2, healthyReplicaCount: v3, scoreBps, severity });
  const digestHex = createHash('sha256').update(payload).digest('hex');

  return {
    targetId,
    replicationLagMs: v1,
    consecutiveProbeFailures: v2,
    healthyReplicaCount: v3,
    scoreBps,
    severity,
    digestHex,
  };
}
