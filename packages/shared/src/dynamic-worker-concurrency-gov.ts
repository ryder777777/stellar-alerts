import { createHash } from 'node:crypto';

export interface WorkerConcurrencyDecisionInput {
  targetId: string;
  redisQueueLag: number;
  activeWorkers: number;
  cpuUtilizationBps: number;
  thresholdLimit?: number;
}

export interface WorkerConcurrencyDecision {
  targetId: string;
  redisQueueLag: number;
  activeWorkers: number;
  cpuUtilizationBps: number;
  scoreBps: number;
  severity: 'normal' | 'elevated' | 'critical';
  digestHex: string;
}

export function governDynamicWorkerConcurrency(input: WorkerConcurrencyDecisionInput): WorkerConcurrencyDecision {
  const targetId = input.targetId.trim();
  if (!targetId) {
    throw new Error('governDynamicWorkerConcurrency: targetId must not be empty');
  }
  if (
    !Number.isFinite(input.redisQueueLag) ||
    !Number.isFinite(input.activeWorkers) ||
    !Number.isFinite(input.cpuUtilizationBps)
  ) {
    throw new Error('governDynamicWorkerConcurrency: numeric metrics must be finite');
  }

  const v1 = Math.max(0, Math.trunc(input.redisQueueLag));
  const v2 = Math.max(0, Math.trunc(input.activeWorkers));
  const v3 = Math.max(0, Math.trunc(input.cpuUtilizationBps));
  const limit = Math.max(1, Math.trunc(input.thresholdLimit ?? 1000));

  const scoreBps = Math.min(10000, Math.round(((v1 + v2) * 10000) / limit));
  let severity: 'normal' | 'elevated' | 'critical' = 'normal';
  if (v3 > limit || scoreBps >= 8500) {
    severity = 'critical';
  } else if (scoreBps >= 4500) {
    severity = 'elevated';
  }

  const payload = JSON.stringify({ targetId, redisQueueLag: v1, activeWorkers: v2, cpuUtilizationBps: v3, scoreBps, severity });
  const digestHex = createHash('sha256').update(payload).digest('hex');

  return {
    targetId,
    redisQueueLag: v1,
    activeWorkers: v2,
    cpuUtilizationBps: v3,
    scoreBps,
    severity,
    digestHex,
  };
}
