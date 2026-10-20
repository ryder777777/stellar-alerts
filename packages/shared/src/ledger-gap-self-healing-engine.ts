import { createHash } from 'node:crypto';

export interface LedgerGapHealPlanInput {
  targetId: string;
  missingLedgerCount: number;
  workerConcurrency: number;
  maxChunkSize: number;
  thresholdLimit?: number;
}

export interface LedgerGapHealPlan {
  targetId: string;
  missingLedgerCount: number;
  workerConcurrency: number;
  maxChunkSize: number;
  scoreBps: number;
  severity: 'normal' | 'elevated' | 'critical';
  digestHex: string;
}

export function planParallelLedgerMicroBackfill(input: LedgerGapHealPlanInput): LedgerGapHealPlan {
  const targetId = input.targetId.trim();
  if (!targetId) {
    throw new Error('planParallelLedgerMicroBackfill: targetId must not be empty');
  }
  if (
    !Number.isFinite(input.missingLedgerCount) ||
    !Number.isFinite(input.workerConcurrency) ||
    !Number.isFinite(input.maxChunkSize)
  ) {
    throw new Error('planParallelLedgerMicroBackfill: numeric metrics must be finite');
  }

  const v1 = Math.max(0, Math.trunc(input.missingLedgerCount));
  const v2 = Math.max(0, Math.trunc(input.workerConcurrency));
  const v3 = Math.max(0, Math.trunc(input.maxChunkSize));
  const limit = Math.max(1, Math.trunc(input.thresholdLimit ?? 1000));

  const scoreBps = Math.min(10000, Math.round(((v1 + v2) * 10000) / limit));
  let severity: 'normal' | 'elevated' | 'critical' = 'normal';
  if (v3 > limit || scoreBps >= 8500) {
    severity = 'critical';
  } else if (scoreBps >= 4500) {
    severity = 'elevated';
  }

  const payload = JSON.stringify({ targetId, missingLedgerCount: v1, workerConcurrency: v2, maxChunkSize: v3, scoreBps, severity });
  const digestHex = createHash('sha256').update(payload).digest('hex');

  return {
    targetId,
    missingLedgerCount: v1,
    workerConcurrency: v2,
    maxChunkSize: v3,
    scoreBps,
    severity,
    digestHex,
  };
}
