import { createHash } from 'node:crypto';

export interface ReconnectBackoffScheduleInput {
  targetId: string;
  disconnectAttempt: number;
  baseDelayMs: number;
  jitterSeed: number;
  thresholdLimit?: number;
}

export interface ReconnectBackoffSchedule {
  targetId: string;
  disconnectAttempt: number;
  baseDelayMs: number;
  jitterSeed: number;
  scoreBps: number;
  severity: 'normal' | 'elevated' | 'critical';
  digestHex: string;
}

export function computeAdaptiveLedgerReconnectJitter(input: ReconnectBackoffScheduleInput): ReconnectBackoffSchedule {
  const targetId = input.targetId.trim();
  if (!targetId) {
    throw new Error('computeAdaptiveLedgerReconnectJitter: targetId must not be empty');
  }
  if (
    !Number.isFinite(input.disconnectAttempt) ||
    !Number.isFinite(input.baseDelayMs) ||
    !Number.isFinite(input.jitterSeed)
  ) {
    throw new Error('computeAdaptiveLedgerReconnectJitter: numeric metrics must be finite');
  }

  const v1 = Math.max(0, Math.trunc(input.disconnectAttempt));
  const v2 = Math.max(0, Math.trunc(input.baseDelayMs));
  const v3 = Math.max(0, Math.trunc(input.jitterSeed));
  const limit = Math.max(1, Math.trunc(input.thresholdLimit ?? 1000));

  const scoreBps = Math.min(10000, Math.round(((v1 + v2) * 10000) / limit));
  let severity: 'normal' | 'elevated' | 'critical' = 'normal';
  if (v3 > limit || scoreBps >= 8500) {
    severity = 'critical';
  } else if (scoreBps >= 4500) {
    severity = 'elevated';
  }

  const payload = JSON.stringify({ targetId, disconnectAttempt: v1, baseDelayMs: v2, jitterSeed: v3, scoreBps, severity });
  const digestHex = createHash('sha256').update(payload).digest('hex');

  return {
    targetId,
    disconnectAttempt: v1,
    baseDelayMs: v2,
    jitterSeed: v3,
    scoreBps,
    severity,
    digestHex,
  };
}
