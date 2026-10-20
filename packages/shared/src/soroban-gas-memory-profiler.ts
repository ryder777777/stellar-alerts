import { createHash } from 'node:crypto';

export interface SorobanResourceProfileInput {
  targetId: string;
  cpuInstructions: number;
  memoryBytes: number;
  ledgerLimitBps: number;
  thresholdLimit?: number;
}

export interface SorobanResourceProfile {
  targetId: string;
  cpuInstructions: number;
  memoryBytes: number;
  ledgerLimitBps: number;
  scoreBps: number;
  severity: 'normal' | 'elevated' | 'critical';
  digestHex: string;
}

export function profileSorobanGasAndMemoryUsage(input: SorobanResourceProfileInput): SorobanResourceProfile {
  const targetId = input.targetId.trim();
  if (!targetId) {
    throw new Error('profileSorobanGasAndMemoryUsage: targetId must not be empty');
  }
  if (
    !Number.isFinite(input.cpuInstructions) ||
    !Number.isFinite(input.memoryBytes) ||
    !Number.isFinite(input.ledgerLimitBps)
  ) {
    throw new Error('profileSorobanGasAndMemoryUsage: numeric metrics must be finite');
  }

  const v1 = Math.max(0, Math.trunc(input.cpuInstructions));
  const v2 = Math.max(0, Math.trunc(input.memoryBytes));
  const v3 = Math.max(0, Math.trunc(input.ledgerLimitBps));
  const limit = Math.max(1, Math.trunc(input.thresholdLimit ?? 1000));

  const scoreBps = Math.min(10000, Math.round(((v1 + v2) * 10000) / limit));
  let severity: 'normal' | 'elevated' | 'critical' = 'normal';
  if (v3 > limit || scoreBps >= 8500) {
    severity = 'critical';
  } else if (scoreBps >= 4500) {
    severity = 'elevated';
  }

  const payload = JSON.stringify({ targetId, cpuInstructions: v1, memoryBytes: v2, ledgerLimitBps: v3, scoreBps, severity });
  const digestHex = createHash('sha256').update(payload).digest('hex');

  return {
    targetId,
    cpuInstructions: v1,
    memoryBytes: v2,
    ledgerLimitBps: v3,
    scoreBps,
    severity,
    digestHex,
  };
}
