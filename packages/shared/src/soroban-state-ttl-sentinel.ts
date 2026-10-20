import { createHash } from 'node:crypto';

export interface SorobanStateTtlAlertInput {
  targetId: string;
  currentLedger: number;
  liveUntilLedger: number;
  warningWindowLedgers: number;
  thresholdLimit?: number;
}

export interface SorobanStateTtlAlert {
  targetId: string;
  currentLedger: number;
  liveUntilLedger: number;
  warningWindowLedgers: number;
  scoreBps: number;
  severity: 'normal' | 'elevated' | 'critical';
  digestHex: string;
}

export function evaluateSorobanStateTtlExpiration(input: SorobanStateTtlAlertInput): SorobanStateTtlAlert {
  const targetId = input.targetId.trim();
  if (!targetId) {
    throw new Error('evaluateSorobanStateTtlExpiration: targetId must not be empty');
  }
  if (
    !Number.isFinite(input.currentLedger) ||
    !Number.isFinite(input.liveUntilLedger) ||
    !Number.isFinite(input.warningWindowLedgers)
  ) {
    throw new Error('evaluateSorobanStateTtlExpiration: numeric metrics must be finite');
  }

  const v1 = Math.max(0, Math.trunc(input.currentLedger));
  const v2 = Math.max(0, Math.trunc(input.liveUntilLedger));
  const v3 = Math.max(0, Math.trunc(input.warningWindowLedgers));
  const limit = Math.max(1, Math.trunc(input.thresholdLimit ?? 1000));

  const scoreBps = Math.min(10000, Math.round(((v1 + v2) * 10000) / limit));
  let severity: 'normal' | 'elevated' | 'critical' = 'normal';
  if (v3 > limit || scoreBps >= 8500) {
    severity = 'critical';
  } else if (scoreBps >= 4500) {
    severity = 'elevated';
  }

  const payload = JSON.stringify({ targetId, currentLedger: v1, liveUntilLedger: v2, warningWindowLedgers: v3, scoreBps, severity });
  const digestHex = createHash('sha256').update(payload).digest('hex');

  return {
    targetId,
    currentLedger: v1,
    liveUntilLedger: v2,
    warningWindowLedgers: v3,
    scoreBps,
    severity,
    digestHex,
  };
}
