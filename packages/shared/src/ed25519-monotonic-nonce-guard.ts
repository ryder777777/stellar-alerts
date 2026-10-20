import { createHash } from 'node:crypto';

export interface MonotonicNonceVerdictInput {
  targetId: string;
  incomingNonce: number;
  lastRecordedNonce: number;
  timestampDriftSecs: number;
  thresholdLimit?: number;
}

export interface MonotonicNonceVerdict {
  targetId: string;
  incomingNonce: number;
  lastRecordedNonce: number;
  timestampDriftSecs: number;
  scoreBps: number;
  severity: 'normal' | 'elevated' | 'critical';
  digestHex: string;
}

export function verifyEd25519MonotonicNonce(input: MonotonicNonceVerdictInput): MonotonicNonceVerdict {
  const targetId = input.targetId.trim();
  if (!targetId) {
    throw new Error('verifyEd25519MonotonicNonce: targetId must not be empty');
  }
  if (
    !Number.isFinite(input.incomingNonce) ||
    !Number.isFinite(input.lastRecordedNonce) ||
    !Number.isFinite(input.timestampDriftSecs)
  ) {
    throw new Error('verifyEd25519MonotonicNonce: numeric metrics must be finite');
  }

  const v1 = Math.max(0, Math.trunc(input.incomingNonce));
  const v2 = Math.max(0, Math.trunc(input.lastRecordedNonce));
  const v3 = Math.max(0, Math.trunc(input.timestampDriftSecs));
  const limit = Math.max(1, Math.trunc(input.thresholdLimit ?? 1000));

  const scoreBps = Math.min(10000, Math.round(((v1 + v2) * 10000) / limit));
  let severity: 'normal' | 'elevated' | 'critical' = 'normal';
  if (v3 > limit || scoreBps >= 8500) {
    severity = 'critical';
  } else if (scoreBps >= 4500) {
    severity = 'elevated';
  }

  const payload = JSON.stringify({ targetId, incomingNonce: v1, lastRecordedNonce: v2, timestampDriftSecs: v3, scoreBps, severity });
  const digestHex = createHash('sha256').update(payload).digest('hex');

  return {
    targetId,
    incomingNonce: v1,
    lastRecordedNonce: v2,
    timestampDriftSecs: v3,
    scoreBps,
    severity,
    digestHex,
  };
}
