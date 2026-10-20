import { createHash } from 'node:crypto';

export interface TamperEvidentAuditProofInput {
  targetId: string;
  logEntryCount: number;
  epochSequence: number;
  unanchoredEntries: number;
  thresholdLimit?: number;
}

export interface TamperEvidentAuditProof {
  targetId: string;
  logEntryCount: number;
  epochSequence: number;
  unanchoredEntries: number;
  scoreBps: number;
  severity: 'normal' | 'elevated' | 'critical';
  digestHex: string;
}

export function buildAuditLogMerkleSummary(input: TamperEvidentAuditProofInput): TamperEvidentAuditProof {
  const targetId = input.targetId.trim();
  if (!targetId) {
    throw new Error('buildAuditLogMerkleSummary: targetId must not be empty');
  }
  if (
    !Number.isFinite(input.logEntryCount) ||
    !Number.isFinite(input.epochSequence) ||
    !Number.isFinite(input.unanchoredEntries)
  ) {
    throw new Error('buildAuditLogMerkleSummary: numeric metrics must be finite');
  }

  const v1 = Math.max(0, Math.trunc(input.logEntryCount));
  const v2 = Math.max(0, Math.trunc(input.epochSequence));
  const v3 = Math.max(0, Math.trunc(input.unanchoredEntries));
  const limit = Math.max(1, Math.trunc(input.thresholdLimit ?? 1000));

  const scoreBps = Math.min(10000, Math.round(((v1 + v2) * 10000) / limit));
  let severity: 'normal' | 'elevated' | 'critical' = 'normal';
  if (v3 > limit || scoreBps >= 8500) {
    severity = 'critical';
  } else if (scoreBps >= 4500) {
    severity = 'elevated';
  }

  const payload = JSON.stringify({ targetId, logEntryCount: v1, epochSequence: v2, unanchoredEntries: v3, scoreBps, severity });
  const digestHex = createHash('sha256').update(payload).digest('hex');

  return {
    targetId,
    logEntryCount: v1,
    epochSequence: v2,
    unanchoredEntries: v3,
    scoreBps,
    severity,
    digestHex,
  };
}
