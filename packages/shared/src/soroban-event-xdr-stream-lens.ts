import { createHash } from 'node:crypto';

export interface SorobanEventStreamDigestInput {
  targetId: string;
  decodedEventCount: number;
  contractTopicCount: number;
  malformedXdrCount: number;
  thresholdLimit?: number;
}

export interface SorobanEventStreamDigest {
  targetId: string;
  decodedEventCount: number;
  contractTopicCount: number;
  malformedXdrCount: number;
  scoreBps: number;
  severity: 'normal' | 'elevated' | 'critical';
  digestHex: string;
}

export function summarizeSorobanEventXdrStream(input: SorobanEventStreamDigestInput): SorobanEventStreamDigest {
  const targetId = input.targetId.trim();
  if (!targetId) {
    throw new Error('summarizeSorobanEventXdrStream: targetId must not be empty');
  }
  if (
    !Number.isFinite(input.decodedEventCount) ||
    !Number.isFinite(input.contractTopicCount) ||
    !Number.isFinite(input.malformedXdrCount)
  ) {
    throw new Error('summarizeSorobanEventXdrStream: numeric metrics must be finite');
  }

  const v1 = Math.max(0, Math.trunc(input.decodedEventCount));
  const v2 = Math.max(0, Math.trunc(input.contractTopicCount));
  const v3 = Math.max(0, Math.trunc(input.malformedXdrCount));
  const limit = Math.max(1, Math.trunc(input.thresholdLimit ?? 1000));

  const scoreBps = Math.min(10000, Math.round(((v1 + v2) * 10000) / limit));
  let severity: 'normal' | 'elevated' | 'critical' = 'normal';
  if (v3 > limit || scoreBps >= 8500) {
    severity = 'critical';
  } else if (scoreBps >= 4500) {
    severity = 'elevated';
  }

  const payload = JSON.stringify({ targetId, decodedEventCount: v1, contractTopicCount: v2, malformedXdrCount: v3, scoreBps, severity });
  const digestHex = createHash('sha256').update(payload).digest('hex');

  return {
    targetId,
    decodedEventCount: v1,
    contractTopicCount: v2,
    malformedXdrCount: v3,
    scoreBps,
    severity,
    digestHex,
  };
}
