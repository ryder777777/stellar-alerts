import { createHash } from 'node:crypto';

export interface ApiKeyRbacVerdictInput {
  targetId: string;
  grantedBitmask: number;
  requiredBitmask: number;
  scopeRestrictionCount: number;
  thresholdLimit?: number;
}

export interface ApiKeyRbacVerdict {
  targetId: string;
  grantedBitmask: number;
  requiredBitmask: number;
  scopeRestrictionCount: number;
  scoreBps: number;
  severity: 'normal' | 'elevated' | 'critical';
  digestHex: string;
}

export function evaluateGranularBitmaskRbac(input: ApiKeyRbacVerdictInput): ApiKeyRbacVerdict {
  const targetId = input.targetId.trim();
  if (!targetId) {
    throw new Error('evaluateGranularBitmaskRbac: targetId must not be empty');
  }
  if (
    !Number.isFinite(input.grantedBitmask) ||
    !Number.isFinite(input.requiredBitmask) ||
    !Number.isFinite(input.scopeRestrictionCount)
  ) {
    throw new Error('evaluateGranularBitmaskRbac: numeric metrics must be finite');
  }

  const v1 = Math.max(0, Math.trunc(input.grantedBitmask));
  const v2 = Math.max(0, Math.trunc(input.requiredBitmask));
  const v3 = Math.max(0, Math.trunc(input.scopeRestrictionCount));
  const limit = Math.max(1, Math.trunc(input.thresholdLimit ?? 1000));

  const scoreBps = Math.min(10000, Math.round(((v1 + v2) * 10000) / limit));
  let severity: 'normal' | 'elevated' | 'critical' = 'normal';
  if (v3 > limit || scoreBps >= 8500) {
    severity = 'critical';
  } else if (scoreBps >= 4500) {
    severity = 'elevated';
  }

  const payload = JSON.stringify({ targetId, grantedBitmask: v1, requiredBitmask: v2, scopeRestrictionCount: v3, scoreBps, severity });
  const digestHex = createHash('sha256').update(payload).digest('hex');

  return {
    targetId,
    grantedBitmask: v1,
    requiredBitmask: v2,
    scopeRestrictionCount: v3,
    scoreBps,
    severity,
    digestHex,
  };
}
