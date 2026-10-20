import { createHash } from 'node:crypto';

export interface ParticleStreamFrameBudgetInput {
  targetId: string;
  paymentsPerSec: number;
  activeParticles: number;
  targetFps: number;
  thresholdLimit?: number;
}

export interface ParticleStreamFrameBudget {
  targetId: string;
  paymentsPerSec: number;
  activeParticles: number;
  targetFps: number;
  scoreBps: number;
  severity: 'normal' | 'elevated' | 'critical';
  digestHex: string;
}

export function computeWebGlPaymentParticleBudget(input: ParticleStreamFrameBudgetInput): ParticleStreamFrameBudget {
  const targetId = input.targetId.trim();
  if (!targetId) {
    throw new Error('computeWebGlPaymentParticleBudget: targetId must not be empty');
  }
  if (
    !Number.isFinite(input.paymentsPerSec) ||
    !Number.isFinite(input.activeParticles) ||
    !Number.isFinite(input.targetFps)
  ) {
    throw new Error('computeWebGlPaymentParticleBudget: numeric metrics must be finite');
  }

  const v1 = Math.max(0, Math.trunc(input.paymentsPerSec));
  const v2 = Math.max(0, Math.trunc(input.activeParticles));
  const v3 = Math.max(0, Math.trunc(input.targetFps));
  const limit = Math.max(1, Math.trunc(input.thresholdLimit ?? 1000));

  const scoreBps = Math.min(10000, Math.round(((v1 + v2) * 10000) / limit));
  let severity: 'normal' | 'elevated' | 'critical' = 'normal';
  if (v3 > limit || scoreBps >= 8500) {
    severity = 'critical';
  } else if (scoreBps >= 4500) {
    severity = 'elevated';
  }

  const payload = JSON.stringify({ targetId, paymentsPerSec: v1, activeParticles: v2, targetFps: v3, scoreBps, severity });
  const digestHex = createHash('sha256').update(payload).digest('hex');

  return {
    targetId,
    paymentsPerSec: v1,
    activeParticles: v2,
    targetFps: v3,
    scoreBps,
    severity,
    digestHex,
  };
}
