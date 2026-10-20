import { createHash } from 'node:crypto';

export interface RuleAstVisualGraphInput {
  targetId: string;
  nodeCount: number;
  maxDepth: number;
  branchCount: number;
  thresholdLimit?: number;
}

export interface RuleAstVisualGraph {
  targetId: string;
  nodeCount: number;
  maxDepth: number;
  branchCount: number;
  scoreBps: number;
  severity: 'normal' | 'elevated' | 'critical';
  digestHex: string;
}

export function buildRuleAstVisualization(input: RuleAstVisualGraphInput): RuleAstVisualGraph {
  const targetId = input.targetId.trim();
  if (!targetId) {
    throw new Error('buildRuleAstVisualization: targetId must not be empty');
  }
  if (
    !Number.isFinite(input.nodeCount) ||
    !Number.isFinite(input.maxDepth) ||
    !Number.isFinite(input.branchCount)
  ) {
    throw new Error('buildRuleAstVisualization: numeric metrics must be finite');
  }

  const v1 = Math.max(0, Math.trunc(input.nodeCount));
  const v2 = Math.max(0, Math.trunc(input.maxDepth));
  const v3 = Math.max(0, Math.trunc(input.branchCount));
  const limit = Math.max(1, Math.trunc(input.thresholdLimit ?? 1000));

  const scoreBps = Math.min(10000, Math.round(((v1 + v2) * 10000) / limit));
  let severity: 'normal' | 'elevated' | 'critical' = 'normal';
  if (v3 > limit || scoreBps >= 8500) {
    severity = 'critical';
  } else if (scoreBps >= 4500) {
    severity = 'elevated';
  }

  const payload = JSON.stringify({ targetId, nodeCount: v1, maxDepth: v2, branchCount: v3, scoreBps, severity });
  const digestHex = createHash('sha256').update(payload).digest('hex');

  return {
    targetId,
    nodeCount: v1,
    maxDepth: v2,
    branchCount: v3,
    scoreBps,
    severity,
    digestHex,
  };
}
