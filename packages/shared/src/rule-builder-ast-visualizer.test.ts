import { describe, it, expect } from 'vitest';
import { buildRuleAstVisualization } from './rule-builder-ast-visualizer.js';

describe('buildRuleAstVisualization', () => {
  it('computes normal severity and deterministic sha256 digest within nominal bounds', () => {
    const res = buildRuleAstVisualization({
      targetId: 'stellar-alert-01',
      nodeCount: 120,
      maxDepth: 80,
      branchCount: 25,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('normal');
    expect(res.scoreBps).toBe(2000);
    expect(res.digestHex).toHaveLength(64);
  });

  it('escalates to critical when metrics breach thresholdLimit', () => {
    const res = buildRuleAstVisualization({
      targetId: 'stellar-alert-02',
      nodeCount: 650,
      maxDepth: 300,
      branchCount: 1500,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('critical');
    expect(res.scoreBps).toBe(9500);
  });

  it('throws on blank targetId', () => {
    expect(() =>
      buildRuleAstVisualization({
        targetId: '   ',
        nodeCount: 1,
        maxDepth: 2,
        branchCount: 3,
      }),
    ).toThrow(/targetId must not be empty/);
  });
});
