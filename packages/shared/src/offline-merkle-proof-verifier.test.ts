import { describe, it, expect } from 'vitest';
import { verifyOfflineMerkleInclusionBatch } from './offline-merkle-proof-verifier.js';

describe('verifyOfflineMerkleInclusionBatch', () => {
  it('computes normal severity and deterministic sha256 digest within nominal bounds', () => {
    const res = verifyOfflineMerkleInclusionBatch({
      targetId: 'stellar-alert-01',
      proofSiblingCount: 120,
      leafIndex: 80,
      treeHeight: 25,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('normal');
    expect(res.scoreBps).toBe(2000);
    expect(res.digestHex).toHaveLength(64);
  });

  it('escalates to critical when metrics breach thresholdLimit', () => {
    const res = verifyOfflineMerkleInclusionBatch({
      targetId: 'stellar-alert-02',
      proofSiblingCount: 650,
      leafIndex: 300,
      treeHeight: 1500,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('critical');
    expect(res.scoreBps).toBe(9500);
  });

  it('throws on blank targetId', () => {
    expect(() =>
      verifyOfflineMerkleInclusionBatch({
        targetId: '   ',
        proofSiblingCount: 1,
        leafIndex: 2,
        treeHeight: 3,
      }),
    ).toThrow(/targetId must not be empty/);
  });
});
