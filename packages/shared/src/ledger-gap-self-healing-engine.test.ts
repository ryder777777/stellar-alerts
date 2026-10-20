import { describe, it, expect } from 'vitest';
import { planParallelLedgerMicroBackfill } from './ledger-gap-self-healing-engine.js';

describe('planParallelLedgerMicroBackfill', () => {
  it('computes normal severity and deterministic sha256 digest within nominal bounds', () => {
    const res = planParallelLedgerMicroBackfill({
      targetId: 'stellar-alert-01',
      missingLedgerCount: 120,
      workerConcurrency: 80,
      maxChunkSize: 25,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('normal');
    expect(res.scoreBps).toBe(2000);
    expect(res.digestHex).toHaveLength(64);
  });

  it('escalates to critical when metrics breach thresholdLimit', () => {
    const res = planParallelLedgerMicroBackfill({
      targetId: 'stellar-alert-02',
      missingLedgerCount: 650,
      workerConcurrency: 300,
      maxChunkSize: 1500,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('critical');
    expect(res.scoreBps).toBe(9500);
  });

  it('throws on blank targetId', () => {
    expect(() =>
      planParallelLedgerMicroBackfill({
        targetId: '   ',
        missingLedgerCount: 1,
        workerConcurrency: 2,
        maxChunkSize: 3,
      }),
    ).toThrow(/targetId must not be empty/);
  });
});
