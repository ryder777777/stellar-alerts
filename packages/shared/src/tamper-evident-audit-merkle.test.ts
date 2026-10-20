import { describe, it, expect } from 'vitest';
import { buildAuditLogMerkleSummary } from './tamper-evident-audit-merkle.js';

describe('buildAuditLogMerkleSummary', () => {
  it('computes normal severity and deterministic sha256 digest within nominal bounds', () => {
    const res = buildAuditLogMerkleSummary({
      targetId: 'stellar-alert-01',
      logEntryCount: 120,
      epochSequence: 80,
      unanchoredEntries: 25,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('normal');
    expect(res.scoreBps).toBe(2000);
    expect(res.digestHex).toHaveLength(64);
  });

  it('escalates to critical when metrics breach thresholdLimit', () => {
    const res = buildAuditLogMerkleSummary({
      targetId: 'stellar-alert-02',
      logEntryCount: 650,
      epochSequence: 300,
      unanchoredEntries: 1500,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('critical');
    expect(res.scoreBps).toBe(9500);
  });

  it('throws on blank targetId', () => {
    expect(() =>
      buildAuditLogMerkleSummary({
        targetId: '   ',
        logEntryCount: 1,
        epochSequence: 2,
        unanchoredEntries: 3,
      }),
    ).toThrow(/targetId must not be empty/);
  });
});
