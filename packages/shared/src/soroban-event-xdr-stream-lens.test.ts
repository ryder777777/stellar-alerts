import { describe, it, expect } from 'vitest';
import { summarizeSorobanEventXdrStream } from './soroban-event-xdr-stream-lens.js';

describe('summarizeSorobanEventXdrStream', () => {
  it('computes normal severity and deterministic sha256 digest within nominal bounds', () => {
    const res = summarizeSorobanEventXdrStream({
      targetId: 'stellar-alert-01',
      decodedEventCount: 120,
      contractTopicCount: 80,
      malformedXdrCount: 25,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('normal');
    expect(res.scoreBps).toBe(2000);
    expect(res.digestHex).toHaveLength(64);
  });

  it('escalates to critical when metrics breach thresholdLimit', () => {
    const res = summarizeSorobanEventXdrStream({
      targetId: 'stellar-alert-02',
      decodedEventCount: 650,
      contractTopicCount: 300,
      malformedXdrCount: 1500,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('critical');
    expect(res.scoreBps).toBe(9500);
  });

  it('throws on blank targetId', () => {
    expect(() =>
      summarizeSorobanEventXdrStream({
        targetId: '   ',
        decodedEventCount: 1,
        contractTopicCount: 2,
        malformedXdrCount: 3,
      }),
    ).toThrow(/targetId must not be empty/);
  });
});
