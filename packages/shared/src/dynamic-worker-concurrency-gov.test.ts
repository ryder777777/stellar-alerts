import { describe, it, expect } from 'vitest';
import { governDynamicWorkerConcurrency } from './dynamic-worker-concurrency-gov.js';

describe('governDynamicWorkerConcurrency', () => {
  it('computes normal severity and deterministic sha256 digest within nominal bounds', () => {
    const res = governDynamicWorkerConcurrency({
      targetId: 'stellar-alert-01',
      redisQueueLag: 120,
      activeWorkers: 80,
      cpuUtilizationBps: 25,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('normal');
    expect(res.scoreBps).toBe(2000);
    expect(res.digestHex).toHaveLength(64);
  });

  it('escalates to critical when metrics breach thresholdLimit', () => {
    const res = governDynamicWorkerConcurrency({
      targetId: 'stellar-alert-02',
      redisQueueLag: 650,
      activeWorkers: 300,
      cpuUtilizationBps: 1500,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('critical');
    expect(res.scoreBps).toBe(9500);
  });

  it('throws on blank targetId', () => {
    expect(() =>
      governDynamicWorkerConcurrency({
        targetId: '   ',
        redisQueueLag: 1,
        activeWorkers: 2,
        cpuUtilizationBps: 3,
      }),
    ).toThrow(/targetId must not be empty/);
  });
});
