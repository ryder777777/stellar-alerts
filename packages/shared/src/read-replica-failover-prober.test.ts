import { describe, it, expect } from 'vitest';
import { probeReadReplicaFailoverHealth } from './read-replica-failover-prober.js';

describe('probeReadReplicaFailoverHealth', () => {
  it('computes normal severity and deterministic sha256 digest within nominal bounds', () => {
    const res = probeReadReplicaFailoverHealth({
      targetId: 'stellar-alert-01',
      replicationLagMs: 120,
      consecutiveProbeFailures: 80,
      healthyReplicaCount: 25,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('normal');
    expect(res.scoreBps).toBe(2000);
    expect(res.digestHex).toHaveLength(64);
  });

  it('escalates to critical when metrics breach thresholdLimit', () => {
    const res = probeReadReplicaFailoverHealth({
      targetId: 'stellar-alert-02',
      replicationLagMs: 650,
      consecutiveProbeFailures: 300,
      healthyReplicaCount: 1500,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('critical');
    expect(res.scoreBps).toBe(9500);
  });

  it('throws on blank targetId', () => {
    expect(() =>
      probeReadReplicaFailoverHealth({
        targetId: '   ',
        replicationLagMs: 1,
        consecutiveProbeFailures: 2,
        healthyReplicaCount: 3,
      }),
    ).toThrow(/targetId must not be empty/);
  });
});
