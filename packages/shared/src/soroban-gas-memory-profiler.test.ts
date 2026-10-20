import { describe, it, expect } from 'vitest';
import { profileSorobanGasAndMemoryUsage } from './soroban-gas-memory-profiler.js';

describe('profileSorobanGasAndMemoryUsage', () => {
  it('computes normal severity and deterministic sha256 digest within nominal bounds', () => {
    const res = profileSorobanGasAndMemoryUsage({
      targetId: 'stellar-alert-01',
      cpuInstructions: 120,
      memoryBytes: 80,
      ledgerLimitBps: 25,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('normal');
    expect(res.scoreBps).toBe(2000);
    expect(res.digestHex).toHaveLength(64);
  });

  it('escalates to critical when metrics breach thresholdLimit', () => {
    const res = profileSorobanGasAndMemoryUsage({
      targetId: 'stellar-alert-02',
      cpuInstructions: 650,
      memoryBytes: 300,
      ledgerLimitBps: 1500,
      thresholdLimit: 1000,
    });
    expect(res.severity).toBe('critical');
    expect(res.scoreBps).toBe(9500);
  });

  it('throws on blank targetId', () => {
    expect(() =>
      profileSorobanGasAndMemoryUsage({
        targetId: '   ',
        cpuInstructions: 1,
        memoryBytes: 2,
        ledgerLimitBps: 3,
      }),
    ).toThrow(/targetId must not be empty/);
  });
});
