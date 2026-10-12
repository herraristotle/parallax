import { describe, it, expect, vi } from 'vitest';
import { ParallaxPipeline } from '../pipeline';

describe('ParallaxPipeline', () => {
  it('should construct with config', () => {
    const pipeline = new ParallaxPipeline({
      target: 'https://example.com',
      wordlistTier: 'fast',
    });
    expect(pipeline).toBeDefined();
  });

  it('should expose internal modules', () => {
    const pipeline = new ParallaxPipeline({
      target: 'https://example.com',
    });
    expect(pipeline.getProbe()).toBeDefined();
    expect(pipeline.getDiff()).toBeDefined();
    expect(pipeline.getPoison()).toBeDefined();
    expect(pipeline.getWeaponize()).toBeDefined();
  });

  it('should accept optional cookie and headers', () => {
    const pipeline = new ParallaxPipeline({
      target: 'https://example.com',
      cookie: 'session=abc',
      headers: { 'Authorization': 'Bearer token' },
    });
    expect(pipeline).toBeDefined();
  });
});

describe('ParallaxPipeline summary findings', () => {
  it('counts unkeyed query params surfaced by the probe', () => {
    const pipeline = new ParallaxPipeline({ target: 'https://example.com' });
    (pipeline as any).captureProbeFindings({ cacheKey: { unkeyedParams: ['utm_source', 'gclid'] } });
    expect((pipeline as any).summaryFindings()).toBe(2);
  });

  it('adds unkeyed params on top of poison/weaponize/diff counts', () => {
    const pipeline = new ParallaxPipeline({ target: 'https://example.com' });
    (pipeline as any).captureProbeFindings({ cacheKey: { unkeyedParams: ['utm_source'] } });
    expect((pipeline as any).summaryFindings()).toBe(1);
  });

  it('counts deception findings in summaryFindings', () => {
    const pipeline = new ParallaxPipeline({ target: 'https://example.com' });
    (pipeline as any).deceptionCount = 3;
    expect((pipeline as any).summaryFindings()).toBe(3);
  });

  it('sums deception + unkeyed params + other findings', () => {
    const pipeline = new ParallaxPipeline({ target: 'https://example.com' });
    (pipeline as any).captureProbeFindings({ cacheKey: { unkeyedParams: ['utm_source'] } });
    (pipeline as any).deceptionCount = 2;
    expect((pipeline as any).summaryFindings()).toBe(3);
  });

  it('counts confirmed exploit executions in summaryFindings', () => {
    const pipeline = new ParallaxPipeline({ target: 'https://example.com' });
    (pipeline as any).executedSolved = 4;
    expect((pipeline as any).summaryFindings()).toBe(4);
  });
});

describe('ParallaxPipeline weaponize resilience', () => {
  it('continues when weaponize.run throws', async () => {
    const pipeline = new ParallaxPipeline({ target: 'https://example.com', enableTiming: false });
    const weaponize = pipeline.getWeaponize();
    weaponize.run = vi.fn().mockRejectedValue(new Error('weaponize failed'));

    // The pipeline should not throw even if weaponize.run rejects
    // Mock all other stages to avoid HTTP calls
    (pipeline as any).probe.run = vi.fn().mockResolvedValue({
      cdn: { name: 'test', confidence: 0.9, allMatches: {} },
      proxy: { name: 'unknown', confidence: 0, allMatches: {} },
      framework: { name: 'unknown', confidence: 0, allMatches: {} },
      cacheKey: { unkeyedParams: [] },
      hiddenCacheDetected: false
    });
    (pipeline as any).harvest.run = vi.fn().mockResolvedValue([]);
    (pipeline as any).poison.run = vi.fn().mockResolvedValue(undefined);
    (pipeline as any).diff.run = vi.fn().mockResolvedValue(undefined);
    (pipeline as any).discover = vi.fn().mockResolvedValue({ cachedUrls: [], uncacheableUrls: [], totalTested: 0 });

    // Should not throw — weaponize failure is contained
    await expect(pipeline.run()).resolves.toBeDefined();
    expect(weaponize.run).toHaveBeenCalled();
  });
});
