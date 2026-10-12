import { describe, it, expect } from 'vitest';
import { CacheTiming } from '../cache-timing';

describe('CacheTiming', () => {
  it('should compute Welch t-test correctly', () => {
    const timing = new CacheTiming({ target: 'https://example.com' });
    // Two groups: randomized (positive values) vs fixed (negative = cached)
    const randomized = [10, 12, 11, 13, 10, 12, 11, 13, 10, 12];
    const fixed = [-5, -4, -6, -5, -4, -6, -5, -4, -6, -5];
    const result = timing.welchTTest(randomized, fixed);
    expect(result.pValue).toBeLessThan(0.01);
    expect(result.significant).toBe(true);
  });

  it('should not find significance for similar groups', () => {
    const timing = new CacheTiming({ target: 'https://example.com' });
    const group1 = [10, 11, 12, 10, 11, 12, 10, 11, 12, 10];
    const group2 = [10, 11, 12, 10, 11, 12, 10, 11, 12, 10];
    const result = timing.welchTTest(group1, group2);
    expect(result.significant).toBe(false);
  });

  it('should remove outliers beyond 2x stddev', () => {
    const timing = new CacheTiming({ target: 'https://example.com' });
    const data = [10, 12, 11, 13, 10, 100, 12, 11, 13, 10];
    const cleaned = timing.removeOutliers(data);
    expect(cleaned).not.toContain(100);
    expect(cleaned.length).toBeLessThan(data.length);
  });

  it('should not remove data when no outliers', () => {
    const timing = new CacheTiming({ target: 'https://example.com' });
    const data = [10, 11, 12, 10, 11, 12, 10, 11, 12, 10];
    const cleaned = timing.removeOutliers(data);
    expect(cleaned.length).toBe(data.length);
  });

  it('should generate cache-buster header set', () => {
    const timing = new CacheTiming({ target: 'https://example.com' });
    const busters = timing.generateCacheBusters();
    expect(busters).toHaveProperty('query');
    expect(busters).toHaveProperty('origin');
    expect(busters).toHaveProperty('user-agent');
    expect(busters).toHaveProperty('x-forwarded-host');
    expect(busters).toHaveProperty('x-forwarded-scheme');
    expect(busters).toHaveProperty('x-method-override');
  });

  it('should continue timing analysis when some pairs fail', async () => {
    let callCount = 0;
    const flakyClient = {
      get: async () => {
        callCount++;
        if (callCount === 2 || callCount === 5) throw new Error('Transient failure');
        return { status: 200, body: '', headers: {}, fromCache: false };
      }
    };
    const timing = new CacheTiming({ target: 'https://example.com', pairsPerGroup: 3 }, flakyClient as any);
    const result = await timing.detectHiddenCache();
    // Should complete despite 2 failures (2 pairs fail → 4 fewer timings collected, but still runs)
    expect(callCount).toBeGreaterThan(4);
    expect(result.hiddenCacheDetected).toBeDefined();
  });
});
