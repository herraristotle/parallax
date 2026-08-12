import { describe, it, expect } from 'vitest';
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
