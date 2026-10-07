import { describe, it, expect, vi } from 'vitest';

const captured: Array<Record<string, unknown>> = [];

vi.mock('../discover', async (importOriginal) => {
  const mod = await importOriginal<typeof import('../discover')>();
  class MockDiscover {
    constructor(config: Record<string, unknown>) {
      captured.push(config);
    }
    run = async () => ({ cachedUrls: [], uncacheableUrls: [], totalTested: 0 });
  }
  return { ...mod, Discover: MockDiscover };
});

import { ParallaxPipeline } from '../pipeline';

describe('pipeline external discovery wiring', () => {
  it('passes external + exec through to Discover', async () => {
    captured.length = 0;
    const exec = async () => '';
    const pipeline = new ParallaxPipeline({
      target: 'https://example.com',
      external: true,
      exec,
    });
    await (pipeline as unknown as { discover(p: unknown): Promise<unknown> }).discover({});
    expect(captured).toHaveLength(1);
    expect(captured[0].external).toBe(true);
    expect(captured[0].exec).toBe(exec);
  });

  it('external stays off unless configured', async () => {
    captured.length = 0;
    const pipeline = new ParallaxPipeline({ target: 'https://example.com' });
    await (pipeline as unknown as { discover(p: unknown): Promise<unknown> }).discover({});
    expect(captured[0].external).toBeFalsy();
  });
});
