import { describe, it, expect } from 'vitest';
import { HeaderHarvest } from '../header-harvest';

describe('HeaderHarvest', () => {
  it('should construct with default config', () => {
    const harvest = new HeaderHarvest();
    expect(harvest).toBeDefined();
  });

  it('should construct with custom thresholds', () => {
    const harvest = new HeaderHarvest({ lowThreshold: 5, highThreshold: 10000 });
    expect(harvest).toBeDefined();
  });

  it('should return empty array when files not found', async () => {
    const harvest = new HeaderHarvest({ headersFile: '/nonexistent/headers.txt', parametersFile: '/nonexistent/parameters.txt' });
    const headers = await harvest.harvestUncommonHeaders();
    expect(headers).toEqual([]);
  });

  it('should return empty array for parameters when file not found', async () => {
    const harvest = new HeaderHarvest({ parametersFile: '/nonexistent/params.txt' });
    const params = await harvest.loadParameters();
    expect(params).toEqual([]);
  });

  it('should build wordlists from available data', async () => {
    const harvest = new HeaderHarvest({ headersFile: '/nonexistent/headers.txt', parametersFile: '/nonexistent/params.txt' });
    const wordlists = await harvest.buildWordlists();
    expect(wordlists).toHaveProperty('fast');
    expect(wordlists).toHaveProperty('all');
    expect(wordlists).toHaveProperty('totalUncommon');
    expect(wordlists).toHaveProperty('totalVary');
    expect(wordlists).toHaveProperty('totalCDNInternal');
    expect(wordlists).toHaveProperty('totalIANA');
    expect(wordlists.fast.length).toBeLessThanOrEqual(379);
  });

  it('should filter standard Vary headers', async () => {
    const harvest = new HeaderHarvest({ headersFile: '/nonexistent/headers.txt' });
    const vary = await harvest.harvestVaryHeaders();
    expect(vary).not.toContain('accept-encoding');
    expect(vary).not.toContain('user-agent');
    expect(vary).not.toContain('cookie');
  });
});
