import { describe, it, expect } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { HeaderHarvest } from '../header-harvest';
import { FetchLike } from '../bigquery';

describe('HeaderHarvest', () => {
  it('should construct with default config', () => {
    const harvest = new HeaderHarvest();
    expect(harvest).toBeDefined();
  });

  it('should construct with custom thresholds', () => {
    const harvest = new HeaderHarvest({ lowThreshold: 5, highThreshold: 10000 });
    expect(harvest).toBeDefined();
  });

  it('loads bundled header and parameter wordlists by default', async () => {
    const harvest = new HeaderHarvest();
    expect(await harvest.harvestUncommonHeaders()).toContain('accept');
    expect(await harvest.loadParameters()).toContain('id');
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

describe('HeaderHarvest BigQuery path (B-13)', () => {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const credPath = path.join(os.tmpdir(), `hq-${Date.now()}.json`);
  fs.writeFileSync(credPath, JSON.stringify({
    client_email: 'x@proj.iam.gserviceaccount.com',
    private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  }));
  const headersFile = path.join(os.tmpdir(), `hq-headers-${Date.now()}.txt`);
  fs.writeFileSync(headersFile, 'x-file-only\ncf-cache-status\n');

  const okFetch = (bqHeaders: string[]): FetchLike => async (url) => {
    if (String(url).includes('oauth2.googleapis.com')) {
      return { ok: true, status: 200, text: async () => JSON.stringify({ access_token: 'tok' }) };
    }
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({
        jobComplete: true,
        rows: bqHeaders.map((h) => ({ f: [{ v: h }, { v: '5' }] })),
      }),
    };
  };

  it('merges BigQuery results ahead of file-based headers', async () => {
    const harvest = new HeaderHarvest({
      bigQueryProject: 'bill-proj',
      bigQueryCredentialsPath: credPath,
      headersFile,
    });
    harvest.fetchImpl = okFetch(['X-BQ-Header', 'cf-cache-status']);
    const headers = await harvest.harvestUncommonHeaders();
    expect(headers.slice(0, 2)).toEqual(['x-bq-header', 'cf-cache-status']);
    expect(headers).toContain('x-file-only');
    expect(headers.filter((h) => h === 'cf-cache-status')).toHaveLength(1);
  });

  it('falls back to file harvest when GCP errors', async () => {
    const harvest = new HeaderHarvest({
      bigQueryProject: 'bill-proj',
      bigQueryCredentialsPath: credPath,
      headersFile,
    });
    harvest.fetchImpl = async () => ({
      ok: false,
      status: 403,
      text: async () => JSON.stringify({ error: 'forbidden' }),
    });
    const headers = await harvest.harvestUncommonHeaders();
    expect(headers).toEqual(['x-file-only', 'cf-cache-status']);
  });

  it('stays file-only when no project is configured', async () => {
    const harvest = new HeaderHarvest({ headersFile });
    harvest.fetchImpl = async () => {
      throw new Error('network must not be used');
    };
    const headers = await harvest.harvestUncommonHeaders();
    expect(headers).toEqual(['x-file-only', 'cf-cache-status']);
  });
});
