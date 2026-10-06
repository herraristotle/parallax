import { describe, it, expect } from 'vitest';
import { CacheDeception } from '../cache-deception';
import type { HttpClient, HttpResponse } from '../http-client';

function stubClient(handler: (url: string, n: number) => HttpResponse): HttpClient {
  let n = 0;
  return {
    get: async (url: string) => handler(url, n++),
  } as unknown as HttpClient;
}

function resp(overrides: Partial<HttpResponse> = {}): HttpResponse {
  return {
    status: 200,
    headers: {},
    body: '',
    ...overrides,
  };
}

const DYNAMIC_BODY = '<html><form action="/logout">Welcome user@example.com csrf=abc123</form></html>';

describe('CacheDeception', () => {
  it('confirms deception when origin serves dynamic body and cache reports HIT', async () => {
    let calls = 0;
    const client = stubClient((url) => {
      calls++;
      if (calls === 1) {
        // baseline — dynamic endpoint
        return resp({ body: DYNAMIC_BODY, headers: { 'set-cookie': 'sid=1' } });
      }
      // attack requests: origin serves same body, cache says HIT on 2nd fetch
      const isSecondOfPair = (calls - 1) % 2 === 0;
      return resp({
        body: DYNAMIC_BODY,
        headers: isSecondOfPair
          ? { 'cf-cache-status': 'HIT', 'content-type': 'text/html' }
          : { 'cf-cache-status': 'MISS', 'content-type': 'text/html' },
      });
    });

    const deception = new CacheDeception({ target: 'https://example.com/account' }, client);
    const findings = await deception.testEndpoint('https://example.com/account');

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].originServed).toBe(true);
    expect(findings[0].confirmed).toBe(true);
    expect(findings[0].cacheEvidence['cf-cache-status']).toBe('HIT');
    expect(findings[0].attackUrl).toContain('.css');
  });

  it('returns nothing for non-dynamic endpoints', async () => {
    const client = stubClient(() => resp({ body: 'body{color:red}', headers: { 'content-type': 'text/css' } }));
    const deception = new CacheDeception({ target: 'https://example.com/style.css' }, client);
    const findings = await deception.testEndpoint('https://example.com/style.css');
    expect(findings).toEqual([]);
  });

  it('does not confirm when cache never reports a hit', async () => {
    let calls = 0;
    const client = stubClient(() => {
      calls++;
      if (calls === 1) return resp({ body: DYNAMIC_BODY, headers: { 'set-cookie': 'sid=1' } });
      return resp({ body: DYNAMIC_BODY, headers: { 'cf-cache-status': 'MISS', 'content-type': 'text/html' } });
    });
    const deception = new CacheDeception({ target: 'https://example.com/account' }, client);
    const findings = await deception.testEndpoint('https://example.com/account');
    expect(findings.filter(f => f.confirmed)).toEqual([]);
  });

  it('skips 404 endpoints', async () => {
    const client = stubClient(() => resp({ status: 404, body: 'nope' }));
    const deception = new CacheDeception({ target: 'https://example.com/missing' }, client);
    const findings = await deception.testEndpoint('https://example.com/missing');
    expect(findings).toEqual([]);
  });

  it('run() stops after first confirmed finding', async () => {
    let calls = 0;
    const client = stubClient(() => {
      calls++;
      if (calls === 1) return resp({ body: DYNAMIC_BODY, headers: { 'set-cookie': 'sid=1' } });
      const isSecondOfPair = (calls - 1) % 2 === 0;
      return resp({
        body: DYNAMIC_BODY,
        headers: isSecondOfPair
          ? { 'x-cache': 'HIT from cloudfront' }
          : { 'x-cache': 'Miss from cloudfront' },
      });
    });
    const deception = new CacheDeception({ target: 'https://example.com' }, client);
    const findings = await deception.run([
      'https://example.com/a',
      'https://example.com/b',
      'https://example.com/c',
    ]);
    expect(findings.some(f => f.confirmed)).toBe(true);
    // Confirmed on first endpoint → sweep stops (bounded call count).
    expect(calls).toBeLessThan(26);
  });

  it('treats Age > 0 as cache-hit evidence', async () => {
    let calls = 0;
    const client = stubClient(() => {
      calls++;
      if (calls === 1) return resp({ body: DYNAMIC_BODY, headers: { 'set-cookie': 'sid=1' } });
      const isSecondOfPair = (calls - 1) % 2 === 0;
      return resp({
        body: DYNAMIC_BODY,
        headers: isSecondOfPair ? { age: '42' } : { age: '0' },
      });
    });
    const deception = new CacheDeception({ target: 'https://example.com/profile' }, client);
    const findings = await deception.testEndpoint('https://example.com/profile');
    expect(findings.some(f => f.confirmed && f.cacheEvidence['age'] === '42')).toBe(true);
  });
});
