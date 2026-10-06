import { describe, it, expect } from 'vitest';
import { CacheProbe } from '../cache-probe';
import type { HttpClient, HttpResponse } from '../http-client';

describe('CacheProbe', () => {
  it('should detect Cloudflare from cf-cache-status header', () => {
    const probe = new CacheProbe({ target: 'https://example.com' });
    const result = probe.detectCDN({ 'cf-cache-status': 'HIT', 'cf-ray': 'abc123' });
    expect(result.name).toBe('cloudflare');
    expect(result.confidence).toBeGreaterThan(0.9);
  });

  it('should detect CloudFront from x-cache header', () => {
    const probe = new CacheProbe({ target: 'https://example.com' });
    const result = probe.detectCDN({ 'x-cache': 'Hit from cloudfront' });
    expect(result.name).toBe('cloudfront');
  });

  it('should detect Fastly from x-served-by', () => {
    const probe = new CacheProbe({ target: 'https://example.com' });
    const result = probe.detectCDN({ 'x-served-by': 'cache-123' });
    expect(result.name).toBe('fastly');
  });

  it('should detect Akamai from x-akamai-transformed', () => {
    const probe = new CacheProbe({ target: 'https://example.com' });
    const result = probe.detectCDN({ 'x-akamai-transformed': 'ok' });
    expect(result.name).toBe('akamai');
  });

  it('should return unknown for no matching headers', () => {
    const probe = new CacheProbe({ target: 'https://example.com' });
    const result = probe.detectCDN({ 'server': 'apache' });
    expect(result.name).toBe('unknown');
    expect(result.confidence).toBe(0);
  });

  it('should detect Varnish from x-varnish', () => {
    const probe = new CacheProbe({ target: 'https://example.com' });
    const result = probe.detectProxy({ 'x-varnish': '12345' });
    expect(result.name).toBe('varnish');
  });

  it('should detect Nginx from server header', () => {
    const probe = new CacheProbe({ target: 'https://example.com' });
    const result = probe.detectProxy({ 'server': 'nginx' });
    expect(result.name).toBe('nginx');
  });

  it('should detect Next.js from x-powered-by', () => {
    const probe = new CacheProbe({ target: 'https://example.com' });
    const result = probe.detectFramework({ 'x-powered-by': 'Next.js' });
    expect(result.name).toBe('nextjs');
  });

  it('should detect Express from x-powered-by', () => {
    const probe = new CacheProbe({ target: 'https://example.com' });
    const result = probe.detectFramework({ 'x-powered-by': 'Express' });
    expect(result.name).toBe('express');
  });

  it('should accumulate confidence with multiple matches', () => {
    const probe = new CacheProbe({ target: 'https://example.com' });
    const result = probe.detectCDN({ 'cf-cache-status': 'HIT', 'cf-ray': 'abc123', 'server': 'cloudflare' });
    expect(result.name).toBe('cloudflare');
    expect(result.confidence).toBeGreaterThan(0.9);
  });
});

describe('cache-key header dim (B-11)', () => {
  function stub(handler: (headers: Record<string, string>, url: string) => string): HttpClient {
    return {
      get: async (url: string, headers: Record<string, string> = {}) => ({
        status: 200,
        headers: {},
        body: handler(headers, url),
        bodyHash: 'x',
        timingMs: 1,
        fromCache: false,
      } satisfies HttpResponse),
    } as unknown as HttpClient;
  }

  it('records a header whose variants each see their own canary (keyed)', async () => {
    const probe = new CacheProbe({ target: 'https://example.com/page' });
    const http = stub((headers) => headers['x-forwarded-host'] || 'static');
    const key = await probe.reverseCacheKey(http);
    expect(key.headersKeyed).toContain('x-forwarded-host');
    // headers that never reflect stay out (inconclusive, not falsely keyed)
    expect(key.headersKeyed).not.toContain('accept-language');
  });

  it('leaves header out when the second variant serves the first canary (unkeyed)', async () => {
    const probe = new CacheProbe({ target: 'https://example.com/page' });
    // shared cache entry: first body for a given cache-buster wins
    const entries = new Map<string, string>();
    const http = stub((headers, url) => {
      const key = url;
      if (!entries.has(key)) entries.set(key, headers['x-forwarded-host'] || 'static');
      return entries.get(key)!;
    });
    const key = await probe.reverseCacheKey(http);
    expect(key.headersKeyed).toEqual([]);
  });

  it('skips headers the origin does not reflect', async () => {
    const probe = new CacheProbe({ target: 'https://example.com/page' });
    const http = stub(() => 'static body');
    const key = await probe.reverseCacheKey(http);
    expect(key.headersKeyed).toEqual([]);
  });
});
