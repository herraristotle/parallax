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

describe('CacheProbe unkeyed query params', () => {
  /** Mini cache: keyed on path + params NOT in ignoreParams (value-sensitive). */
  function cacheServer(ignoreParams: string[]) {
    const store = new Map<string, string>();
    const client = {
      get: async (urlStr: string) => {
        const u = new URL(urlStr);
        const key =
          u.pathname +
          '?' +
          [...u.searchParams.entries()]
            .filter(([k]) => !ignoreParams.includes(k))
            .map(([k, v]) => `${k}=${v}`)
            .sort()
            .join('&');
        const hit = store.get(key);
        if (hit) {
          return { status: 200, headers: {}, body: hit, bodyHash: '', timingMs: 1, fromCache: true };
        }
        const body =
          'resp:' +
          [...u.searchParams.entries()].map(([k, v]) => `${k}=${v}`).join(',');
        store.set(key, body);
        return { status: 200, headers: {}, body, bodyHash: '', timingMs: 1, fromCache: false };
      },
    } as unknown as HttpClient;
    return client;
  }

  it('flags a value-unkeyed param (cache serves stale variant) and not a keyed one', async () => {
    // cache ignores utm_source (classic unkeyed ad-tech param); keys everything else
    const client = cacheServer(['utm_source']);
    const probe = new CacheProbe({ target: 'https://example.com' });
    const unkeyed = await probe.detectUnkeyedQueryParams(client);
    expect(unkeyed).toContain('utm_source');
    expect(unkeyed).not.toContain('gclid');
  });

  it('returns empty when every candidate param is keyed', async () => {
    const client = cacheServer([]);
    const probe = new CacheProbe({ target: 'https://example.com' });
    const unkeyed = await probe.detectUnkeyedQueryParams(client);
    expect(unkeyed).toEqual([]);
  });
});

describe('CacheProbe reflection-gadget discovery', () => {
  /**
   * Mini origin: reflects params listed in reflectParams inside a <script>
   * block; cache keyed on all params EXCEPT ignoreParams. canaryPrefix lets
   * tests target specific wordlist params.
   */
  function gadgetServer(opts: { ignoreParams: string[]; reflectParams: string[] }) {
    const store = new Map<string, string>();
    return {
      get: async (urlStr: string) => {
        const u = new URL(urlStr);
        const key =
          u.pathname +
          '?' +
          [...u.searchParams.entries()]
            .filter(([k]) => !opts.ignoreParams.includes(k))
            .map(([k, v]) => `${k}=${v}`)
            .sort()
            .join('&');
        const hit = store.get(key);
        if (hit) return { status: 200, headers: {}, body: hit, bodyHash: '', timingMs: 1, fromCache: true };
        // origin page: reflect chosen params inside a script block
        const reflected = [...u.searchParams.entries()]
          .filter(([k]) => opts.reflectParams.includes(k))
          .map(([, v]) => v)
          .join('|');
        const body = `<html><script>var d="${reflected}";</script></html>`;
        store.set(key, body);
        return { status: 200, headers: {}, body, bodyHash: '', timingMs: 1, fromCache: false };
      },
    } as unknown as HttpClient;
  }

  it('finds params that are both unkeyed AND reflected, with js context', async () => {
    // 'nc' is unkeyed + reflected; 'q' is reflected but keyed; 'utm_source' unkeyed but NOT reflected
    const client = gadgetServer({ ignoreParams: ['nc', 'utm_source'], reflectParams: ['nc', 'q'] });
    const probe = new CacheProbe({ target: 'https://example.com' });
    const gadgets = await probe.discoverReflectionGadgets(client);
    const nc = gadgets.find(g => g.param === 'nc');
    expect(nc).toBeDefined();
    expect(nc!.context).toBe('js');
    // keyed-but-reflected: excluded (fresh cache entry per value → not poisonable)
    expect(gadgets.find(g => g.param === 'q')).toBeUndefined();
    // unkeyed-but-unreflected: excluded (no gadget)
    expect(gadgets.find(g => g.param === 'utm_source')).toBeUndefined();
  });

  it('classifies html-context reflection', async () => {
    // reflect in plain HTML (not inside a script block)
    const store = new Map<string, string>();
    const client = {
      get: async (urlStr: string) => {
        const u = new URL(urlStr);
        const key = u.pathname + '?' + [...u.searchParams.entries()].filter(([k]) => k !== 'nc').map(([k, v]) => `${k}=${v}`).join('&');
        const hit = store.get(key);
        if (hit) return { status: 200, headers: {}, body: hit, bodyHash: '', timingMs: 1, fromCache: true };
        const v = u.searchParams.get('nc') || '';
        const body = `<html><body>Welcome ${v}</body></html>`;
        store.set(key, body);
        return { status: 200, headers: {}, body, bodyHash: '', timingMs: 1, fromCache: false };
      },
    } as unknown as HttpClient;
    const probe = new CacheProbe({ target: 'https://example.com' });
    const gadgets = await probe.discoverReflectionGadgets(client);
    const nc = gadgets.find(g => g.param === 'nc');
    expect(nc).toBeDefined();
    expect(nc!.context).toBe('html');
  });
});

describe('CacheProbe target-specific param mining', () => {
  it('extracts param names from the target page HTML/JS', async () => {
    const client = {
      get: async () => ({
        status: 200,
        headers: {},
        body: `
          <html><body>
            <a href="/product?stock=123&nc=abc">buy</a>
            <form><input name="callback" value=""><input name='redirect' value=""></form>
            <script>
              fetch('/api/items?item=5&page=2');
              const cfg = { apiKey: "x", langParam: "en" };
            </script>
          </body></html>`,
        bodyHash: '',
        timingMs: 1,
        fromCache: false,
      }),
    } as unknown as HttpClient;
    const probe = new CacheProbe({ target: 'https://example.com' });
    const mined = await probe.mineTargetParams(client);
    expect(mined).toContain('stock');
    expect(mined).toContain('nc');
    expect(mined).toContain('callback');
    expect(mined).toContain('redirect');
    expect(mined).toContain('item');
    expect(mined).toContain('page');
    // noise guards: no javascript keywords / values
    expect(mined).not.toContain('href');
    expect(mined).not.toContain('const');
  });

  it('merged into gadget discovery when no explicit list given', async () => {
    // target reflects `secretapp` (only findable by mining) and cache is unkeyed on it
    const store = new Map<string, string>();
    const client = {
      get: async (urlStr: string) => {
        const u = new URL(urlStr);
        if (u.searchParams.toString() === '') {
          // page load: reveal the app's own param usage
          return {
            status: 200, headers: {}, bodyHash: '', timingMs: 1, fromCache: false,
            body: '<a href="/?secretapp=1">x</a>',
          };
        }
        const key = u.pathname + '?buster=' + (u.searchParams.get('_pc_x') || '') + (u.searchParams.has('secretapp') ? ':p' : '');
        const hit = store.get(key);
        if (hit) return { status: 200, headers: {}, body: hit, bodyHash: '', timingMs: 1, fromCache: true };
        const v = u.searchParams.get('secretapp') || '';
        const body = `<html><script>var d="${v}";</script></html>`;
        store.set(key, body);
        return { status: 200, headers: {}, body, bodyHash: '', timingMs: 1, fromCache: false };
      },
    } as unknown as HttpClient;
    const probe = new CacheProbe({ target: 'https://example.com' });
    const gadgets = await probe.discoverReflectionGadgets(client, undefined, { mineTarget: true });
    expect(gadgets.find(g => g.param === 'secretapp')).toBeDefined();
  });
});
