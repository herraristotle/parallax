import { describe, it, expect } from 'vitest';
import { Discover } from '../discover';
import type { HttpClient, HttpResponse } from '../http-client';

function stubClient(handler: (url: string) => { body?: string; headers?: Record<string, string> }): HttpClient {
  return {
    get: async (url: string) => {
      const r = handler(url);
      return {
        status: 200,
        headers: r.headers || {},
        body: r.body ?? 'ok',
        bodyHash: 'x',
        timingMs: 1,
        fromCache: false,
      } satisfies HttpResponse;
    },
  } as unknown as HttpClient;
}

describe('Discover', () => {
  it('should have default paths', () => {
    const discover = new Discover({ target: 'https://example.com' });
    expect(discover.defaultPaths.length).toBeGreaterThanOrEqual(32);
    expect(discover.defaultPaths).toContain('/');
    expect(discover.defaultPaths).toContain('/index.html');
    expect(discover.defaultPaths).toContain('/robots.txt');
    expect(discover.defaultPaths).toContain('/api/health');
  });

  it('should deduplicate URLs by pathname', () => {
    const discover = new Discover({ target: 'https://example.com' });
    const urls = [
      'https://example.com/foo',
      'https://example.com/foo?a=1',
      'https://example.com/foo?b=2',
      'https://example.com/bar',
    ];
    const deduped = discover.deduplicateUrls(urls);
    expect(deduped).toEqual([
      'https://example.com/foo',
      'https://example.com/bar',
    ]);
  });

  it('should return empty array for empty input', () => {
    const discover = new Discover({ target: 'https://example.com' });
    expect(discover.deduplicateUrls([])).toEqual([]);
  });

  it('should accept custom config', () => {
    const discover = new Discover({
      target: 'https://example.com',
      cookie: 'session=abc',
      headers: { 'Authorization': 'Bearer token' },
    });
    expect(discover.defaultPaths.length).toBeGreaterThanOrEqual(32);
  });
});

describe('discover wordlists + crawl + buster (B-15)', () => {
  it('all tier is a superset of fast', () => {
    const discover = new Discover({ target: 'https://example.com' });
    expect(discover.allPaths.length).toBeGreaterThan(discover.defaultPaths.length);
    for (const p of discover.defaultPaths) expect(discover.allPaths).toContain(p);
  });

  it('testCacheability sends both pair requests with one shared cache buster', async () => {
    const urls: string[] = [];
    const http = stubClient((url) => {
      urls.push(url);
      return { body: 'ok' };
    });
    const discover = new Discover({ target: 'https://example.com' }, http);
    await discover.testCacheability('https://example.com/page');

    expect(urls).toHaveLength(2);
    const busters = urls.map(u => new URL(u).searchParams.get('_pc_bust'));
    expect(busters[0]).toBeTruthy();
    expect(busters[0]).toBe(busters[1]);
    // original path preserved
    expect(new URL(urls[0]).pathname).toBe('/page');
  });

  it('crawl picks up same-origin href/src links from the target HTML', async () => {
    const html = `<html><a href="/about">About</a><img src="/images/hero.png">` +
      `<a href="https://other.com/x">ext</a><a href="mailto:a@b.c">m</a></html>`;
    const http = stubClient((url) => ({
      body: url === 'https://example.com/' ? html : 'ok',
    }));
    const discover = new Discover({ target: 'https://example.com/' }, http);
    const result = await discover.run({} as any);

    const tested = [...result.cachedUrls.map(c => c.url), ...result.uncacheableUrls];
    expect(tested.some(u => u.includes('/about'))).toBe(true);
    expect(tested.some(u => u.includes('/images/hero.png'))).toBe(true);
    expect(tested.some(u => u.includes('other.com'))).toBe(false);
  });

  it('crawl can be disabled', async () => {
    const html = `<a href="/about">About</a>`;
    const http = stubClient((url) => ({
      body: url === 'https://example.com/' ? html : 'ok',
    }));
    const discover = new Discover({ target: 'https://example.com/', crawl: false }, http);
    const result = await discover.run({} as any);

    const tested = [...result.cachedUrls.map(c => c.url), ...result.uncacheableUrls];
    expect(tested.some(u => u.includes('/about'))).toBe(false);
  });

  it('all-tier run tests more paths than fast-tier', async () => {
    const makeDiscover = (wordlist?: 'fast' | 'all') => {
      const http = stubClient(() => ({ body: 'ok' }));
      return new Discover({ target: 'https://example.com/', wordlist }, http);
    };
    const fast = await makeDiscover('fast').run({} as any);
    const all = await makeDiscover('all').run({} as any);
    expect(all.totalTested).toBeGreaterThan(fast.totalTested);
  });
});
