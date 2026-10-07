import { describe, it, expect, vi } from 'vitest';
import { Discover } from '../discover';
import { Logger } from '../logger';
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

describe('discover external sources: katana + gau (parity)', () => {
  it('external run spawns katana and gau and merges their same-origin paths', async () => {
    const calls: Array<{ cmd: string; args: string[] }> = [];
    const exec = async (cmd: string, args: string[]) => {
      calls.push({ cmd, args });
      if (cmd === 'katana') {
        return [
          'https://example.com/legacy',
          'https://example.com/legacy?ref=1',
          'https://other.com/ignored',
        ].join('\n');
      }
      return [
        'https://example.com/historical',
        'http://example.com/old-page',
        'https://cdn.example.com/not-same-origin',
      ].join('\n');
    };
    const http = stubClient(() => ({ body: 'ok' }));
    const discover = new Discover({ target: 'https://example.com/', external: true, exec }, http);
    const result = await discover.run({} as any);

    const tested = [...result.cachedUrls.map(c => c.url), ...result.uncacheableUrls];
    expect(tested.some(u => u.includes('/legacy'))).toBe(true);
    expect(tested.some(u => u.includes('/historical'))).toBe(true);
    expect(tested.some(u => u.includes('/old-page'))).toBe(true);
    expect(tested.some(u => u.includes('other.com'))).toBe(false);
    expect(tested.some(u => u.includes('cdn.example.com'))).toBe(false);

    const katana = calls.find(c => c.cmd === 'katana');
    const gau = calls.find(c => c.cmd === 'gau');
    expect(katana).toBeTruthy();
    expect(katana!.args).toContain('-u');
    expect(katana!.args).toContain('https://example.com/');
    expect(gau).toBeTruthy();
    expect(gau!.args).toContain('example.com');
  });

  it('missing external binaries degrade gracefully to wordlist-only discovery', async () => {
    const exec = async () => {
      const err = new Error('spawn katana ENOENT') as Error & { code: string };
      err.code = 'ENOENT';
      throw err;
    };
    const http = stubClient(() => ({ body: 'ok' }));
    const discover = new Discover({ target: 'https://example.com/', external: true, exec }, http);
    const result = await discover.run({} as any);
    expect(result.totalTested).toBeGreaterThan(0);
    expect(result.cachedUrls.length + result.uncacheableUrls.length).toBeGreaterThan(0);
  });

  it('external sources are opt-in: no exec calls without external: true', async () => {
    const calls: string[] = [];
    const exec = async (cmd: string) => {
      calls.push(cmd);
      return '';
    };
    const http = stubClient(() => ({ body: 'ok' }));
    const discover = new Discover({ target: 'https://example.com/', exec }, http);
    await discover.run({} as any);
    expect(calls).toEqual([]);
  });

  it('warns per tool when an external binary is unavailable', async () => {
    const warnSpy = vi.spyOn(Logger.prototype, 'warn');
    try {
      const exec = async (cmd: string) => {
        const err = new Error(`spawn ${cmd} ENOENT`) as Error & { code: string };
        err.code = 'ENOENT';
        throw err;
      };
      const http = stubClient(() => ({ body: 'ok' }));
      const discover = new Discover({ target: 'https://example.com/', external: true, exec }, http);
      const result = await discover.run({} as any);

      // Still degrades gracefully...
      expect(result.totalTested).toBeGreaterThan(0);
      // ...but the operator must SEE which tool was missing.
      const warned = warnSpy.mock.calls.map(c => String(c[0]) + JSON.stringify(c[1] ?? {}));
      expect(warned.some(w => w.includes('katana'))).toBe(true);
      expect(warned.some(w => w.includes('gau'))).toBe(true);
      expect(warned.some(w => w.includes('ENOENT'))).toBe(true);
    } finally {
      warnSpy.mockRestore();
    }
  });
});
