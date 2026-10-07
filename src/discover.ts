import { DiscoverResult, CachedUrl, ProbeResult } from './types';
import { HttpClient } from './http-client';
import { Logger } from './logger';
import { execFile } from 'child_process';

/** Runs an external binary, returns stdout. Injected in tests. */
export type ExecRunner = (cmd: string, args: string[]) => Promise<string>;

export interface DiscoverConfig {
  target: string;
  cookie?: string;
  headers?: Record<string, string>;
  wordlist?: 'fast' | 'all';
  crawl?: boolean;
  /** Opt-in: merge katana crawl + GAU historical URLs (parity with competitor). */
  external?: boolean;
  exec?: ExecRunner;
}

/** Real runner: rejects on spawn failure/timeout so the caller can warn. */
const defaultExec: ExecRunner = (cmd, args) =>
  new Promise((resolve, reject) => {
    execFile(
      cmd,
      args,
      { timeout: 120_000, maxBuffer: 10 * 1024 * 1024, windowsHide: true },
      (err, stdout) => (err ? reject(err) : resolve(stdout)),
    );
  });

export class Discover {
  private config: DiscoverConfig;
  private http: HttpClient;
  private readonly log = new Logger('discover');

  defaultPaths = [
    '/', '/index.html', '/index.htm', '/default.html',
    '/assets/style.css', '/assets/script.js', '/static/style.css',
    '/images/logo.png', '/favicon.ico', '/robots.txt',
    '/api/health', '/api/status', '/api/version',
    '/login', '/register', '/dashboard', '/profile',
    '/css/main.css', '/js/app.js', '/img/banner.png',
    '/fonts/opensans.woff2', '/media/video.mp4',
    '/feed', '/sitemap.xml', '/manifest.json',
    '/.well-known/security.txt', '/.well-known/openid-configuration',
    '/graphql', '/swagger.json', '/openapi.json',
    '/v1/users', '/v2/users', '/admin', '/debug',
  ];

  /** fast = defaultPaths; all = fast + extended coverage (cms/api/backup/static). */
  allPaths = [
    ...this.defaultPaths,
    '/wp-json/', '/wp-login.php', '/wp-admin/', '/xmlrpc.php',
    '/cgi-bin/', '/server-status', '/server-info',
    '/.env', '/.git/HEAD', '/.gitignore', '/.htaccess', '/web.config',
    '/backup', '/backup.zip', '/db.sql', '/dump.sql',
    '/phpinfo.php', '/info.php', '/test.php',
    '/api', '/api/v1', '/api/v2', '/api/docs', '/api/swagger',
    '/api/users', '/api/products', '/api/config', '/api/healthz', '/api/metrics',
    '/health', '/healthz', '/ready', '/metrics', '/status.json',
    '/console', '/actuator', '/actuator/health', '/actuator/env',
    '/trace', '/jmx-console', '/manager/html',
    '/search', '/cart', '/checkout', '/orders',
    '/static/js/main.js', '/static/css/main.css', '/static/img/logo.png',
    '/uploads/', '/files/', '/docs/', '/documentation/',
    '/sitemap_index.xml', '/sitemap-1.xml', '/crossdomain.xml',
    '/browser-sync/browser-sync-client.js',
    '/__nextjs_original-stack-frame', '/_next/static/',
    '/app.js', '/main.js', '/bundle.js', '/vendor.js',
    '/error', '/404', '/500', '/maintenance',
    '/version', '/build-info', '/release',
  ];

  constructor(config: DiscoverConfig, httpClient?: HttpClient) {
    this.config = config;
    this.http = httpClient || new HttpClient({ timeoutMs: 10000, rateLimitPerSec: 10 });
  }

  async run(probeResult: ProbeResult): Promise<DiscoverResult> {
    const cachedUrls: CachedUrl[] = [];
    const uncacheableUrls: string[] = [];
    const wordlist = this.config.wordlist === 'all' ? this.allPaths : this.defaultPaths;
    const crawled = this.config.crawl === false ? [] : await this.crawl();
    const external = await this.externalPaths();
    const paths = [...new Set([...crawled, ...external, ...wordlist])];

    for (const path of paths) {
      const url = new URL(this.config.target);
      url.pathname = path;

      const result = await this.testCacheability(url.toString());
      if (result.cacheable) {
        cachedUrls.push({
          url: url.toString(),
          cacheStatus: result.cacheStatus,
          cacheHeaders: result.headers,
          isTargetUrl: path === '/',
        });
      } else {
        uncacheableUrls.push(url.toString());
      }
    }

    return { cachedUrls, uncacheableUrls, totalTested: paths.length };
  }

  /**
   * Depth-1 same-origin crawl: fetch the target HTML, extract href/src
   * links, return pathnames (max 25). Best-effort — empty on any failure.
   */
  async crawl(): Promise<string[]> {
    try {
      const resp = await this.http.get(this.config.target, this.config.headers || {});
      const origin = new URL(this.config.target).origin;
      const paths = new Set<string>();
      const re = /(?:href|src)\s*=\s*["']([^"'#]+)/gi;
      let m: RegExpExecArray | null;
      while ((m = re.exec(resp.body)) !== null && paths.size < 25) {
        try {
          const u = new URL(m[1], this.config.target);
          if (u.origin === origin && u.pathname) paths.add(u.pathname);
        } catch {
          // Skip unparseable links (mailto:, javascript:, etc.)
        }
      }
      return [...paths];
    } catch {
      return [];
    }
  }

  /**
   * External discovery (parity with competitor pipeline): katana deep crawl
   * + GAU historical URLs. Hostname-matched pathnames only. Any failure
   * (binary not installed, timeout, junk output) degrades to [].
   */
  async externalPaths(): Promise<string[]> {
    if (!this.config.external) return [];
    const run = this.config.exec ?? defaultExec;
    const host = new URL(this.config.target).hostname;
    const source = async (cmd: string, args: string[]): Promise<string> => {
      try {
        return await run(cmd, args);
      } catch (err) {
        this.log.warn(`${cmd} unavailable — install it or drop --external; continuing without its output`, {
          cmd,
          error: (err as Error).message,
        });
        return '';
      }
    };
    const [katanaOut, gauOut] = await Promise.all([
      source('katana', ['-u', this.config.target, '-d', '3', '-silent']),
      source('gau', [host]),
    ]);
    const paths = new Set<string>();
    for (const line of `${katanaOut}\n${gauOut}`.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const u = new URL(trimmed, this.config.target);
        if (u.hostname === host && u.pathname) paths.add(u.pathname);
      } catch {
        // Skip junk lines (non-URL output, banners)
      }
    }
    return [...paths];
  }

  async testCacheability(url: string): Promise<{ cacheable: boolean; cacheStatus: string; headers: Record<string, string> }> {
    // Cache buster: both pair requests share one unique key so the pair
    // starts from a cold entry instead of a pre-warmed/poisoned one.
    const bust = Math.random().toString(36).substring(2, 10);
    const busted = new URL(url);
    busted.searchParams.set('_pc_bust', bust);
    const pairUrl = busted.toString();

    const resp1 = await this.http.get(pairUrl, this.config.headers || {});
    const resp2 = await this.http.get(pairUrl, this.config.headers || {});

    // resp2 is the (potential) HIT — prefer its cache status, fall back to resp1
    const s2 = this.getCacheStatus(resp2.headers);
    const cacheHeader = s2 === 'UNKNOWN' ? this.getCacheStatus(resp1.headers) : s2;
    const cacheable = resp1.status === resp2.status && resp1.body === resp2.body;

    return { cacheable, cacheStatus: cacheHeader, headers: resp1.headers };
  }

  deduplicateUrls(urls: string[]): string[] {
    const seen = new Set<string>();
    return urls.filter(u => {
      const parsed = new URL(u);
      const key = parsed.pathname;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  private getCacheStatus(headers: Record<string, string>): string {
    const cacheHeaders = [
      'cf-cache-status', 'x-cache', 'x-varnish-cache',
      'x-amz-cf-id', 'x-served-by', 'x-iinfo',
    ];
    for (const h of cacheHeaders) {
      if (headers[h]) return headers[h];
    }
    if (headers['age'] && parseInt(headers['age']) > 0) return 'HIT';
    return 'UNKNOWN';
  }
}
