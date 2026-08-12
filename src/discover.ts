import { DiscoverResult, CachedUrl, ProbeResult } from './types';
import { HttpClient } from './http-client';

export interface DiscoverConfig {
  target: string;
  cookie?: string;
  headers?: Record<string, string>;
}

export class Discover {
  private config: DiscoverConfig;
  private http: HttpClient;

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

  constructor(config: DiscoverConfig, httpClient?: HttpClient) {
    this.config = config;
    this.http = httpClient || new HttpClient({ timeoutMs: 10000, rateLimitPerSec: 10 });
  }

  async run(probeResult: ProbeResult): Promise<DiscoverResult> {
    const cachedUrls: CachedUrl[] = [];
    const uncacheableUrls: string[] = [];

    for (const path of this.defaultPaths) {
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

    return { cachedUrls, uncacheableUrls, totalTested: this.defaultPaths.length };
  }

  async testCacheability(url: string): Promise<{ cacheable: boolean; cacheStatus: string; headers: Record<string, string> }> {
    const resp1 = await this.http.get(url, this.config.headers || {});
    const resp2 = await this.http.get(url, this.config.headers || {});

    const cacheHeader = this.getCacheStatus(resp1.headers);
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
