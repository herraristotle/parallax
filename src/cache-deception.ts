import { HttpClient } from './http-client';
import type { DeceptionFinding } from './types';

export type { DeceptionFinding };

export interface DeceptionConfig {
  target: string;
  cookie?: string;
  headers?: Record<string, string>;
}

/**
 * Web Cache Deception detector (Gil, 2017).
 *
 * Method: take an endpoint that serves dynamic (user-specific) content,
 * append a deceptive static-looking suffix/path pattern, and verify two
 * conditions both hold:
 *   1. the origin ignores the suffix and still returns the dynamic body
 *      (server behavior — routing treats `/account.css` as `/account`),
 *   2. the cache keys on the extension and stores the response
 *      (second request comes back with cache-hit evidence).
 * When both hold, the cache will serve one user's response to others.
 *
 * Pattern families cover the whitepaper's known frameworks:
 *   - Cloudflare/IIS/NGINX path style: `endpoint.css`, `endpoint/.css`
 *   - PATH_INFO style (PHP/Apache):   `endpoint/x.css`
 *   - encoded variants that bypass cache normalizers.
 */
const DECEPTIVE_PATTERNS = [
  '{path}.css',
  '{path}/x.css',
  '{path}/.css',
  '{path}%2e.css',
  '{path}.js',
  '{path}/x.js',
  '{path}.png',
  '{path}%00.css',
];

const DYNAMIC_MARKERS = [
  /set-cookie/i,
  /csrf/i,
  /authenticity_token/i,
  /<form/i,
  /logout/i,
  /account|profile|dashboard/i,
];

function isDynamicBody(body: string, headers: Record<string, string>): boolean {
  if (headers['set-cookie']) return true;
  const sample = body.slice(0, 8000);
  return DYNAMIC_MARKERS.some((re) => re.test(sample));
}

function cacheHitEvidence(headers: Record<string, string>): Record<string, string> {
  const evidence: Record<string, string> = {};
  const indicators = [
    'cf-cache-status', 'x-cache', 'x-cache-hits', 'x-varnish',
    'age', 'x-served-by', 'cache-control', 'expires', 'last-modified',
  ];
  for (const key of indicators) {
    const value = headers[key];
    if (value) evidence[key] = value;
  }
  return evidence;
}

function looksLikeCacheHit(headers: Record<string, string>): boolean {
  const cf = (headers['cf-cache-status'] || '').toUpperCase();
  if (cf === 'HIT' || cf === 'STALE') return true;
  const xCache = (headers['x-cache'] || '').toUpperCase();
  if (xCache.includes('HIT')) return true;
  const age = parseInt(headers['age'] || '0', 10);
  if (!isNaN(age) && age > 0) return true;
  const vary = headers['x-varnish'];
  if (vary && vary.includes(' ')) return true; // hit marker in varnish pair
  return false;
}

export class CacheDeception {
  private config: DeceptionConfig;
  private http: HttpClient;

  constructor(config: DeceptionConfig, httpClient?: HttpClient) {
    this.config = config;
    this.http = httpClient || new HttpClient({ timeoutMs: 10000, rateLimitPerSec: 5 });
  }

  /**
   * Test a single dynamic endpoint for cache deception.
   * Returns a finding only when origin-serves AND cache-stores both hold.
   */
  async testEndpoint(endpointUrl: string): Promise<DeceptionFinding[]> {
    const findings: DeceptionFinding[] = [];
    const headers = this.config.headers || {};
    const parsed = new URL(endpointUrl);
    const path = parsed.pathname.replace(/\/+$/, '') || '/';

    // Baseline: confirm the endpoint is dynamic before wasting requests.
    const baseline = await this.http.get(endpointUrl, headers);
    if (baseline.status >= 400 || !isDynamicBody(baseline.body, baseline.headers)) {
      return findings;
    }

    for (const pattern of DECEPTIVE_PATTERNS) {
      const attackUrl = new URL(parsed.toString());
      attackUrl.pathname = pattern.replace('{path}', path);

      try {
        // Request 1: does the origin still serve the dynamic body?
        const first = await this.http.get(attackUrl.toString(), headers);
        if (first.status >= 400) continue;
        const originServed =
          first.body === baseline.body ||
          isDynamicBody(first.body, first.headers);
        if (!originServed) continue;

        // Request 2: did the cache store it?
        const second = await this.http.get(attackUrl.toString(), headers);
        const evidence = cacheHitEvidence(second.headers);
        const cached =
          looksLikeCacheHit(second.headers) ||
          (second.body.length > 0 && second.body === first.body && looksLikeCacheHit(second.headers));

        // Dynamic content + cache-hit evidence under a static-looking URL
        // is the deception condition. Require explicit hit evidence —
        // identical bodies alone don't prove cache involvement.
        const confirmed = originServed && looksLikeCacheHit(second.headers);

        if (confirmed || (originServed && Object.keys(evidence).length > 0 && looksLikeCacheHit(second.headers))) {
          findings.push({
            endpoint: endpointUrl,
            attackUrl: attackUrl.toString(),
            pattern: pattern,
            originServed,
            cached,
            cacheEvidence: evidence,
            originContentType: first.headers['content-type'],
            confirmed,
          });
        }
      } catch {
        // Pattern unsupported by edge — skip silently.
      }
    }

    return findings;
  }

  /** Sweep a list of discovered endpoints (dynamic ones shortlist internally). */
  async run(endpoints: string[], limit = 20): Promise<DeceptionFinding[]> {
    const findings: DeceptionFinding[] = [];
    for (const endpoint of endpoints.slice(0, limit)) {
      try {
        findings.push(...(await this.testEndpoint(endpoint)));
      } catch {
        // Unreachable endpoint — keep sweeping.
      }
      if (findings.some((f) => f.confirmed)) break; // one confirmed case is enough
    }
    return findings;
  }
}
