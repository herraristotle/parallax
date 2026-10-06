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
  // Berto CLOSER'24 §4.2: webmail attack vectors
  '{path}.woff2',
  '{path}/logo.svg',
  '{path}.ico',
  // Kettle web-cache-entanglement: RPO (Relative Path Overwrite)
  '{path}/..%2f..%2fattacker.css',
  '{path}/%2e%2e/static/evil.css',
  // Mirheidari sec22 DE: path parameter confusion
  '{path};.css',
  '{path}%3b.css',
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

/** Strip per-response volatile tokens so identicality compares page structure. */
function normalizeBody(body: string): string {
  return body
    .replace(/cf_obf_email\s*=\s*"[^"]*"/gi, 'cf_obf_email=""')       // CF email obfuscation (sec22 §4.2)
    .replace(/name="_csrf[^"]*"\s+value="[^"]*"/gi, 'name="_csrf" value=""')
    .replace(/authenticity_token"[^>]*value="[^"]*"/gi, 'authenticity_token" value=""')
    .replace(/\b[0-9a-f]{32,}\b/gi, 'HASH')                            // nonces / session hashes
    .replace(/\d{10,}/g, 'TS');                                        // timestamps
}

/** Marker-free page identicality (Mirheidari sec22 §3.1): Jaccard on word tokens. */
export function pageIdenticality(a: string, b: string): number {
  const tokenize = (s: string) => new Set(normalizeBody(s).toLowerCase().split(/\s+/).filter(Boolean));
  const ta = tokenize(a);
  const tb = tokenize(b);
  if (ta.size === 0 && tb.size === 0) return 1;
  let inter = 0;
  for (const t of ta) if (tb.has(t)) inter++;
  return inter / (ta.size + tb.size - inter);
}

/** Berto CLOSER'24 §5: SameSite=None; Secure session cookie enables webmail WCD vector. */
function enablesWebmailVector(headers: Record<string, string>): boolean {
  const cookie = headers['set-cookie'] || '';
  return /samesite\s*=\s*none/i.test(cookie) && /secure/i.test(cookie);
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
          const finding: DeceptionFinding = {
            endpoint: endpointUrl,
            attackUrl: attackUrl.toString(),
            pattern: pattern,
            originServed,
            cached,
            cacheEvidence: evidence,
            originContentType: first.headers['content-type'],
            confirmed,
          };

          // sec22 §3.1 marker-free identicality: re-fetch deceptive URL with
          // credentials stripped. If the cache still serves the authenticated
          // body, any user gets the victim's content (cross-user leak).
          const unauthHeaders = { ...headers };
          delete unauthHeaders['cookie'];
          delete unauthHeaders['authorization'];
          const hadCreds = 'cookie' in headers || 'authorization' in headers;
          if (hadCreds) {
            try {
              const unauth = await this.http.get(attackUrl.toString(), unauthHeaders);
              const score = pageIdenticality(first.body, unauth.body);
              finding.identicalityScore = score;
              finding.crossUserLeak =
                score >= 0.95 && unauth.body.length > 0 &&
                (looksLikeCacheHit(unauth.headers) || unauth.body === first.body);
            } catch {
              // Unauth probe failed — identicality stays undefined.
            }
          }

          if (enablesWebmailVector(baseline.headers)) finding.webmailVector = true;

          findings.push(finding);
          if (confirmed) break;
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
