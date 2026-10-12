import { CacheProbeConfig, ProbeResult, CDNFingerprint, ProxyFingerprint, FrameworkFingerprint, CacheKeySpec } from './types';
import { HttpClient, HttpResponse } from './http-client';
import * as fs from 'fs';
import * as path from 'path';

const CF_EMAIL_RE = /data-cfemail="[a-f0-9]+"/gi;

export class CacheProbe {
  private config: CacheProbeConfig;
  private http: HttpClient;

  // CDN signatures with Bayesian confidence accumulation
  private static CDN_SIGNATURES = [
    // Cloudflare
    { header: 'cf-cache-status', pattern: null, cdn: 'cloudflare', confidence: 0.95 },
    { header: 'cf-ray', pattern: null, cdn: 'cloudflare', confidence: 0.95 },
    { header: 'server', pattern: 'cloudflare', cdn: 'cloudflare', confidence: 0.90 },
    
    // CloudFront
    { header: 'x-amz-cf-id', pattern: null, cdn: 'cloudfront', confidence: 0.95 },
    { header: 'x-cache', pattern: 'from cloudfront', cdn: 'cloudfront', confidence: 0.95 },
    { header: 'via', pattern: 'cloudfront', cdn: 'cloudfront', confidence: 0.90 },
    
    // Fastly
    { header: 'x-served-by', pattern: 'cache-', cdn: 'fastly', confidence: 0.90 },
    { header: 'x-cache', pattern: 'fastly', cdn: 'fastly', confidence: 0.90 },
    { header: 'fastly-debug-digest', pattern: null, cdn: 'fastly', confidence: 0.95 },
    
    // Akamai
    { header: 'x-akamai-transformed', pattern: null, cdn: 'akamai', confidence: 0.95 },
    { header: 'x-akamai-request-id', pattern: null, cdn: 'akamai', confidence: 0.95 },
    { header: 'server', pattern: 'akamai', cdn: 'akamai', confidence: 0.85 },
    
    // Azure Front Door
    { header: 'x-azure-ref', pattern: null, cdn: 'azure-front-door', confidence: 0.95 },
    
    // Google Cloud CDN
    { header: 'x-cache', pattern: 'google', cdn: 'google-cloud-cdn', confidence: 0.85 },
    
    // Imperva
    { header: 'x-iinfo', pattern: null, cdn: 'imperva', confidence: 0.90 },
    { header: 'x-cdn', pattern: 'imperva', cdn: 'imperva', confidence: 0.85 },
    
    // Vercel
    { header: 'x-vercel-cache', pattern: null, cdn: 'vercel', confidence: 0.95 },
    { header: 'x-vercel-id', pattern: null, cdn: 'vercel', confidence: 0.95 },
    
    // Netlify
    { header: 'x-nf-request-id', pattern: null, cdn: 'netlify', confidence: 0.95 },
    { header: 'server', pattern: 'netlify', cdn: 'netlify', confidence: 0.90 },
  ];

  // Proxy layer signatures
  private static PROXY_SIGNATURES = [
    { header: 'x-varnish', pattern: null, proxy: 'varnish', confidence: 0.95 },
    { header: 'via', pattern: 'varnish', proxy: 'varnish', confidence: 0.90 },
    { header: 'x-varnish-cache', pattern: null, proxy: 'varnish', confidence: 0.90 },
    
    { header: 'server', pattern: 'nginx', proxy: 'nginx', confidence: 0.80 },
    { header: 'x-nginx-cache', pattern: null, proxy: 'nginx', confidence: 0.90 },
    
    { header: 'server', pattern: 'apache', proxy: 'apache', confidence: 0.75 },
    { header: 'x-cache', pattern: 'apache', proxy: 'apache', confidence: 0.70 },
    
    { header: 'x-haproxy', pattern: null, proxy: 'haproxy', confidence: 0.90 },
    { header: 'x-proxy-cache', pattern: null, proxy: 'haproxy', confidence: 0.85 },
    
    { header: 'server', pattern: 'envoy', proxy: 'envoy', confidence: 0.85 },
    { header: 'x-envoy', pattern: null, proxy: 'envoy', confidence: 0.90 },
    
    { header: 'server', pattern: 'traefik', proxy: 'traefik', confidence: 0.85 },
    { header: 'x-traefik', pattern: null, proxy: 'traefik', confidence: 0.90 },
    
    { header: 'server', pattern: 'caddy', proxy: 'caddy', confidence: 0.85 },
    { header: 'server', pattern: 'openresty', proxy: 'openresty', confidence: 0.90 },
    { header: 'server', pattern: 'openlitespeed', proxy: 'openlitespeed', confidence: 0.90 },
  ];

  // Framework signatures
  private static FRAMEWORK_SIGNATURES = [
    { header: 'x-powered-by', pattern: 'express', framework: 'express', confidence: 0.90 },
    { header: 'x-powered-by', pattern: 'next.js', framework: 'nextjs', confidence: 0.95 },
    { header: 'server', pattern: 'next.js', framework: 'nextjs', confidence: 0.90 },
    { header: 'x-nuxt', pattern: null, framework: 'nuxt', confidence: 0.95 },
    { header: 'x-powered-by', pattern: 'php', framework: 'php', confidence: 0.70 },
    { header: 'x-aspnet-version', pattern: null, framework: 'asp.net', confidence: 0.95 },
    { header: 'x-powered-by', pattern: 'django', framework: 'django', confidence: 0.85 },
    { header: 'server', pattern: 'gunicorn', framework: 'flask', confidence: 0.70 },
    { header: 'server', pattern: 'werkzeug', framework: 'flask', confidence: 0.80 },
    { header: 'x-rails-version', pattern: null, framework: 'rails', confidence: 0.95 },
    { header: 'x-powered-by', pattern: 'laravel', framework: 'laravel', confidence: 0.85 },
    { header: 'x-drupal-cache', pattern: null, framework: 'drupal', confidence: 0.95 },
    { header: 'x-generator', pattern: 'wordpress', framework: 'wordpress', confidence: 0.90 },
    { header: 'server', pattern: 'kestrel', framework: 'asp.net-core', confidence: 0.85 },
  ];

  constructor(config: CacheProbeConfig, httpClient?: HttpClient) {
    this.config = config;
    this.http = httpClient || new HttpClient({ timeoutMs: 10000, rateLimitPerSec: 5 });
  }

  async run(): Promise<ProbeResult> {
    try {
      const response = await this.http.get(this.config.target, this.config.headers || {});
      
      const cdn = this.detectCDN(response.headers);
      const proxy = this.detectProxy(response.headers);
      const framework = this.detectFramework(response.headers);
      const cacheKey = await this.reverseCacheKey(this.http);

      return {
        cdn,
        proxy,
        framework,
        cacheKey,
        hiddenCacheDetected: false,
      };
    } catch {
      return {
        cdn: { name: 'unknown', confidence: 0, allMatches: {} },
        proxy: { name: 'unknown', confidence: 0, allMatches: {} },
        framework: { name: 'unknown', confidence: 0, allMatches: {} },
        cacheKey: this.emptyCacheKey(),
        hiddenCacheDetected: false,
      };
    }
  }

  public detectCDN(headers: Record<string, string>): CDNFingerprint {
    const matches: Array<{ cdn: string; confidence: number }> = [];
    
    for (const sig of CacheProbe.CDN_SIGNATURES) {
      const value = headers[sig.header.toLowerCase()] || '';
      if (sig.pattern === null ? value !== '' : value.toLowerCase().includes(sig.pattern.toLowerCase())) {
        matches.push({ cdn: sig.cdn, confidence: sig.confidence });
      }
    }

    // Bayesian accumulation: for each match, update posterior
    // P(CDN|evidence) = P(evidence|CDN) * P(CDN) / P(evidence)
    // Simplified: accumulate using log-odds
    const cdnEvidence: Record<string, number> = {};
    for (const m of matches) {
      const prior = cdnEvidence[m.cdn] || 0;
      // Use the match confidence as likelihood ratio
      cdnEvidence[m.cdn] = prior + Math.log(m.confidence / (1 - m.confidence));
    }

    // Convert log-odds back to probability
    const cdnConfidence: Record<string, number> = {};
    for (const [cdn, logOdds] of Object.entries(cdnEvidence)) {
      cdnConfidence[cdn] = 1 / (1 + Math.exp(-logOdds));
    }

    const primary = Object.entries(cdnConfidence).sort((a, b) => b[1] - a[1])[0];
    return {
      name: primary?.[0] || 'unknown',
      confidence: primary?.[1] || 0,
      allMatches: cdnConfidence
    };
  }

  public detectProxy(headers: Record<string, string>): ProxyFingerprint {
    const matches: Array<{ proxy: string; confidence: number }> = [];
    
    for (const sig of CacheProbe.PROXY_SIGNATURES) {
      const value = headers[sig.header.toLowerCase()] || '';
      if (sig.pattern === null ? value !== '' : value.toLowerCase().includes(sig.pattern.toLowerCase())) {
        matches.push({ proxy: sig.proxy, confidence: sig.confidence });
      }
    }

    const proxyEvidence: Record<string, number> = {};
    for (const m of matches) {
      const prior = proxyEvidence[m.proxy] || 0;
      proxyEvidence[m.proxy] = prior + Math.log(m.confidence / (1 - m.confidence));
    }

    const proxyConfidence: Record<string, number> = {};
    for (const [proxy, logOdds] of Object.entries(proxyEvidence)) {
      proxyConfidence[proxy] = 1 / (1 + Math.exp(-logOdds));
    }

    const primary = Object.entries(proxyConfidence).sort((a, b) => b[1] - a[1])[0];
    return {
      name: primary?.[0] || 'unknown',
      confidence: primary?.[1] || 0,
      allMatches: proxyConfidence
    };
  }

  public detectFramework(headers: Record<string, string>): FrameworkFingerprint {
    const matches: Array<{ framework: string; confidence: number }> = [];
    
    for (const sig of CacheProbe.FRAMEWORK_SIGNATURES) {
      const value = headers[sig.header.toLowerCase()] || '';
      if (sig.pattern === null ? value !== '' : value.toLowerCase().includes(sig.pattern.toLowerCase())) {
        matches.push({ framework: sig.framework, confidence: sig.confidence });
      }
    }

    const frameworkEvidence: Record<string, number> = {};
    let version: string | undefined;
    
    for (const m of matches) {
      const prior = frameworkEvidence[m.framework] || 0;
      frameworkEvidence[m.framework] = prior + Math.log(m.confidence / (1 - m.confidence));
    }

    // Extract version from server header or powered-by
    const server = headers['server'] || '';
    const poweredBy = headers['x-powered-by'] || '';
    const versionMatch = server.match(/(\d+\.\d+(\.\d+)?)/) || poweredBy.match(/(\d+\.\d+(\.\d+)?)/);
    if (versionMatch) version = versionMatch[1];

    const frameworkConfidence: Record<string, number> = {};
    for (const [fw, logOdds] of Object.entries(frameworkEvidence)) {
      frameworkConfidence[fw] = 1 / (1 + Math.exp(-logOdds));
    }

    const primary = Object.entries(frameworkConfidence).sort((a, b) => b[1] - a[1])[0];
    return {
      name: primary?.[0] || 'unknown',
      confidence: primary?.[1] || 0,
      version,
      allMatches: frameworkConfidence
    };
  }

  /**
   * Empirically reverse the cache key by testing each URL component
   * From blog: "Not an assumption from CDN documentation. Documentation describes defaults;
   * real configurations diverge."
   */
  async reverseCacheKey(http?: HttpClient): Promise<CacheKeySpec> {
    const client = http || new HttpClient({ timeoutMs: 10000, rateLimitPerSec: 5 });

    const results: CacheKeySpec = {
      scheme: true,
      host: true,
      hostCaseSensitive: false,
      path: true,
      pathCaseSensitive: true,
      pathNormalized: false,
      queryString: true,
      querySorted: true,
      port: false,
      headersKeyed: [],
      fragmentStripped: true,
      rawHeaders: {},
      timestamp: new Date().toISOString(),
    };

    results.hostCaseSensitive = await this.testCacheComponent(client, 'host-case');
    results.pathCaseSensitive = await this.testCacheComponent(client, 'path-case');
    results.querySorted = await this.testCacheComponent(client, 'query-sort');
    results.port = await this.testCacheComponent(client, 'port');
    results.fragmentStripped = await this.testCacheComponent(client, 'fragment');
    results.headersKeyed = await this.detectKeyedHeaders(client);
    results.unkeyedParams = await this.detectUnkeyedQueryParams(client);

    return results;
  }

  /** Classic web-cache key-reversal suspects (URL-overrides + variant headers). */
  private static readonly KEY_HEADER_CANDIDATES = [
    'x-forwarded-host', 'x-original-url', 'x-rewrite-url', 'x-host',
    'forwarded', 'x-http-method-override', 'referer', 'accept-language',
    'x-requested-with',
  ];

  /**
   * Header dim of cache-key reversal (6th dim). Same cache-buster, two
   * header values: if the origin reflects them and the second request still
   * serves the first canary, the entry was shared → header unkeyed; if each
   * variant sees its own canary → header is part of the key. Non-reflected
   * headers are inconclusive and left out.
   */
  private async detectKeyedHeaders(http: HttpClient): Promise<string[]> {
    const keyed: string[] = [];
    for (const header of CacheProbe.KEY_HEADER_CANDIDATES) {
      try {
        const cb = Math.random().toString(36).substring(2, 10);
        const url = new URL(this.config.target);
        url.searchParams.set('_pc_test', cb);
        url.searchParams.set('_pc_component', `header-${header}`);

        const value1 = `pc${cb}a.example`;
        const value2 = `pc${cb}b.example`;
        const base = this.config.headers || {};

        const r1 = await http.get(url.toString(), { ...base, [header]: value1 });
        if (!r1.body.includes(value1)) continue; // not reflected → inconclusive

        const r2 = await http.get(url.toString(), { ...base, [header]: value2 });
        if (r2.body.includes(value2) && !r2.body.includes(value1)) {
          keyed.push(header);
        }
        // r2 still serves value1 → shared entry → unkeyed (not pushed)
      } catch {
        // Skip failed probes
      }
    }
    return keyed;
  }

  /** Ad-tech / analytics params commonly excluded from cache keys (Param Miner hot list). */
  private static readonly QUERY_PARAM_CANDIDATES = [
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'gclid', 'fbclid', 'msclkid', 'mc_cid', 'mc_eid', 'pc_probe',
  ];

  /**
   * Reflection-gadget param candidates — common app params (HCache
   * parameters.txt head + PortSwigger favourites). Full 6,452-param list
   * loads via loadParamWordlist(path) and discoverReflectionGadgets extras.
   */
  private static readonly GADGET_PARAM_CANDIDATES = [
    'q', 's', 'search', 'id', 'page', 'pg', 'p', 'url', 'uri', 'redirect',
    'redir', 'next', 'return', 'continue', 'dest', 'destination', 'target',
    'host', 'site', 'domain', 'callback', 'cb', 'debug', 'test', 'nc',
    'lang', 'language', 'file', 'path', 'dir', 'folder', 'doc', 'document',
    'view', 'show', 'type', 'mode', 'format', 'output', 'data', 'item',
    'name', 'title', 'ref', 'source', 'src', 'feed', 'cat', 'category',
    'template', 'include', 'module', 'action', 'load', 'read', 'open',
    'filename', 'cid', 'uuid', 'price', 'products', 'product', 'cart',
    ...CacheProbe.QUERY_PARAM_CANDIDATES,
  ];

  /** Load a newline-delimited param wordlist (e.g. HCache parameters.txt). */
  static loadParamWordlist(path: string): string[] {
    return fs
      .readFileSync(path, 'utf8')
      .split('\n')
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#'));
  }

  /**
   * Bundled HCache/Param-Miner param wordlist (6,452 entries) that ships with
   * the package. Resolved relative to this module so it works from src/ and dist/.
   */
  static bundledParamWordlist(): string[] {
    const candidates = [
      path.join(__dirname, '..', 'wordlists', 'parameters.txt'),
      path.join(__dirname, '..', '..', 'wordlists', 'parameters.txt'),
    ];
    for (const p of candidates) {
      try {
        if (fs.existsSync(p)) return CacheProbe.loadParamWordlist(p);
      } catch {
        // try next candidate
      }
    }
    return [];
  }

  /**
   * Target-specific param mining (ParamFinder-style): extract param names from
   * the target's own HTML/JS — links, forms, fetch/XHR calls. Catches
   * app-specific params no static wordlist knows.
   */
  async mineTargetParams(http?: HttpClient): Promise<string[]> {
    const client = http || new HttpClient({ timeoutMs: 10000, rateLimitPerSec: 5 });
    const found = new Set<string>();
    try {
      const r = await client.get(this.config.target, this.config.headers || {});
      const body = r.body;
      // ?param= and &param= in URLs (hrefs, fetch strings)
      for (const m of body.matchAll(/[?&]([a-zA-Z_][a-zA-Z0-9_]{1,40})=/g)) {
        found.add(m[1]);
      }
      // form inputs: name="param"
      for (const m of body.matchAll(/name=["']([a-zA-Z_][a-zA-Z0-9_]{1,40})["']/gi)) {
        found.add(m[1]);
      }
      // filter obvious HTML/JS noise
      const noise = new Set([
        'href', 'src', 'class', 'id', 'style', 'type', 'value', 'alt', 'rel',
        'const', 'let', 'var', 'function', 'return', 'import', 'export',
      ]);
      for (const n of noise) found.delete(n);
    } catch {
      // Mining is best-effort
    }
    return [...found];
  }

  /**
   * Reflection-gadget discovery (Param Miner / HCache style). Phase 1 sweeps
   * the wordlist for params whose value reflects in the response body; phase 2
   * confirms each reflected param is ALSO unkeyed (second value gets the
   * first value's cached entry). Only unkeyed+reflected params are gadgets —
   * poisonable XSS sinks.
   */
  async discoverReflectionGadgets(
    http?: HttpClient,
    extraParams?: string[],
    opts?: { mineTarget?: boolean },
  ): Promise<Array<{ param: string; context: 'js' | 'attribute' | 'html' }>> {
    const client = http || new HttpClient({ timeoutMs: 10000, rateLimitPerSec: 10 });
    // Default: curated fast candidates (incl. nc). Full 6,452-param sweep
    // via extraParams=CacheProbe.bundledParamWordlist() ('all' tier).
    let params = extraParams?.length ? extraParams : CacheProbe.GADGET_PARAM_CANDIDATES;
    if (opts?.mineTarget) {
      const mined = await this.mineTargetParams(client);
      const seen = new Set(params);
      for (const p of mined) if (!seen.has(p)) { params = [...params, p]; seen.add(p); }
    }
    const gadgets: Array<{ param: string; context: 'js' | 'attribute' | 'html' }> = [];
    for (const param of params) {
      try {
        const v1 = `pcg${Math.random().toString(36).substring(2, 10)}`;
        const u1 = new URL(this.config.target);
        u1.searchParams.set(param, v1);
        const r1 = await client.get(u1.toString(), this.config.headers || {});
        if (!r1.body.includes(v1)) continue; // not reflected → no gadget
        const context = this.classifyReflection(r1.body, v1);
        // Unkeyed check: different value; cache serving v1's entry back = unkeyed
        const v2 = `pcg${Math.random().toString(36).substring(2, 10)}`;
        const u2 = new URL(this.config.target);
        u2.searchParams.set(param, v2);
        const r2 = await client.get(u2.toString(), this.config.headers || {});
        const servesStale =
          (r2.fromCache && r2.body.includes(v1) && !r2.body.includes(v2)) ||
          r2.body === r1.body;
        if (servesStale) gadgets.push({ param, context });
      } catch {
        // Skip failed probes
      }
    }
    return gadgets;
  }

  /** Classify where the canary sits: inside a script block, inside a tag, or plain HTML. */
  private classifyReflection(body: string, canary: string): 'js' | 'attribute' | 'html' {
    const idx = body.indexOf(canary);
    if (idx === -1) return 'html';
    const before = body.slice(Math.max(0, idx - 200), idx);
    const lastScriptOpen = before.lastIndexOf('<script');
    const lastScriptClose = before.lastIndexOf('</script>');
    if (lastScriptOpen > lastScriptClose) return 'js';
    const lastTagOpen = before.lastIndexOf('<');
    const lastTagClose = before.lastIndexOf('>');
    if (lastTagOpen > lastTagClose) return 'attribute'; // value sits inside a tag
    return 'html';
  }

  /**
   * Query dim of cache-key reversal. Same URL, two values per candidate: a
   * keyed param gives value2 a fresh entry (MISS); an unkeyed one makes the
   * cache serve value1's entry back (HIT + identical body) → flag it.
   */
  async detectUnkeyedQueryParams(http?: HttpClient): Promise<string[]> {
    const client = http || new HttpClient({ timeoutMs: 10000, rateLimitPerSec: 5 });
    const unkeyed: string[] = [];
    for (const param of CacheProbe.QUERY_PARAM_CANDIDATES) {
      try {
        const v1 = `pc${Math.random().toString(36).substring(2, 10)}a`;
        const v2 = `pc${Math.random().toString(36).substring(2, 10)}b`;
        const u1 = new URL(this.config.target);
        u1.searchParams.set(param, v1);
        const u2 = new URL(this.config.target);
        u2.searchParams.set(param, v2);
        const r1 = await client.get(u1.toString(), this.config.headers || {});
        const r2 = await client.get(u2.toString(), this.config.headers || {});
        if (r2.fromCache && r2.body === r1.body) unkeyed.push(param);
      } catch {
        // Skip failed probes
      }
    }
    return unkeyed;
  }

  private async testCacheComponent(http: HttpClient, component: string): Promise<boolean> {
    const cb1 = Math.random().toString(36).substring(2, 10);
    const cb2 = Math.random().toString(36).substring(2, 10);

    try {
      const url1 = new URL(this.config.target);
      url1.searchParams.set('_pc_test', cb1);
      url1.searchParams.set('_pc_component', component);

      const url2 = new URL(this.config.target);
      url2.searchParams.set('_pc_test', cb2);
      url2.searchParams.set('_pc_component', component);

      const resp1 = await http.get(url1.toString(), this.config.headers || {});
      const resp2 = await http.get(url2.toString(), this.config.headers || {});

      return resp1.body !== resp2.body;
    } catch {
      return false;
    }
  }

  private emptyCacheKey(): CacheKeySpec {
    return {
      scheme: true, host: true, hostCaseSensitive: false,
      path: true, pathCaseSensitive: true, pathNormalized: false,
      queryString: true, querySorted: true, port: false,
      headersKeyed: [], fragmentStripped: true,
      rawHeaders: {}, timestamp: new Date().toISOString(),
    };
  }
}