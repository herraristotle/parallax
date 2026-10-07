import { randomBytes } from 'crypto';
import { HttpClient } from './http-client';
import type { InteractshClient } from './oob';

export interface InternalCacheConfig {
  target: string;
  cookie?: string;
  headers?: Record<string, string>;
}

export interface InternalCacheFinding {
  url: string;
  parameter?: string;
  signal: 'esi_transform' | 'keyless_cross_serve' | 'esi_header';
  evidence: string;
  confidence: 'CONFIRMED' | 'LIKELY' | 'POSSIBLE';
  /** ESI src pointed at the OOB host and a callback arrived — edge fetched it. */
  oobConfirmed?: boolean;
}

/**
 * Standard published ESI syntax — detection only: an edge that transforms
 * this tag processes ESI; an edge that fetches src confirms server-side.
 */
const ESI_TAG_PREFIX = '<esi:include src="';

/** ESI/edge layer response headers (Kettle internal-cache recognition). */
const ESI_HEADERS = ['surrogate-control', 'x-cache-layer', 'x-esi', 'x-served-by'];

/** Reflection candidates probed in order; first hit wins (bounded requests). */
const PROBE_PARAMS = ['q', 's', 'search', 'name', 'url', 'lang', 'page', 'ref'];

function marker(): string {
  return `kettle${randomBytes(6).toString('hex')}`;
}

function withParams(target: string, params: Record<string, string>): string {
  const url = new URL(target);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  return url.toString();
}

/**
 * Kettle internal cache / ESI detection (web-cache-entanglement,
 * §Internal Cache Poisoning + §5.1).
 *
 * Heuristics (body/header-based; OOB paths optional):
 *  - ESI transform: a reflected param receives an <esi:include> tag; the
 *    edge consuming/rewriting the tag (instead of echoing it) proves an ESI
 *    processor. With interactsh, src pointing at the OOB host and a
 *    callback proves the edge fetched it server-side.
 *  - Keyless cross-serve: two requests differing only in cache-buster get
 *    identical bodies where each marker must differ — a keyless internal
 *    cache served one request's response to the other.
 *  - ESI headers: surrogate-control / x-cache-layer / x-esi / x-served-by
 *    presence.
 */
export class CacheInternal {
  private config: InternalCacheConfig;
  private http: HttpClient;
  private oob: InteractshClient | null;

  constructor(config: InternalCacheConfig, httpClient?: HttpClient, oob?: InteractshClient | null) {
    this.config = config;
    this.http = httpClient || new HttpClient({ timeoutMs: 10000, rateLimitPerSec: 5 });
    this.oob = oob ?? null;
  }

  async run(): Promise<InternalCacheFinding[]> {
    const findings: InternalCacheFinding[] = [];
    const headers = this.config.headers || {};

    const param = await this.findReflectedParam(headers);
    if (!param) return findings; // no reflection surface — bounded

    findings.push(...await this.testEsiTransform(param, headers));
    findings.push(...await this.testKeylessCrossServe(param, headers));
    findings.push(...await this.collectEsiHeaders(headers));
    return findings;
  }

  /** First query param that echoes a marker into the body; null → run() stops. */
  async findReflectedParam(headers: Record<string, string>): Promise<string | null> {
    for (const name of PROBE_PARAMS) {
      const probe = marker();
      try {
        const resp = await this.http.get(withParams(this.config.target, { [name]: probe }), headers);
        if (resp.status < 400 && resp.body.includes(probe)) return name;
      } catch {
        continue;
      }
    }
    return null;
  }

  async testEsiTransform(param: string, headers: Record<string, string>): Promise<InternalCacheFinding[]> {
    const findings: InternalCacheFinding[] = [];
    const canary = marker();
    const useOob = this.oob?.isReady() === true;
    const src = useOob ? `http://${this.oob!.nextPayload()}` : `http://esi-internal.invalid/${canary}`;
    const payload = `${ESI_TAG_PREFIX}${src}"></esi:include>${canary}`;

    let resp: { body: string };
    try {
      resp = await this.http.get(withParams(this.config.target, { [param]: payload }), headers);
    } catch {
      return findings;
    }

    // Echoed verbatim → no ESI processor touched it.
    if (resp.body.includes(ESI_TAG_PREFIX)) return findings;

    let oobConfirmed = false;
    if (useOob) {
      const hit = await this.oob!.waitForInteraction(10_000, 1_000);
      oobConfirmed = hit !== null;
    }

    findings.push({
      url: this.config.target,
      parameter: param,
      signal: 'esi_transform',
      evidence: `esi tag with src=${src} consumed/rewritten (marker ${canary} ${resp.body.includes(canary) ? 'reflected alongside' : 'not echoed'})`,
      confidence: oobConfirmed ? 'CONFIRMED' : 'LIKELY',
      oobConfirmed: oobConfirmed || undefined,
    });
    return findings;
  }

  /**
   * Two requests differing only in param marker + cache-buster: each response
   * must echo its own marker. Identical served bodies → keyless cache
   * cross-served request 1's response to request 2.
   */
  async testKeylessCrossServe(param: string, headers: Record<string, string>): Promise<InternalCacheFinding[]> {
    const m1 = marker();
    const m2 = marker();
    const buster = Date.now();
    try {
      const r1 = await this.http.get(
        withParams(this.config.target, { [param]: m1, _cb: String(buster) }), headers);
      const r2 = await this.http.get(
        withParams(this.config.target, { [param]: m2, _cb: String(buster + 1) }), headers);
      if (r1.status >= 400 || r2.status >= 400) return [];
      // Both echoed their own marker → normal behavior.
      if (r2.body.includes(m2)) return [];
      // r2 got r1's body (or any body lacking m2 but present for m1).
      if (r1.body.includes(m1) && r1.body === r2.body) {
        return [{
          url: this.config.target,
          parameter: param,
          signal: 'keyless_cross_serve',
          evidence: `cache-busted request with marker ${m2} received cached body carrying ${m1}`,
          confidence: 'CONFIRMED',
        }];
      }
      // r2 missing its marker without matching r1 — weaker signal.
      if (r1.body.includes(m1) && !r2.body.includes(m2)) {
        return [{
          url: this.config.target,
          parameter: param,
          signal: 'keyless_cross_serve',
          evidence: `marker ${m2} absent from response while ${m1} reflected — possible keyless keying`,
          confidence: 'LIKELY',
        }];
      }
    } catch {
      return [];
    }
    return [];
  }

  async collectEsiHeaders(headers: Record<string, string>): Promise<InternalCacheFinding[]> {
    try {
      const resp = await this.http.get(this.config.target, headers);
      const found = CacheInternal.headerFinding(this.config.target, resp.headers);
      return found ? [found] : [];
    } catch {
      return [];
    }
  }

  /** Evidence from a response's headers → esi_header finding. */
  static headerFinding(url: string, respHeaders: Record<string, string>): InternalCacheFinding | null {
    const present = ESI_HEADERS.filter((h) => respHeaders[h] !== undefined);
    if (present.length === 0) return null;
    return {
      url,
      signal: 'esi_header',
      evidence: present.map((h) => `${h}: ${respHeaders[h]}`).join('; '),
      confidence: 'POSSIBLE',
    };
  }
}
