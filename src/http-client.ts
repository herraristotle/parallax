import * as crypto from 'crypto';
import * as http2 from 'node:http2';

export interface HttpConfig {
  timeoutMs: number;
  maxRetries: number;
  retryBaseMs: number;
  rateLimitPerSec: number;
  userAgent: string;
  /** Route GETs through a persistent HTTP/2 session per origin (stdlib
   *  node:http2). Falls back to HTTP/1.1 fetch when the origin refuses h2. */
  http2?: boolean;
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  bodyHash: string;
  timingMs: number;
  fromCache: boolean;
}

interface CookieEntry {
  domain: string;
  cookie: string;
}

const DEFAULT_CONFIG: HttpConfig = {
  timeoutMs: 10000,
  maxRetries: 3,
  retryBaseMs: 1000,
  rateLimitPerSec: 10,
  userAgent: 'Parallax/1.0',
  http2: false,
};

export class HttpClient {
  private config: HttpConfig;
  private cookies: CookieEntry[] = [];
  private requestCount = 0;
  private lastRequestTime = 0;
  private rateChain: Promise<void> = Promise.resolve();
  private h2Sessions = new Map<string, http2.ClientHttp2Session>();

  constructor(config?: Partial<HttpConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  async get(url: string, headers?: Record<string, string>): Promise<HttpResponse> {
    if (this.config.http2) {
      try {
        const h2 = await this.h2Get(url, headers);
        if (h2) return h2;
      } catch (err) {
        // h2 failed after connect: drop session, fall back to HTTP/1.1
        const origin = `${new URL(url).protocol}//${new URL(url).host}`;
        this.h2Sessions.delete(origin);
        // pre-response failures fall back; post-response failures rethrow
        if (this.isPostResponseError(err)) throw err;
      }
    }
    return this.request('GET', url, headers);
  }

  private isPostResponseError(err: unknown): boolean {
    return err instanceof Error && err.message.startsWith('h2 post-response:');
  }

  /** Destroy all HTTP/2 sessions (shutdown / tests). */
  closeH2(): void {
    for (const session of this.h2Sessions.values()) {
      session.destroy();
    }
    this.h2Sessions.clear();
  }

  /**
   * GET over a shared h2 session for the URL's origin. Throws when h2 cannot
   * complete pre-response (caller falls back); marks post-response failures
   * so callers rethrow instead of double-fetching.
   */
  private async h2Get(url: string, headers?: Record<string, string>): Promise<HttpResponse> {
    const u = new URL(url);
    const origin = `${u.protocol}//${u.host}`;
    const session = await this.getH2Session(origin);

    await this.rateLimit();
    const start = Date.now();
    let started = false;
    try {
      const result = await new Promise<{ status: number; headers: Record<string, string>; body: string }>((resolve, reject) => {
        const req = session.request({
          ':path': `${u.pathname}${u.search}`,
          ':method': 'GET',
          'user-agent': this.config.userAgent,
          ...(headers || {}),
        });
        const timer = setTimeout(() => {
          req.close();
          reject(new Error(started ? 'h2 post-response: timeout' : 'h2 timeout'));
        }, this.config.timeoutMs);
        let status = 0;
        const respHeaders: Record<string, string> = {};
        let body = '';
        req.on('response', (h) => {
          started = true;
          status = Number(h[':status']) || 0;
          for (const [k, v] of Object.entries(h)) {
            if (!k.startsWith(':') && typeof v === 'string') respHeaders[k.toLowerCase()] = v;
          }
        });
        req.on('data', (chunk: Buffer) => { body += chunk.toString('utf8'); });
        req.on('end', () => {
          clearTimeout(timer);
          resolve({ status, headers: respHeaders, body });
        });
        req.on('error', (err) => {
          clearTimeout(timer);
          reject(new Error(started ? `h2 post-response: ${err.message}` : `h2: ${err.message}`));
        });
        req.end();
      });

      this.requestCount++;
      return {
        status: result.status,
        headers: result.headers,
        body: result.body,
        bodyHash: this.hash(result.body),
        timingMs: Date.now() - start,
        fromCache: this.detectCache(result.headers),
      };
    } catch (err) {
      if (session.destroyed || session.closed) this.h2Sessions.delete(origin);
      throw err;
    }
  }

  private getH2Session(origin: string): Promise<http2.ClientHttp2Session> {
    const existing = this.h2Sessions.get(origin);
    if (existing && !existing.destroyed && !existing.closed) {
      return Promise.resolve(existing);
    }
    return new Promise((resolve, reject) => {
      let settled = false;
      const session = http2.connect(origin);
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        session.destroy();
        this.h2Sessions.delete(origin);
        reject(new Error('h2 connect timeout'));
      }, Math.min(2000, this.config.timeoutMs));
      session.once('connect', () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.h2Sessions.set(origin, session);
        const drop = () => {
          if (this.h2Sessions.get(origin) === session) this.h2Sessions.delete(origin);
        };
        session.on('error', drop);
        session.on('close', drop);
        resolve(session);
      });
      session.once('error', (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.h2Sessions.delete(origin);
        reject(err);
      });
    });
  }

  async head(url: string, headers?: Record<string, string>): Promise<HttpResponse> {
    return this.request('HEAD', url, headers);
  }

  async request(
    method: string,
    url: string,
    headers?: Record<string, string>,
    body?: string,
  ): Promise<HttpResponse> {
    const mergedHeaders: Record<string, string> = {
      'user-agent': this.config.userAgent,
      ...headers,
    };

    const cookies = this.getCookies(url);
    if (cookies.length > 0) {
      mergedHeaders['cookie'] = cookies.join('; ');
    }

    let lastError: Error | undefined;
    for (let attempt = 0; attempt <= this.config.maxRetries; attempt++) {
      if (attempt > 0) {
        const backoffMs = this.config.retryBaseMs * Math.pow(2, attempt - 1);
        const jitter = Math.random() * backoffMs * 0.1;
        await this.sleep(backoffMs + jitter);
      }

      await this.rateLimit();

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.config.timeoutMs);

      const start = Date.now();
      try {
        const fetch = (await import('node-fetch')).default;
        const res = await fetch(url, {
          method,
          headers: mergedHeaders,
          body: body ?? null,
          signal: controller.signal,
        });
        clearTimeout(timeoutId);

        const responseBody = method === 'HEAD' ? '' : await res.text();
        const elapsed = Date.now() - start;
        this.requestCount++;

        const resHeaders: Record<string, string> = {};
        res.headers.forEach((value, key) => {
          resHeaders[key.toLowerCase()] = value;
        });

        const fromCache = this.detectCache(resHeaders);

        return {
          status: res.status,
          headers: resHeaders,
          body: responseBody,
          bodyHash: this.hash(responseBody),
          timingMs: elapsed,
          fromCache,
        };
      } catch (err) {
        clearTimeout(timeoutId);
        lastError = err instanceof Error ? err : new Error(String(err));
      }
    }

    throw lastError ?? new Error('Request failed after retries');
  }

  setCookie(cookie: string, urlOrDomain: string): void {
    let domain: string;
    try {
      domain = new URL(urlOrDomain).hostname;
    } catch {
      domain = urlOrDomain;
    }

    const existing = this.cookies.findIndex(
      (c) => c.domain === domain && c.cookie.split('=')[0] === cookie.split('=')[0],
    );
    if (existing >= 0) {
      this.cookies[existing].cookie = cookie;
    } else {
      this.cookies.push({ domain, cookie });
    }
  }

  getCookies(url: string): string[] {
    let domain: string;
    try {
      domain = new URL(url).hostname;
    } catch {
      return [];
    }

    return this.cookies
      .filter((c) => domain === c.domain || domain.endsWith('.' + c.domain))
      .map((c) => c.cookie);
  }

  getRequestCount(): number {
    return this.requestCount;
  }

  resetRequestCount(): void {
    this.requestCount = 0;
  }

  private detectCache(headers: Record<string, string>): boolean {
    if (headers['cf-cache-status'] && headers['cf-cache-status'].toLowerCase() === 'hit') {
      return true;
    }
    if (headers['x-cache'] && headers['x-cache'].toLowerCase().includes('hit')) {
      return true;
    }
    if (headers['x-varnish-cache'] && headers['x-varnish-cache'] !== '0') {
      return true;
    }
    const age = parseInt(headers['age'] ?? '0', 10);
    if (age > 0) {
      return true;
    }
    return false;
  }

  private hash(content: string): string {
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  private async rateLimit(): Promise<void> {
    if (this.config.rateLimitPerSec <= 0) return;

    const minInterval = 1000 / this.config.rateLimitPerSec;
    // Chain request starts so concurrent get() calls are spaced correctly
    // (check-then-sleep alone lets parallel callers fire as a burst).
    const prev = this.rateChain;
    let release!: () => void;
    this.rateChain = new Promise<void>((resolve) => { release = resolve; });
    await prev;
    try {
      const wait = this.lastRequestTime + minInterval - Date.now();
      if (wait > 0) await this.sleep(wait);
      this.lastRequestTime = Date.now();
    } finally {
      release();
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
