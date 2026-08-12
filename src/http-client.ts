import * as crypto from 'crypto';

export interface HttpConfig {
  timeoutMs: number;
  maxRetries: number;
  retryBaseMs: number;
  rateLimitPerSec: number;
  userAgent: string;
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
};

export class HttpClient {
  private config: HttpConfig;
  private cookies: CookieEntry[] = [];
  private requestCount = 0;
  private lastRequestTime = 0;

  constructor(config?: Partial<HttpConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  async get(url: string, headers?: Record<string, string>): Promise<HttpResponse> {
    return this.request('GET', url, headers);
  }

  async head(url: string, headers?: Record<string, string>): Promise<HttpResponse> {
    return this.request('HEAD', url, headers);
  }

  async request(
    method: string,
    url: string,
    headers?: Record<string, string>,
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
          signal: controller.signal,
        });
        clearTimeout(timeoutId);

        const body = method === 'HEAD' ? '' : await res.text();
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
          body,
          bodyHash: this.hash(body),
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
    const now = Date.now();
    const elapsed = now - this.lastRequestTime;

    if (elapsed < minInterval) {
      await this.sleep(minInterval - elapsed);
    }

    this.lastRequestTime = Date.now();
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
