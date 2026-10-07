import { randomUUID, createHash } from 'crypto';

/**
 * Self-hosted interactsh OOB client (projectdiscovery/interactsh).
 *
 * Protocol: POST {server}/register with correlation-id, then poll
 * GET {server}/interactions?id&secret&token. Payloads are
 * `{random}.{correlationId}.{domain}` so the server can correlate
 * inbound callbacks to this session.
 *
 * Degrades to a disabled no-op when INTERACTSH_SERVER/DOMAIN are
 * unset or register() fails — scans continue without OOB evidence.
 */
export interface OobConfig {
  server: string;
  domain: string;
  token?: string;
}

export interface OobInteraction {
  protocol: string;
  remoteAddress: string;
  fullId?: string;
  rawRequest?: string;
}

/** Minimal fetch shape — injectable so tests never touch the network. */
export type FetchLike = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<{ ok: boolean; status: number; text(): Promise<string> }>;

export function oobConfigFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): OobConfig | null {
  const server = (env.INTERACTSH_SERVER || '').trim();
  const domain = (env.INTERACTSH_DOMAIN || '').trim();
  if (!server || !domain) return null;
  const token = (env.INTERACTSH_TOKEN || '').trim();
  return token ? { server, domain, token } : { server, domain };
}

export class InteractshClient {
  private config: OobConfig;
  private fetchFn: FetchLike;
  private correlationId = randomUUID();
  private secret = createHash('sha256').update(this.correlationId).digest('base64');
  private registered = false;
  private disabled = false;

  constructor(config: OobConfig, fetchFn?: FetchLike) {
    this.config = config;
    this.fetchFn = fetchFn ?? (async (url, init) => {
      const fetch = (await import('node-fetch')).default;
      return fetch(url, init) as unknown as ReturnType<FetchLike>;
    });
  }

  isReady(): boolean {
    return this.registered && !this.disabled;
  }

  /** POST /register. Any failure self-disables the client (no-ops after). */
  async register(): Promise<boolean> {
    if (this.disabled) return false;
    try {
      const res = await this.fetchFn(`${this.config.server}/register`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...(this.config.token ? { 'x-interactsh-token': this.config.token } : {}),
        },
        body: JSON.stringify({
          'correlation-id': this.correlationId,
          'secret-key': this.secret,
        }),
      });
      if (!res.ok) {
        this.disabled = true;
        return false;
      }
      await res.text().catch(() => '');
      this.registered = true;
      return true;
    } catch {
      this.disabled = true;
      return false;
    }
  }

  /** Next unique payload host: `{random}.{correlationId}.{domain}`. */
  nextPayload(): string {
    const label = randomUUID().replace(/-/g, '').slice(0, 13);
    return `${label}.${this.correlationId}.${this.config.domain}`;
  }

  /** Poll once; disabled/unregistered/failed → []. */
  async pollOnce(): Promise<OobInteraction[]> {
    if (!this.isReady()) return [];
    try {
      const params = new URLSearchParams({
        id: this.correlationId,
        secret: this.secret,
        ...(this.config.token ? { token: this.config.token } : {}),
      });
      const res = await this.fetchFn(`${this.config.server}/interactions?${params}`);
      if (!res.ok) return [];
      const body = await res.text();
      if (!body) return [];
      const parsed = JSON.parse(body) as { interactions?: unknown[]; data?: string[] };
      const raw = Array.isArray(parsed.interactions) ? parsed.interactions : [];
      const out: OobInteraction[] = [];
      for (const entry of raw) {
        if (typeof entry === 'string') {
          out.push({ protocol: 'http', remoteAddress: 'unknown', rawRequest: entry });
        } else if (entry && typeof entry === 'object') {
          const o = entry as Record<string, unknown>;
          out.push({
            protocol: String(o.protocol ?? 'http'),
            remoteAddress: String(o['remote-address'] ?? o.remoteAddress ?? 'unknown'),
            fullId: typeof o['full-id'] === 'string' ? o['full-id'] : undefined,
            rawRequest: typeof o['raw-request'] === 'string' ? o['raw-request'] : undefined,
          });
        }
      }
      return out;
    } catch {
      return [];
    }
  }

  /** Bounded poll loop; first interaction or null on timeout. */
  async waitForInteraction(
    timeoutMs = 10_000,
    intervalMs = 1_000,
  ): Promise<OobInteraction | null> {
    if (!this.isReady()) return null;
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const hits = await this.pollOnce();
      if (hits.length > 0) return hits[0];
      const wait = Math.min(intervalMs, Math.max(0, deadline - Date.now()));
      if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    }
    return null;
  }
}
