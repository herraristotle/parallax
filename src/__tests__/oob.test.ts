import { describe, it, expect } from 'vitest';
import { InteractshClient, oobConfigFromEnv, type FetchLike } from '../oob';

function jsonResponse(body: string, ok = true, status = 200) {
  return { ok, status, text: async () => body };
}

function stubFetch(handler: (url: string, init?: { method?: string; body?: string }) => ReturnType<FetchLike> extends Promise<infer R> ? R : never): FetchLike {
  return async (url, init) => handler(url, init) as Awaited<ReturnType<FetchLike>>;
}

const CONFIG = { server: 'https://oast.example', domain: 'oast.example' };

describe('oobConfigFromEnv', () => {
  it('returns null when server or domain missing', () => {
    expect(oobConfigFromEnv({} as NodeJS.ProcessEnv)).toBeNull();
    expect(oobConfigFromEnv({ INTERACTSH_SERVER: 'https://x' } as NodeJS.ProcessEnv)).toBeNull();
    expect(oobConfigFromEnv({ INTERACTSH_DOMAIN: 'x.example' } as NodeJS.ProcessEnv)).toBeNull();
    expect(
      oobConfigFromEnv({ INTERACTSH_SERVER: '  ', INTERACTSH_DOMAIN: 'x.example' } as NodeJS.ProcessEnv),
    ).toBeNull();
  });

  it('returns config with token when all three set', () => {
    const cfg = oobConfigFromEnv({
      INTERACTSH_SERVER: 'https://oast.example',
      INTERACTSH_DOMAIN: 'oast.example',
      INTERACTSH_TOKEN: 'sekrit',
    } as NodeJS.ProcessEnv);
    expect(cfg).toEqual({ server: 'https://oast.example', domain: 'oast.example', token: 'sekrit' });
  });

  it('omits empty token', () => {
    const cfg = oobConfigFromEnv({
      INTERACTSH_SERVER: 'https://oast.example',
      INTERACTSH_DOMAIN: 'oast.example',
      INTERACTSH_TOKEN: '',
    } as NodeJS.ProcessEnv);
    expect(cfg).not.toHaveProperty('token');
  });
});

describe('InteractshClient', () => {
  it('register() posts correlation-id and becomes ready', async () => {
    let registeredBody = '';
    const client = new InteractshClient(CONFIG, stubFetch((url, init) => {
      expect(url).toBe('https://oast.example/register');
      expect(init?.method).toBe('POST');
      registeredBody = init?.body ?? '';
      return jsonResponse('{}');
    }));
    expect(await client.register()).toBe(true);
    expect(client.isReady()).toBe(true);
    const parsed = JSON.parse(registeredBody);
    expect(typeof parsed['correlation-id']).toBe('string');
    expect(parsed['correlation-id'].length).toBeGreaterThan(0);
  });

  it('register() failure self-disables; poll/wait become no-ops', async () => {
    const client = new InteractshClient(CONFIG, stubFetch(() => jsonResponse('nope', false, 403)));
    expect(await client.register()).toBe(false);
    expect(client.isReady()).toBe(false);
    expect(await client.pollOnce()).toEqual([]);
    expect(await client.waitForInteraction(50, 10)).toBeNull();
    // Second register attempt stays disabled without another fetch.
    expect(await client.register()).toBe(false);
  });

  it('register() network throw disables instead of propagating', async () => {
    const client = new InteractshClient(CONFIG, async () => {
      throw new Error('ECONNREFUSED');
    });
    expect(await client.register()).toBe(false);
    expect(client.isReady()).toBe(false);
  });

  it('nextPayload() matches {label}.{correlationId}.{domain}', async () => {
    const client = new InteractshClient(CONFIG, stubFetch(() => jsonResponse('{}')));
    await client.register();
    const payload = client.nextPayload();
    expect(payload).toMatch(/^[0-9a-f]{13}\.[0-9a-f-]{36}\.oast\.example$/);
    // Unique per call, stable correlation segment.
    const second = client.nextPayload();
    expect(second).not.toBe(payload);
    expect(second.split('.')[1]).toBe(payload.split('.')[1]);
  });

  it('pollOnce() builds interactions URL with id + secret and parses entries', async () => {
    let pollUrl = '';
    const client = new InteractshClient(CONFIG, stubFetch((url) => {
      if (url.endsWith('/register')) return jsonResponse('{}');
      pollUrl = url;
      return jsonResponse(JSON.stringify({
        interactions: [
          { protocol: 'dns', 'remote-address': '1.2.3.4', 'full-id': 'abc.oast.example' },
        ],
      }));
    }));
    await client.register();
    const hits = await client.pollOnce();
    const parsedUrl = new URL(pollUrl);
    expect(parsedUrl.pathname).toBe('/interactions');
    expect(parsedUrl.searchParams.get('id')).toBeTruthy();
    expect(parsedUrl.searchParams.get('secret')).toBeTruthy();
    expect(hits).toHaveLength(1);
    expect(hits[0].protocol).toBe('dns');
    expect(hits[0].remoteAddress).toBe('1.2.3.4');
  });

  it('waitForInteraction returns first hit within timeout', async () => {
    let polls = 0;
    const client = new InteractshClient(CONFIG, stubFetch((url) => {
      if (url.endsWith('/register')) return jsonResponse('{}');
      polls++;
      if (polls < 2) return jsonResponse('[]');
      return jsonResponse(JSON.stringify({ interactions: [{ protocol: 'http' }] }));
    }));
    await client.register();
    const hit = await client.waitForInteraction(2000, 10);
    expect(hit).not.toBeNull();
    expect(hit!.protocol).toBe('http');
  });

  it('waitForInteraction returns null on timeout', async () => {
    const client = new InteractshClient(CONFIG, stubFetch((url) => {
      if (url.endsWith('/register')) return jsonResponse('{}');
      return jsonResponse('[]');
    }));
    await client.register();
    expect(await client.waitForInteraction(50, 10)).toBeNull();
  });

  it('pollOnce handles malformed JSON without throwing', async () => {
    const client = new InteractshClient(CONFIG, stubFetch((url) => {
      if (url.endsWith('/register')) return jsonResponse('{}');
      return jsonResponse('not-json');
    }));
    await client.register();
    expect(await client.pollOnce()).toEqual([]);
  });
});
