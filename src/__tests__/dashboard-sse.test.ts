import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { startDashboard, type DashboardHandle } from '../dashboard-server';

const ID = 'parallax-report-1760000000001';
const REPORT = JSON.stringify({
  probe: { cdn: { name: 'Cloudflare', confidence: 0.9 }, proxy: {}, framework: { name: 'None' }, cacheKey: {}, hiddenCacheDetected: false },
  discover: { cachedUrls: [{ url: 'https://a.test/', cacheStatus: 'HIT', cacheHeaders: {}, isTargetUrl: true }], uncacheableUrls: [], totalTested: 1 },
  diff: [], poison: [], weaponize: [], internal: [], deception: [],
});

/** Read the SSE stream until `predicate` matches accumulated text or timeout. */
async function readSse(url: string, predicate: (s: string) => boolean, timeoutMs = 4000): Promise<string> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ac.signal });
    const reader = res.body!.getReader();
    const dec = new TextDecoder();
    let acc = '';
    while (!predicate(acc)) {
      const { done, value } = await reader.read();
      if (done) break;
      acc += dec.decode(value, { stream: true });
    }
    return acc;
  } finally {
    clearTimeout(timer);
    ac.abort();
  }
}

describe('dashboard SSE /events', () => {
  let handle: DashboardHandle | null = null;
  let dir = '';

  const boot = async (overrides: Record<string, unknown> = {}) => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'px-sse-'));
    handle = await startDashboard({
      outputDir: dir, port: 0, pollMs: 30, heartbeatMs: 80,
      ...overrides,
    });
    return handle;
  };

  afterEach(async () => {
    if (handle) await handle.close();
    handle = null;
    if (dir) { fs.rmSync(dir, { recursive: true, force: true }); dir = ''; }
  });

  it('streams report-added when a report file lands (Review Focus: watcher→SSE)', async () => {
    const h = await boot();
    // both watcher events must arrive on one connected stream: a *new* stream opened
    // after the writes cannot replay them (the route has no Last-Event-ID replay).
    const seen = readSse(h.url + '/events', s => s.includes('event: report-changed'));
    // give the stream a tick to connect before the write
    await new Promise(r => setTimeout(r, 50));
    fs.writeFileSync(path.join(dir, `${ID}.json`), REPORT);
    // let the poll watcher observe the add before mutating the file
    await new Promise(r => setTimeout(r, 200));
    // second write of same content but different size/mtime → report-changed (or add if watcher raced)
    fs.writeFileSync(path.join(dir, `${ID}.json`), REPORT + ' ');
    const text = await seen;
    expect(text).toContain('event: report-added');
    expect(text).toContain(`"id":"${ID}"`);
    expect(text).toMatch(/event: report-(added|changed)/);
  });

  it('opens with : connected comment', async () => {
    const h = await boot();
    const text = await readSse(h.url + '/events', s => s.includes(': connected'));
    expect(text).toContain(': connected');
  });

  it('emits heartbeat comments on injected interval', async () => {
    const h = await boot({ heartbeatMs: 50 });
    const text = await readSse(h.url + '/events', s => s.includes(': hb'), 3000);
    expect(text).toContain(': hb');
  });

  it('429 beyond maxSseClients (Review Focus: SSE flood)', async () => {
    const h = await boot({ maxSseClients: 2, heartbeatMs: 60000 });
    const ac1 = new AbortController();
    const ac2 = new AbortController();
    const r1 = fetch(h.url + '/events', { signal: ac1.signal });
    const r2 = fetch(h.url + '/events', { signal: ac2.signal });
    await Promise.all([r1, r2]); // both admitted (cap = 2)
    const third = await fetch(h.url + '/events');
    expect(third.status).toBe(429);
    ac1.abort(); ac2.abort();
  });

  it('close() ends open streams (fetch reader sees done)', async () => {
    const h = await boot();
    const ac = new AbortController();
    const res = await fetch(h.url + '/events', { signal: ac.signal });
    const reader = res.body!.getReader();
    await reader.read(); // consume ': connected'
    const port = h.port;
    await h.close();
    handle = null;
    // stream must terminate: next read resolves done (or aborts on socket close)
    const result = await Promise.race([
      reader.read().then(r => (r.done ? 'done' : 'data')),
      new Promise<string>(r => setTimeout(() => r('timeout'), 2000)),
    ]);
    expect(result).not.toBe('timeout');
    // port released
    await expect(startDashboard({ outputDir: dir, port })).resolves.toBeDefined();
    ac.abort();
  });
});