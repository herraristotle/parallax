import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { startDashboard, type DashboardHandle } from '../dashboard-server';
import { Logger } from '../logger';

function fixture(evilEvidence?: string): any {
  return {
    probe: { cdn: { name: 'Cloudflare', confidence: 0.9 }, proxy: {}, framework: { name: 'None' }, cacheKey: {}, hiddenCacheDetected: false },
    discover: {
      cachedUrls: [{ url: 'https://a.test/page', cacheStatus: 'HIT', cacheHeaders: {}, isTargetUrl: true }],
      uncacheableUrls: [], totalTested: 1,
    },
    diff: [], poison: [{
      findings: [{ inputType: 'header', inputName: 'X-Forwarded-Host', canary: 'c1', classification: 'xss', confidence: 'CONFIRMED' }],
      statistics: {},
    }],
    weaponize: [],
    internal: evilEvidence ? [{ url: 'https://a.test/page', signal: 'esi_transform', evidence: evilEvidence, confidence: 'LIKELY' }] : [],
    deception: [],
  };
}

describe('dashboard-server', () => {
  let handle: DashboardHandle | null = null;
  let dir = '';

  const boot = async (overrides: Record<string, unknown> = {}) => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'px-dash-'));
    handle = await startDashboard({
      outputDir: dir, port: 0, pollMs: 30, heartbeatMs: 60000,
      logger: undefined, ...overrides,
    });
    return handle;
  };

  afterEach(async () => {
    if (handle) await handle.close();
    handle = null;
    if (dir) { fs.rmSync(dir, { recursive: true, force: true }); dir = ''; }
  });

  const ID = 'parallax-report-1760000000000';
  const write = (id: string, data: unknown) => fs.writeFileSync(path.join(dir, `${id}.json`), JSON.stringify(data));

  it('serves shell at / and healthz counts reports', async () => {
    const h = await boot();
    const shell = await fetch(h.url + '/');
    expect(shell.status).toBe(200);
    expect(shell.headers.get('content-type')).toContain('text/html');
    const body = await shell.text();
    expect(body).toContain("new EventSource('/events')");
    expect(body).toContain('src="/vendor/htmx.min.js"');

    let health = await (await fetch(h.url + '/healthz')).json();
    expect(health).toEqual({ ok: true, reports: 0 });
    write(ID, fixture());
    health = await (await fetch(h.url + '/healthz')).json();
    expect(health).toEqual({ ok: true, reports: 1 });
  });

  it('serves vendor htmx with javascript content type', async () => {
    const h = await boot();
    const res = await fetch(h.url + '/vendor/htmx.min.js');
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('javascript');
    expect(await res.text()).toContain('htmx');
  });

  it('/api/reports summarizes files, excludes junk names and torn JSON', async () => {
    const h = await boot();
    write(ID, fixture());
    fs.writeFileSync(path.join(dir, 'not-a-report.json'), '{torn');
    const list = await (await fetch(h.url + '/api/reports')).json();
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ id: ID, target: 'https://a.test/page', cdn: 'Cloudflare', total: 1 });
    // torn file rewritten validly → appears (Review Focus #1)
    write(ID, fixture());
    expect((await (await fetch(h.url + '/api/reports')).json())).toHaveLength(1);
  });

  it('/api/report id validation: traversal 404, missing 422, valid 200', async () => {
    const h = await boot();
    expect((await fetch(`${h.url}/api/report?id=${encodeURIComponent('../../secrets')}`)).status).toBe(404);
    expect((await fetch(`${h.url}/api/report?id=parallax-report-999`)).status).toBe(422);
    write(ID, fixture());
    const res = await fetch(`${h.url}/api/report?id=${ID}`);
    expect(res.status).toBe(200);
    expect((await res.json()).probe.cdn.name).toBe('Cloudflare');
  });

  it('/api/findings filters and raw JSON keeps payload intact', async () => {
    const h = await boot();
    write(ID, fixture('<script>alert(1)</script>'));
    const all = await (await fetch(h.url + '/api/findings')).json();
    expect(all).toHaveLength(2); // poison + internal
    const poison = await (await fetch(h.url + '/api/findings?source=poison')).json();
    expect(poison).toHaveLength(1);
    expect(poison[0].source).toBe('poison');
    // JSON route stays raw (Review Focus #2: escape belongs to HTML partials)
    expect(poison[0].evidence).toContain('X-Forwarded-Host');
  });

  it('HTML partials escape attacker-controlled evidence (Review Focus #2)', async () => {
    const h = await boot();
    write(ID, fixture('<script>alert(1)</script>'));
    const table = await (await fetch(`${h.url}/partials/table`)).text();
    expect(table).not.toContain('<script>alert(1)');
    expect(table).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('partial routes validate ids: detail traversal 404, torn file friendly retry, unknown finding 404', async () => {
    const h = await boot();
    expect((await fetch(`${h.url}/partials/detail?id=${encodeURIComponent('../x')}`)).status).toBe(404);
    fs.writeFileSync(path.join(dir, 'parallax-report-111.json'), '{broken');
    const retry = await fetch(`${h.url}/partials/detail?id=parallax-report-111`);
    expect(retry.status).toBe(422);
    expect(await retry.text()).toContain('not ready');
    write(ID, fixture());
    expect((await fetch(`${h.url}/partials/finding?report=${ID}&fid=nope`)).status).toBe(404);
    const list = await fetch(`${h.url}/partials/list`);
    expect(list.status).toBe(200);
    expect(await list.text()).toContain('/partials/detail?id=');
  });

  it('non-GET methods and unknown paths 404; handler throw → 500, process stays alive', async () => {
    const h = await boot();
    expect((await fetch(h.url + '/nope')).status).toBe(404);
    expect((await fetch(h.url + '/healthz', { method: 'POST' })).status).toBe(404);
    // absolute-form target `http://[` makes new URL() throw at route entry → caught → 500 JSON
    // (fetch normalizes paths, so use raw http.request; controller-probed on Node v24.6.0)
    const raw = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      const r = http.request({ host: '127.0.0.1', port: h.port, path: 'http://[', method: 'GET' }, res => {
        let b = '';
        res.on('data', c => { b += c; });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: b }));
      });
      r.on('error', reject);
      r.end();
    });
    expect(raw.status).toBe(500);
    expect(raw.body).toContain('internal error');
    // process never crashed — healthz still serves
    expect((await fetch(h.url + '/healthz')).status).toBe(200);
  });

  it('close() releases the port (second start on same port works)', async () => {
    const h = await boot({ port: 0 });
    const port = h.port;
    await h.close();
    handle = null;
    await expect(startDashboard({ outputDir: dir, port })).resolves.toBeDefined();
  });

  it('startup log carries the effective poll interval', async () => {
    const logger = new Logger('dashboard', 'debug');
    await boot({ pollMs: 250, logger });
    const entry = logger.getEntries().find(e => e.message.includes('dashboard listening'));
    expect(entry?.message).toContain('poll 250ms');
  });

  it('logs report-added at debug and never logs scan-event frames', async () => {
    const logger = new Logger('dashboard', 'debug');
    const h = await boot({ logger });
    fs.writeFileSync(path.join(dir, 'parallax-report-600.json'), JSON.stringify(fixture()));
    await new Promise(r => setTimeout(r, 200));
    expect(logger.getEntries().some(e => e.level === 'debug' && e.message === 'event: report-added')).toBe(true);
    expect(logger.getEntries().some(e => e.message.includes('scan-event'))).toBe(false);
    expect((await fetch(h.url + '/healthz')).status).toBe(200);
  });
});