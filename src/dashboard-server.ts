import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import type { AddressInfo } from 'net';
import { Logger } from './logger';
import {
  flattenFindings, summarizeReport, isSafeReportId, filterFindings,
  type DashFinding, type ReportSummary,
} from './dashboard-findings';
import { createReportWatcher } from './dashboard-watch';
import { createNdjsonTail } from './dashboard-tail';
import {
  shellHtml, listPartial, tablePartial, detailPartial, findingPartial, feedPartial,
  type FeedItem,
} from './dashboard-ui';

export interface DashboardOptions {
  outputDir: string;
  /** Default 7700; pass 0 for an ephemeral port (tests). */
  port?: number;
  /** Default 127.0.0.1 — the security boundary. */
  host?: string;
  /** Watcher poll interval ms, default 1000. */
  pollMs?: number;
  /** Max concurrent SSE clients, default 32 (429 beyond). */
  maxSseClients?: number;
  /** SSE heartbeat ms, default 25000. */
  heartbeatMs?: number;
  logger?: Logger;
}

export interface DashboardHandle {
  url: string;
  port: number;
  close(): Promise<void>;
}

export async function startDashboard(opts: DashboardOptions): Promise<DashboardHandle> {
  const host = opts.host ?? '127.0.0.1';
  const port = opts.port ?? 7700;
  const maxSse = opts.maxSseClients ?? 32;
  const heartbeatMs = opts.heartbeatMs ?? 25000;
  const log = opts.logger ?? new Logger('dashboard', 'info');
  const outDir = opts.outputDir;
  const feed: FeedItem[] = [];
  const sseClients = new Set<http.ServerResponse>();

  const listIds = (): string[] => {
    try {
      return fs.readdirSync(outDir)
        .filter(n => n.endsWith('.json') && isSafeReportId(n.slice(0, -5)))
        .map(n => n.slice(0, -5));
    } catch {
      return []; // dir missing — empty, not an error
    }
  };

  const readReport = (id: string): unknown =>
    JSON.parse(fs.readFileSync(path.join(outDir, `${id}.json`), 'utf8'));

  const summaries = (): ReportSummary[] => {
    const out: ReportSummary[] = [];
    for (const id of listIds()) {
      try { out.push(summarizeReport(id, readReport(id))); } catch { /* torn JSON — skip */ }
    }
    return out.sort((a, b) => b.ts - a.ts);
  };

  const allFindings = (): DashFinding[] => {
    const out: DashFinding[] = [];
    for (const id of listIds()) {
      try { out.push(...flattenFindings(id, readReport(id))); } catch { /* torn — skip */ }
    }
    return out;
  };

  const pushEvent = (name: string, data: Record<string, unknown>): void => {
    // Report-change events are debug-level chatter; scan-event frames are not logged here.
    if (name !== 'scan-event') log.debug(`event: ${name}`, { id: String(data.id ?? '') });
    feed.push({ name, data, ts: Date.now() });
    if (feed.length > 100) feed.shift();
    const frame = `event: ${name}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const res of sseClients) {
      try { res.write(frame); } catch { sseClients.delete(res); }
    }
  };

  const json = (res: http.ServerResponse, code: number, body: unknown): void => {
    res.writeHead(code, { 'content-type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(body));
  };
  const html = (res: http.ServerResponse, code: number, body: string): void => {
    res.writeHead(code, { 'content-type': 'text/html; charset=utf-8' });
    res.end(body);
  };
  const notFound = (res: http.ServerResponse): void => json(res, 404, { error: 'not found' });

  const vendorPath = (): string | null => {
    const candidates = [
      path.join(__dirname, 'vendor', 'htmx.min.js'),           // running from src (vitest)
      path.join(__dirname, '..', 'src', 'vendor', 'htmx.min.js'), // running from dist
    ];
    return candidates.find(c => fs.existsSync(c)) ?? null;
  };

  const route = (req: http.IncomingMessage, res: http.ServerResponse): void => {
    const url = new URL(req.url ?? '/', `http://${host}`);
    const p = url.pathname;

    if (req.method !== 'GET') { notFound(res); return; }

    if (p === '/') { html(res, 200, shellHtml()); return; }

    if (p === '/healthz') {
      json(res, 200, { ok: true, reports: listIds().length });
      return;
    }

    if (p === '/vendor/htmx.min.js') {
      const vp = vendorPath();
      if (!vp) { notFound(res); return; }
      res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' });
      res.end(fs.readFileSync(vp));
      return;
    }

    if (p === '/api/reports') { json(res, 200, summaries()); return; }

    if (p === '/api/report') {
      const id = url.searchParams.get('id') ?? '';
      if (!isSafeReportId(id)) { notFound(res); return; }
      try { json(res, 200, readReport(id)); }
      catch { json(res, 422, { error: 'report not ready' }); }
      return;
    }

    if (p === '/api/findings') { json(res, 200, filterFindings(allFindings(), url.searchParams)); return; }

    if (p === '/partials/list') { html(res, 200, listPartial(summaries())); return; }

    if (p === '/partials/table') { html(res, 200, tablePartial(filterFindings(allFindings(), url.searchParams))); return; }

    if (p === '/partials/detail') {
      const id = url.searchParams.get('id') ?? '';
      if (!isSafeReportId(id)) { notFound(res); return; }
      try {
        const raw = readReport(id);
        html(res, 200, detailPartial(summarizeReport(id, raw), flattenFindings(id, raw), raw));
      } catch {
        html(res, 422, '<div class="empty">Report not ready — retrying&hellip;</div>');
      }
      return;
    }

    if (p === '/partials/finding') {
      const id = url.searchParams.get('report') ?? '';
      const fid = url.searchParams.get('fid') ?? '';
      if (!isSafeReportId(id)) { notFound(res); return; }
      let row: DashFinding | undefined;
      try { row = flattenFindings(id, readReport(id)).find(r => r.id === fid); }
      catch { row = undefined; }
      if (!row) { notFound(res); return; }
      html(res, 200, findingPartial(row));
      return;
    }

    if (p === '/partials/feed') { html(res, 200, feedPartial(feed)); return; }

    if (p === '/events') {
      if (sseClients.size >= maxSse) { json(res, 429, { error: 'too many sse clients' }); return; }
      res.writeHead(200, {
        'content-type': 'text/event-stream',
        'cache-control': 'no-cache',
        connection: 'keep-alive',
      });
      res.setTimeout(0); // exempt SSE from request timeout
      sseClients.add(res);
      try { res.write(': connected\n\n'); } catch { /* client already gone */ }
      const drop = (): void => { sseClients.delete(res); };
      res.on('close', drop);
      res.on('error', drop);
      return;
    }

    notFound(res);
  };

  const server = http.createServer((req, res) => {
    try {
      route(req, res);
    } catch (err) {
      log.error(`dashboard route error: ${String(err)}`);
      if (!res.headersSent) json(res, 500, { error: 'internal error' });
      else res.end();
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve());
  }).catch((err: NodeJS.ErrnoException) => {
    throw new Error(`dashboard failed to bind ${host}:${port}: ${err.code ?? err.message}`);
  });

  const actualPort = (server.address() as AddressInfo).port;

  const pollMs = opts.pollMs ?? 1000;
  const watcher = createReportWatcher({
    dir: outDir,
    intervalMs: pollMs,
    logger: log,
    onEvent: ev => pushEvent(ev.type, { id: ev.id, ts: ev.ts }),
  });

  const tail = createNdjsonTail({
    file: path.join(outDir, 'scan-events.ndjson'),
    intervalMs: pollMs,
    onEvent: ev => pushEvent('scan-event', { ts: ev.ts, stage: ev.stage, detail: ev.detail }),
  });

  const heartbeat = setInterval(() => {
    for (const res of sseClients) {
      try { res.write(': hb\n\n'); } catch { /* client gone — close handler cleans up */ }
    }
  }, heartbeatMs);

  log.info(`dashboard listening on ${`http://${host}:${actualPort}`} (watching ${outDir}, poll ${pollMs}ms)`);

  let closed = false;
  const close = async (): Promise<void> => {
    if (closed) return;
    closed = true;
    watcher.stop();
    tail.stop();
    clearInterval(heartbeat);
    for (const res of sseClients) { try { res.end(); } catch { /* ignore */ } }
    sseClients.clear();
    await new Promise<void>(resolve => {
      server.close(() => resolve());
      server.closeAllConnections?.();
    });
  };

  return { url: `http://${host}:${actualPort}`, port: actualPort, close };
}