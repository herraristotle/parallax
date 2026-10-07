import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as net from 'node:net';
import { TraceSink } from '../trace';
import { HttpClient } from '../http-client';

const created: string[] = [];

function tmpTracePath(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'parallax-trace-'));
  created.push(dir);
  return path.join(dir, 'run.jsonl');
}

function readLines(file: string): Array<Record<string, unknown>> {
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map(l => JSON.parse(l) as Record<string, unknown>);
}

afterEach(() => {
  while (created.length) {
    fs.rmSync(created.pop()!, { recursive: true, force: true });
  }
});

describe('TraceSink', () => {
  it('writes NDJSON probe records carrying runId, stage and probe fields', () => {
    const file = tmpTracePath();
    const sink = new TraceSink(file);
    sink.setStage('discover');
    sink.probe({
      method: 'GET',
      url: 'https://example.com/page',
      status: 200,
      cacheStatus: 'HIT',
      latencyMs: 42,
      bodyHash: 'abc',
    });

    const lines = readLines(file);
    // setStage emits its own stage.start line; probe is the one after it
    const stageLine = lines.find(l => l.event === 'stage.start');
    expect(stageLine).toBeTruthy();
    expect(stageLine!.stage).toBe('discover');
    const probes = lines.filter(l => l.event === 'probe');
    expect(probes).toHaveLength(1);
    const rec = probes[0];
    expect(rec.event).toBe('probe');
    expect(rec.runId).toBe(sink.runId);
    expect(rec.stage).toBe('discover');
    expect(rec.method).toBe('GET');
    expect(rec.url).toBe('https://example.com/page');
    expect(rec.status).toBe(200);
    expect(rec.cacheStatus).toBe('HIT');
    expect(rec.latencyMs).toBe(42);
    expect(typeof rec.ts).toBe('string');
  });

  it('every line is independently parseable NDJSON', () => {
    const file = tmpTracePath();
    const sink = new TraceSink(file);
    sink.probe({ method: 'GET', url: 'https://a.test/1', status: 200, latencyMs: 1 });
    sink.event('stage.start', { stage: 'poison' });
    sink.probe({ method: 'GET', url: 'https://a.test/2', status: 301, latencyMs: 2 });

    const raw = fs.readFileSync(file, 'utf8').trim().split('\n');
    expect(raw).toHaveLength(3);
    for (const line of raw) expect(() => JSON.parse(line)).not.toThrow();
  });

  it('summary carries runId, duration, request and error counts, plus extras', () => {
    const file = tmpTracePath();
    const sink = new TraceSink(file);
    sink.probe({ method: 'GET', url: 'https://a.test/1', status: 200, latencyMs: 1 });
    sink.probe({ method: 'GET', url: 'https://a.test/2', status: 0, latencyMs: 1, error: 'timeout' });
    sink.summary({ findings: 3, tools: { katana: false, gau: false } });

    const lines = readLines(file);
    const summary = lines.find(l => l.event === 'run.summary');
    expect(summary).toBeTruthy();
    expect(summary!.runId).toBe(sink.runId);
    expect(summary!.requests).toBe(2);
    expect(summary!.errors).toBe(1);
    expect(typeof summary!.durationMs).toBe('number');
    expect((summary!.tools as Record<string, unknown>).katana).toBe(false);
    expect(summary!.findings).toBe(3);
  });
});

describe('HttpClient tracing', () => {
  let server: net.Server | undefined;
  afterEach(async () => { if (server) await new Promise<void>(r => server!.close(() => r())); server = undefined; });

  it('emits one probe record per completed request', async () => {
    server = net.createServer(socket => {
      socket.once('data', () => {
        socket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok');
      });
    });
    await new Promise<void>(r => server!.listen(0, '127.0.0.1', () => r()));
    const { port } = server.address() as net.AddressInfo;

    const file = tmpTracePath();
    const sink = new TraceSink(file);
    const client = new HttpClient({ timeoutMs: 5000, rateLimitPerSec: 0, maxRetries: 1, trace: sink });
    await client.get(`http://127.0.0.1:${port}/probe-me`);

    const probes = readLines(file).filter(l => l.event === 'probe');
    expect(probes).toHaveLength(1);
    expect(probes[0].url).toBe(`http://127.0.0.1:${port}/probe-me`);
    expect(probes[0].status).toBe(200);
    expect(typeof probes[0].latencyMs).toBe('number');
  });
});

describe('pipeline trace wiring', () => {
  it('constructor with traceFile starts a run trace (run.start event)', async () => {
    const { ParallaxPipeline } = await import('../pipeline');
    const file = tmpTracePath();
    new ParallaxPipeline({ target: 'https://example.com', traceFile: file });
    const lines = readLines(file);
    const start = lines.find(l => l.event === 'run.start');
    expect(start).toBeTruthy();
    expect(typeof start!.runId).toBe('string');
    expect(start!.target).toBe('https://example.com');
  });
});
