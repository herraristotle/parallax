import { describe, it, expect, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { createNdjsonTail } from '../dashboard-tail';
import { appendScanEvent } from '../scan-events';
import { startDashboard, type DashboardHandle } from '../dashboard-server';

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

describe('createNdjsonTail', () => {
  let dir = '';
  let stop: (() => void) | null = null;

  afterEach(() => {
    if (stop) stop();
    stop = null;
    if (dir) { fs.rmSync(dir, { recursive: true, force: true }); dir = ''; }
  });

  it('primes silently: pre-existing history is not re-emitted', async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'px-tail-'));
    appendScanEvent(dir, { ts: 1, stage: 'old' });
    const seen: string[] = [];
    const tail = createNdjsonTail({
      file: path.join(dir, 'scan-events.ndjson'),
      intervalMs: 25,
      onEvent: ev => seen.push(ev.stage),
    });
    stop = () => tail.stop();
    await sleep(120);
    expect(seen).toEqual([]); // history skipped
    appendScanEvent(dir, { ts: 2, stage: 'new' });
    await vi.waitFor(() => expect(seen).toEqual(['new']), { timeout: 2000 });
  });

  it('creates the file mid-run: first append after start emits', async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'px-tail2-'));
    const file = path.join(dir, 'scan-events.ndjson');
    const seen: string[] = [];
    const tail = createNdjsonTail({ file, intervalMs: 25, onEvent: ev => seen.push(ev.stage) });
    stop = () => tail.stop();
    await sleep(80); // no file yet — must not throw
    appendScanEvent(dir, { ts: 1, stage: 'a' });
    await vi.waitFor(() => expect(seen).toEqual(['a']), { timeout: 2000 });
  });

  it('holds back partial lines until the newline lands', async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'px-tail3-'));
    const file = path.join(dir, 'scan-events.ndjson');
    const seen: unknown[] = [];
    const tail = createNdjsonTail({ file, intervalMs: 20, onEvent: ev => seen.push(ev) });
    stop = () => tail.stop();
    await sleep(60);
    fs.writeFileSync(file, '{"ts":1,"stage":"partial"'); // torn — no \n
    await sleep(100);
    expect(seen).toEqual([]);
    fs.appendFileSync(file, '}\n');
    await vi.waitFor(() => expect(seen).toHaveLength(1), { timeout: 2000 });
    expect((seen[0] as any).stage).toBe('partial');
  });

  it('skips unparseable lines without stopping the tail', async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'px-tail4-'));
    const file = path.join(dir, 'scan-events.ndjson');
    const seen: string[] = [];
    const tail = createNdjsonTail({ file, intervalMs: 20, onEvent: ev => seen.push(ev.stage) });
    stop = () => tail.stop();
    await sleep(60);
    fs.appendFileSync(file, 'not-json\n{"ts":1,"stage":"ok"}\n');
    await vi.waitFor(() => expect(seen).toEqual(['ok']), { timeout: 2000 });
  });
});

describe('server: ndjson → SSE scan-event', () => {
  let handle: DashboardHandle | null = null;
  let dir = '';

  afterEach(async () => {
    if (handle) await handle.close();
    handle = null;
    if (dir) { fs.rmSync(dir, { recursive: true, force: true }); dir = ''; }
  });

  it('scan event flows to /events and appears in /partials/feed', async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'px-int-'));
    handle = await startDashboard({ outputDir: dir, port: 0, pollMs: 25, heartbeatMs: 60000 });
    const ac = new AbortController();
    const res = await fetch(handle.url + '/events', { signal: ac.signal });
    const reader = res.body!.getReader();
    const dec = new TextDecoder();
    let acc = '';
    const readUntil = async (needle: string) => {
      while (!acc.includes(needle)) {
        const { done, value } = await reader.read();
        if (done) break;
        acc += dec.decode(value, { stream: true });
      }
    };
    await readUntil(': connected'); // stream live
    appendScanEvent(dir, { ts: Date.now(), stage: 'poison', detail: '2 finding(s)' });
    await readUntil('event: scan-event');
    expect(acc).toContain('"stage":"poison"');
    const feed = await (await fetch(handle.url + '/partials/feed')).text();
    expect(feed).toContain('poison');
    ac.abort();
  });
});