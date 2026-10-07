import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { appendScanEvent, type ScanEvent } from '../scan-events';
import { ParallaxPipeline } from '../pipeline';

describe('appendScanEvent', () => {
  let dir = '';
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'px-ndjson-')); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('appends one parseable JSON line per call, in order', () => {
    appendScanEvent(dir, { ts: 1, stage: 'probe', detail: 'cdn=Cloudflare' });
    appendScanEvent(dir, { ts: 2, stage: 'poison', detail: '3 finding(s)' });
    const lines = fs.readFileSync(path.join(dir, 'scan-events.ndjson'), 'utf8').trim().split('\n');
    expect(lines).toHaveLength(2);
    const a = JSON.parse(lines[0]) as ScanEvent;
    const b = JSON.parse(lines[1]) as ScanEvent;
    expect(a).toMatchObject({ stage: 'probe', detail: 'cdn=Cloudflare' });
    expect(b.stage).toBe('poison');
  });

  it('swallows errors: unwritable dir (path is a file) does not throw (Review Focus: scan must not fail)', () => {
    const asFile = path.join(dir, 'not-a-dir');
    fs.writeFileSync(asFile, 'x');
    expect(() => appendScanEvent(asFile, { ts: 1, stage: 'probe' })).not.toThrow();
    expect(() => appendScanEvent('/proc/definitely/not/writable-here', { ts: 1, stage: 'probe' })).not.toThrow();
  });
});

describe('pipeline emitEvent gate', () => {
  let dir = '';
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'px-gate-')); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  // Reach the private method through a cast — unit-testing the gate without running the scan.
  const pipelineWith = (enableDashboardEvents: boolean | undefined, outputDir: string) =>
    new ParallaxPipeline({
      target: 'https://gate.test/',
      enableDashboardEvents,
      outputDir,
      enableOob: false,
    } as any) as any;

  const ndjson = (): string => {
    try { return fs.readFileSync(path.join(dir, 'scan-events.ndjson'), 'utf8'); }
    catch { return ''; }
  };

  it('emitEvent writes when flag undefined (default-on) and when true', () => {
    pipelineWith(undefined, dir).emitEvent('probe', 'cdn=Cloudflare');
    expect(ndjson()).toContain('"stage":"probe"');
    fs.rmSync(path.join(dir, 'scan-events.ndjson'), { force: true });
    pipelineWith(true, dir).emitEvent('probe', 'x');
    expect(ndjson()).toContain('"stage":"probe"');
  });

  it('emitEvent is a no-op only when explicitly false', () => {
    pipelineWith(false, dir).emitEvent('probe', 'x');
    expect(ndjson()).toBe('');
  });

  it('emitEvent never throws even when outputDir is unwritable', () => {
    const asFile = path.join(dir, 'blocked');
    fs.writeFileSync(asFile, 'x');
    const p = pipelineWith(true, asFile);
    expect(() => p.emitEvent('probe', 'x')).not.toThrow();
  });
});