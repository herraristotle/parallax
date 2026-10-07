import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { createReportWatcher, type ReportChangeEvent, type ReportWatcher } from '../dashboard-watch';

async function waitFor(cond: () => boolean, timeoutMs = 3000): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) throw new Error('waitFor timeout');
    await new Promise(r => setTimeout(r, 10));
  }
}

const REPORT = { probe: {}, discover: { cachedUrls: [], uncacheableUrls: [], totalTested: 0 }, diff: [], poison: [], weaponize: [] };

describe('createReportWatcher', () => {
  let watcher: ReportWatcher | null = null;
  const dirs: string[] = [];
  const tmp = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'px-watch-')); dirs.push(d); return d; };

  afterEach(() => {
    watcher?.stop();
    watcher = null;
    while (dirs.length) fs.rmSync(dirs.pop()!, { recursive: true, force: true });
  });

  it('emits report-added for new files and report-changed for modifications', async () => {
    const dir = tmp();
    const events: ReportChangeEvent[] = [];
    watcher = createReportWatcher({ dir, intervalMs: 20, onEvent: ev => events.push(ev) });

    fs.writeFileSync(path.join(dir, 'parallax-report-100.json'), JSON.stringify(REPORT));
    await waitFor(() => events.length >= 1);
    expect(events[0]).toMatchObject({ type: 'report-added', id: 'parallax-report-100' });

    fs.writeFileSync(path.join(dir, 'parallax-report-100.json'), JSON.stringify({ ...REPORT, extra: 1 }));
    await waitFor(() => events.some(e => e.type === 'report-changed'));
    expect(events.filter(e => e.type === 'report-changed')).toHaveLength(1);
  });

  it('files present at start emit nothing (primed silently)', async () => {
    const dir = tmp();
    fs.writeFileSync(path.join(dir, 'parallax-report-100.json'), JSON.stringify(REPORT));
    const events: ReportChangeEvent[] = [];
    watcher = createReportWatcher({ dir, intervalMs: 20, onEvent: ev => events.push(ev) });
    await new Promise(r => setTimeout(r, 120));
    expect(events).toEqual([]);
  });

  it('missing dir never throws; events fire after dir exists and files land', async () => {
    const dir = path.join(tmp(), 'not-yet');
    const events: ReportChangeEvent[] = [];
    watcher = createReportWatcher({ dir, intervalMs: 20, onEvent: ev => events.push(ev) });
    await new Promise(r => setTimeout(r, 60)); // polling ENOENT
    fs.mkdirSync(dir, { recursive: true });
    await new Promise(r => setTimeout(r, 60)); // first successful scan primes
    fs.writeFileSync(path.join(dir, 'parallax-report-200.json'), JSON.stringify(REPORT));
    await waitFor(() => events.length >= 1);
    expect(events[0].id).toBe('parallax-report-200');
  });

  it('ignores non-allowlisted filenames', async () => {
    const dir = tmp();
    const events: ReportChangeEvent[] = [];
    watcher = createReportWatcher({ dir, intervalMs: 20, onEvent: ev => events.push(ev) });
    fs.writeFileSync(path.join(dir, 'evil-1.json'), '{}');
    fs.writeFileSync(path.join(dir, 'parallax-report-abc.json'), '{}');
    fs.writeFileSync(path.join(dir, 'notes.txt'), 'x');
    await new Promise(r => setTimeout(r, 120));
    expect(events).toEqual([]);
  });

  it('deletion is silent; re-add fires report-added again; stop() halts', async () => {
    const dir = tmp();
    const events: ReportChangeEvent[] = [];
    watcher = createReportWatcher({ dir, intervalMs: 20, onEvent: ev => events.push(ev) });
    const file = path.join(dir, 'parallax-report-300.json');
    fs.writeFileSync(file, JSON.stringify(REPORT));
    await waitFor(() => events.length === 1);
    fs.rmSync(file);
    await new Promise(r => setTimeout(r, 60));
    expect(events).toHaveLength(1); // no delete event
    fs.writeFileSync(file, JSON.stringify(REPORT));
    await waitFor(() => events.length === 2);
    expect(events[1].type).toBe('report-added');
    watcher.stop();
    watcher = null;
    fs.writeFileSync(file, JSON.stringify({ ...REPORT, x: 1 }));
    await new Promise(r => setTimeout(r, 80));
    expect(events).toHaveLength(2); // stopped
  });
});