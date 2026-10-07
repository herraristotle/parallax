# Parallax Live Dashboard (SSE + htmx) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Live localhost dashboard reading parallax pipeline JSON reports from the output directory, streaming report/scan updates to an htmx UI over SSE.

**Architecture:** Pure functions (normalizer, renderers) + stat-poll file watcher + stdlib `node:http` server exposing JSON APIs, server-rendered HTML partials, and one SSE stream. Filesystem is the interface: any process writing `parallax-report-*.json` / `scan-events.ndjson` into the output dir is picked up. Phase 2 adds NDJSON stage-event emission from the pipeline behind a flag (opt-in first, then default-on per spec).

**Tech Stack:** TypeScript strict -> CommonJS, `node:http`/`fs`/`path`/`net` stdlib, vendored htmx 2.x, SSE `text/event-stream`, vitest. **No new npm dependencies.**

**Spec:** `docs/superpowers/specs/2026-10-07-dashboard-sse-design.md` (approved 2026-10-07)

## Global Constraints

- No new npm dependencies — deps stay `node-fetch` only; stdlib only.
- TS strict CJS (`lib` includes `dom` so `fetch`/`EventSource` types exist). After every task: `npx tsc --noEmit && npx vitest run` green.
- Baseline **166/166 tests green (18 files)** — must never regress.
- Additive only: no deletions; Phase 1 (Tasks 1-6) makes **zero edits to `pipeline.ts`**, no behavior change to `scan`/`batch`/`discover`.
- Every string interpolated into HTML partials goes through `escapeHtml` — report contents are attacker-controlled.
- Default bind `127.0.0.1`, no auth, no TLS (localhost is the security boundary).
- Report ids validated by `isSafeReportId` allowlist regex `/^(parallax-report|batch-summary)-[0-9]+$/`; never path-join raw request input.
- Phase-2 event emission must never throw out of `pipeline.run()` (`appendScanEvent` swallows internally).
- Every commit message ends with: `Co-Authored-By: Claude Code <noreply@anthropic.com>`
- New tests live in `src/__tests__/*.test.ts` (vitest include pattern `src/**/*.test.ts`).

## Review Focus

Failure modes the spec implies that are most likely to bite a user; each is pinned by a test in the named task:

1. **Half-written report JSON during scan flush** — reader must skip + recover, never crash or serve torn data (Task 4: invalid JSON file excluded from `/api/reports`, `/api/report` returns 422, rewrite → appears).
2. **Attacker-controlled report strings** (`<script>` in evidence/urls) — must render inert in HTML partials, raw only in JSON (Task 3 test + Task 4 end-to-end partial test).
3. **Path traversal via `id`/`report` params** — `../` or arbitrary names must 404 (Task 4).
4. **SSE client flood or disconnect leak** — cap exceeded → 429; disconnect → listener removed; close() ends streams (Task 5).
5. **Pipeline scan must not fail from event writes** — flag-off writes nothing; blocked dir never throws (Task 7).

## File Structure

| File | Responsibility | Phase |
|---|---|---|
| Create `src/dashboard-findings.ts` | Pure: id allowlist, flatten reports to rows, summarize, filter | 1 |
| Create `src/dashboard-watch.ts` | Stat-poll watcher over output dir (add/change events) | 1 |
| Create `src/dashboard-ui.ts` | Pure: `escapeHtml`, shell HTML, partial renderers | 1 |
| Create `src/vendor/htmx.min.js` | Vendored htmx 2.x (downloaded once, committed) | 1 |
| Create `src/dashboard-server.ts` | stdlib http server: routes, SSE, feed, lifecycle | 1 |
| Modify `src/cli.ts` | `dashboard` subcommand + `--port/--host/--poll` flags | 1 |
| Modify `src/index.ts` | Export dashboard API | 1 |
| Create `src/scan-events.ts` | `appendScanEvent` (NDJSON append, never throws) | 2 |
| Create `src/dashboard-tail.ts` | Byte-offset NDJSON tail → `onEvent` (history-silent) | 2 |
| Modify `src/types.ts` | `PipelineConfig` += `enableDashboardEvents?`, `outputDir?` | 2 |
| Modify `src/pipeline.ts` | `emitEvent()` at stage boundaries (flag-gated) | 2 |
| Modify `src/cli.ts` | `--no-scan-events` flag | 2 |

---

### Task 1: Findings Normalizer

**Files:**
- Create: `src/dashboard-findings.ts`
- Test: `src/__tests__/dashboard-findings.test.ts`

**Interfaces:**
- Consumes: `PipelineResult`, `DeceptionFinding`, etc. from `src/types.ts` (existing).
- Produces (later tasks rely on these exact names):
  - `interface DashFinding { id: string; report: string; source: 'poison'|'deception'|'internal'|'diff'|'weaponize'; url: string; classification?: string; confidence?: string; severity?: string; evidence: string; }`
  - `interface ReportSummary { id: string; target: string; ts: number; cdn: string; counts: Record<string, number>; total: number; }`
  - `isSafeReportId(id: string): boolean`, `ALLOWED_REPORT_RE: RegExp`
  - `isPipelineResult(d: unknown): d is PipelineResult`
  - `reportTarget(r: PipelineResult): string`
  - `flattenFindings(reportId: string, data: unknown): DashFinding[]`
  - `summarizeReport(id: string, data: unknown): ReportSummary`
  - `filterFindings(rows: DashFinding[], qp: URLSearchParams): DashFinding[]`

- [ ] **Step 1: Write the failing test**

```ts
// src/__tests__/dashboard-findings.test.ts
import { describe, it, expect } from 'vitest';
import {
  flattenFindings, summarizeReport, filterFindings, isSafeReportId, reportTarget,
  type DashFinding,
} from '../dashboard-findings';

function fixture(): any {
  return {
    probe: { cdn: { name: 'Cloudflare', confidence: 0.9 }, proxy: {}, framework: { name: 'None' }, cacheKey: {}, hiddenCacheDetected: false },
    discover: {
      cachedUrls: [{ url: 'https://a.test/page', cacheStatus: 'HIT', cacheHeaders: {}, isTargetUrl: true }],
      uncacheableUrls: [], totalTested: 1,
    },
    diff: [{ url: 'https://a.test/page', fuzzResults: [], unkeyedDelimiters: [';'] }],
    poison: [{
      findings: [{ inputType: 'header', inputName: 'X-Forwarded-Host', canary: 'c1', classification: 'xss', confidence: 'CONFIRMED' }],
      statistics: {},
    }],
    weaponize: [{
      chains: [{
        finding: { classification: 'xss', inputName: 'X-Forwarded-Host', confidence: 'CONFIRMED' },
        poc: { curlCommand: 'curl https://a.test/page' },
        impact: { severity: 'high', cvss: 8 },
      }],
      summary: {},
    }],
    deception: [{
      endpoint: 'https://a.test/api', attackUrl: 'https://a.test/api/.css', pattern: '.css',
      originServed: true, cached: true, confirmed: true,
    }],
    internal: [{ url: 'https://a.test/page', signal: 'esi_transform', evidence: 'tag consumed', confidence: 'LIKELY' }],
  };
}

const ID = 'parallax-report-1760000000000';

describe('isSafeReportId', () => {
  it('accepts report and batch ids', () => {
    expect(isSafeReportId('parallax-report-1760000000000')).toBe(true);
    expect(isSafeReportId('batch-summary-1760000000000')).toBe(true);
  });
  it('rejects traversal, extensions, and junk', () => {
    expect(isSafeReportId('../../etc/passwd')).toBe(false);
    expect(isSafeReportId('parallax-report-1760000000000.json')).toBe(false);
    expect(isSafeReportId('parallax-report-abc')).toBe(false);
    expect(isSafeReportId('anything-else')).toBe(false);
  });
});

describe('reportTarget', () => {
  it('prefers isTargetUrl, falls back to diff url, then first cached, then unknown', () => {
    const r = fixture();
    expect(reportTarget(r)).toBe('https://a.test/page');
    const noTarget = fixture();
    noTarget.discover.cachedUrls[0].isTargetUrl = false;
    noTarget.diff = [{ url: 'https://b.test/x', fuzzResults: [], unkeyedDelimiters: [] }];
    expect(reportTarget(noTarget)).toBe('https://b.test/x');
    noTarget.diff = [];
    noTarget.discover.cachedUrls = [{ url: 'https://c.test/y', cacheStatus: 'MISS', cacheHeaders: {}, isTargetUrl: false }];
    expect(reportTarget(noTarget)).toBe('https://c.test/y');
    expect(reportTarget({ probe: {}, discover: { cachedUrls: [], uncacheableUrls: [], totalTested: 0 }, diff: [] } as any)).toBe('unknown');
  });
});

describe('flattenFindings', () => {
  it('emits one row per finding across all five sources', () => {
    const rows = flattenFindings(ID, fixture());
    expect(rows.map(r => r.source).sort()).toEqual(['deception', 'diff', 'internal', 'poison', 'weaponize']);
    const poison = rows.find(r => r.source === 'poison')!;
    expect(poison.url).toBe('https://a.test/page');
    expect(poison.classification).toBe('xss');
    expect(poison.confidence).toBe('CONFIRMED');
    expect(poison.report).toBe(ID);
    const weapon = rows.find(r => r.source === 'weaponize')!;
    expect(weapon.severity).toBe('high');
    expect(weapon.evidence).toBe('curl https://a.test/page');
    const internal = rows.find(r => r.source === 'internal')!;
    expect(internal.classification).toBe('esi_transform');
    expect(internal.confidence).toBe('LIKELY');
  });

  it('diff row only when unkeyed delimiters exist', () => {
    const r = fixture();
    r.diff[0].unkeyedDelimiters = [];
    const rows = flattenFindings(ID, r);
    expect(rows.some(x => x.source === 'diff')).toBe(false);
  });

  it('ids are stable across calls and distinct across rows', () => {
    const a = flattenFindings(ID, fixture());
    const b = flattenFindings(ID, fixture());
    expect(a.map(r => r.id)).toEqual(b.map(r => r.id));
    expect(new Set(a.map(r => r.id)).size).toBe(a.length);
  });

  it('junk input returns []', () => {
    expect(flattenFindings(ID, null)).toEqual([]);
    expect(flattenFindings(ID, 'nope')).toEqual([]);
    expect(flattenFindings(ID, { probe: 1 })).toEqual([]);
  });

  it('batch arrays flatten PipelineResult entries and skip error entries', () => {
    const batch = [fixture(), { target: 'https://bad.test', error: 'boom' }, fixture()];
    const rows = flattenFindings(ID, batch);
    expect(rows.filter(r => r.source === 'poison')).toHaveLength(2);
    expect(rows.every(r => r.report === ID)).toBe(true);
    expect(new Set(rows.map(r => r.id)).size).toBe(rows.length);
  });
});

describe('summarizeReport', () => {
  it('summarizes a single report', () => {
    const s = summarizeReport(ID, fixture());
    expect(s.target).toBe('https://a.test/page');
    expect(s.cdn).toBe('Cloudflare');
    expect(s.ts).toBe(1760000000000);
    expect(s.total).toBe(5);
    expect(s.counts.poison).toBe(1);
    expect(s.counts.weaponize).toBe(1);
  });
  it('batch gets target "batch"', () => {
    const s = summarizeReport(ID, [fixture(), { target: 'x', error: 'e' }]);
    expect(s.target).toBe('batch');
    expect(s.total).toBe(5);
  });
  it('non-report junk still yields a summary shell', () => {
    const s = summarizeReport(ID, { junk: true });
    expect(s.total).toBe(0);
    expect(s.target).toBe('unknown');
  });
});

describe('filterFindings', () => {
  const rows: DashFinding[] = flattenFindings(ID, fixture());
  const qp = (q: string) => new URLSearchParams(q);

  it('filters by source', () => {
    expect(filterFindings(rows, qp('source=poison')).map(r => r.source)).toEqual(['poison']);
  });
  it('filters by type (case-insensitive classification)', () => {
    expect(filterFindings(rows, qp('type=XSS'))).toHaveLength(2); // poison + weaponize
  });
  it('severity matches severity ?? confidence', () => {
    expect(filterFindings(rows, qp('severity=high')).map(r => r.source)).toEqual(['weaponize']);
    expect(filterFindings(rows, qp('severity=confirmed')).map(r => r.source)).toEqual(['poison']);
  });
  it('q substring over url+evidence+classification, lowercase', () => {
    expect(filterFindings(rows, qp('q=FORWARD'))).toHaveLength(1);
    expect(filterFindings(rows, qp('q=esi'))).toHaveLength(1);
  });
  it('no params returns everything', () => {
    expect(filterFindings(rows, qp(''))).toHaveLength(rows.length);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/__tests__/dashboard-findings.test.ts`
Expected: FAIL — `Failed to resolve import "../dashboard-findings"` (module does not exist).

- [ ] **Step 3: Write minimal implementation**

```ts
// src/dashboard-findings.ts
import { PipelineResult } from './types';

export interface DashFinding {
  id: string;
  report: string;
  source: 'poison' | 'deception' | 'internal' | 'diff' | 'weaponize';
  url: string;
  classification?: string;
  confidence?: string;
  severity?: string;
  evidence: string;
}

export interface ReportSummary {
  id: string;
  target: string;
  ts: number;
  cdn: string;
  counts: Record<string, number>;
  total: number;
}

/** Filenames we are ever willing to read as reports (id, no extension). */
export const ALLOWED_REPORT_RE = /^(parallax-report|batch-summary)-[0-9]+$/;

export function isSafeReportId(id: string): boolean {
  return ALLOWED_REPORT_RE.test(id);
}

function hashId(...parts: string[]): string {
  const s = parts.join('|');
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  return h.toString(16);
}

export function isPipelineResult(d: unknown): d is PipelineResult {
  return typeof d === 'object' && d !== null && 'probe' in d && 'discover' in d;
}

export function reportTarget(r: PipelineResult): string {
  const hit = r.discover?.cachedUrls?.find(u => u.isTargetUrl);
  if (hit) return hit.url;
  if (r.diff && r.diff.length > 0) return r.diff[0].url;
  if (r.discover?.cachedUrls && r.discover.cachedUrls.length > 0) return r.discover.cachedUrls[0].url;
  return 'unknown';
}

function flattenPipeline(reportId: string, r: PipelineResult, salt: string): DashFinding[] {
  const rows: DashFinding[] = [];
  const target = reportTarget(r);
  const add = (base: Omit<DashFinding, 'id' | 'report'>, key: string): void => {
    rows.push({ id: hashId(reportId, salt, base.source, key), report: reportId, ...base });
  };

  for (const pr of r.poison ?? []) {
    for (const f of pr.findings ?? []) {
      add({
        source: 'poison',
        url: target,
        classification: f.classification,
        confidence: f.confidence,
        evidence: `${f.inputType}:${f.inputName} canary=${f.canary}`,
      }, `${f.inputType}|${f.inputName}|${f.classification}|${f.canary}`);
    }
  }

  for (const d of r.deception ?? []) {
    add({
      source: 'deception',
      url: d.attackUrl,
      classification: 'cache_deception',
      confidence: d.confirmed ? 'CONFIRMED' : 'POSSIBLE',
      evidence: `pattern=${d.pattern} originServed=${d.originServed} cached=${d.cached}${d.crossUserLeak ? ' crossUserLeak' : ''}`,
    }, `${d.endpoint}|${d.pattern}|${d.attackUrl}`);
  }

  for (const i of r.internal ?? []) {
    add({
      source: 'internal',
      url: i.url,
      classification: i.signal,
      confidence: i.confidence,
      evidence: i.parameter ? `${i.evidence} param=${i.parameter}` : i.evidence,
    }, `${i.url}|${i.signal}|${i.parameter ?? ''}`);
  }

  for (const d of r.diff ?? []) {
    if (d.unkeyedDelimiters && d.unkeyedDelimiters.length > 0) {
      add({
        source: 'diff',
        url: d.url,
        classification: 'unkeyed_delimiter',
        evidence: d.unkeyedDelimiters.join(' '),
      }, d.url);
    }
  }

  for (const w of r.weaponize ?? []) {
    for (const c of w.chains ?? []) {
      add({
        source: 'weaponize',
        url: target,
        classification: c.finding?.classification,
        confidence: c.finding?.confidence,
        severity: c.impact?.severity,
        evidence: c.poc?.curlCommand ?? c.poc?.description ?? '',
      }, `${c.finding?.classification}|${c.finding?.inputName}|${c.impact?.severity}|${c.poc?.curlCommand ?? ''}`);
    }
  }

  return rows;
}

export function flattenFindings(reportId: string, data: unknown): DashFinding[] {
  if (Array.isArray(data)) {
    return data
      .filter(isPipelineResult)
      .flatMap((entry, i) => flattenPipeline(reportId, entry, String(i)));
  }
  if (isPipelineResult(data)) return flattenPipeline(reportId, data, '');
  return [];
}

export function summarizeReport(id: string, data: unknown): ReportSummary {
  const rows = flattenFindings(id, data);
  const counts: Record<string, number> = {};
  for (const r of rows) counts[r.source] = (counts[r.source] ?? 0) + 1;
  const ts = Number(id.split('-').pop()) || 0;
  const isBatch = Array.isArray(data);
  const sample = isBatch
    ? data.find(isPipelineResult)
    : (isPipelineResult(data) ? data : null);
  return {
    id,
    target: isBatch ? 'batch' : (sample ? reportTarget(sample) : 'unknown'),
    ts,
    cdn: sample?.probe?.cdn?.name ?? '',
    counts,
    total: rows.length,
  };
}

export function filterFindings(rows: DashFinding[], qp: URLSearchParams): DashFinding[] {
  const source = qp.get('source');
  const type = qp.get('type');
  const sev = qp.get('severity');
  const q = qp.get('q')?.toLowerCase();
  return rows.filter(r =>
    (!source || r.source === source) &&
    (!type || (r.classification ?? '').toLowerCase() === type.toLowerCase()) &&
    (!sev || (r.severity ?? r.confidence ?? '').toLowerCase() === sev.toLowerCase()) &&
    (!q || `${r.url} ${r.evidence} ${r.classification ?? ''}`.toLowerCase().includes(q))
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/__tests__/dashboard-findings.test.ts`
Expected: PASS (all describe blocks).

- [ ] **Step 5: Full gate + commit**

Run: `npx tsc --noEmit && npx vitest run`
Expected: tsc clean; 166 baseline + new tests all green.

```bash
git add src/dashboard-findings.ts src/__tests__/dashboard-findings.test.ts
git commit -m "feat(dashboard): findings normalizer — flatten, summarize, filter, id allowlist

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 2: Report File Watcher

**Files:**
- Create: `src/dashboard-watch.ts`
- Test: `src/__tests__/dashboard-watch.test.ts`

**Interfaces:**
- Consumes: `isSafeReportId` from Task 1.
- Produces:
  - `interface ReportChangeEvent { type: 'report-added' | 'report-changed'; id: string; ts: number; }`
  - `interface ReportWatcher { stop(): void; }`
  - `createReportWatcher(opts: { dir: string; intervalMs?: number; ignoreInitial?: boolean; onEvent: (ev: ReportChangeEvent) => void }): ReportWatcher`
  - Semantics: stat-poll (not `fs.watch`); first successful scan records silently (`ignoreInitial` default true); missing dir → no throw, keep polling; deletion → silent state drop; non-allowlisted filenames ignored.

- [ ] **Step 1: Write the failing test**

```ts
// src/__tests__/dashboard-watch.test.ts
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
    // writeFileSync truncates then writes, so a poll can land mid-write and see
    // two distinct stats; either way at least one change event is expected.
    expect(events.filter(e => e.type === 'report-changed').length).toBeGreaterThanOrEqual(1);
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/__tests__/dashboard-watch.test.ts`
Expected: FAIL — cannot resolve `../dashboard-watch`.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/dashboard-watch.ts
import * as fs from 'fs';
import * as path from 'path';
import { isSafeReportId } from './dashboard-findings';

export interface ReportChangeEvent {
  type: 'report-added' | 'report-changed';
  id: string;
  ts: number;
}

export interface ReportWatcher {
  stop(): void;
}

export interface WatcherOptions {
  dir: string;
  intervalMs?: number;
  /** Files present at the first successful scan emit nothing (default true). */
  ignoreInitial?: boolean;
  onEvent: (ev: ReportChangeEvent) => void;
}

/**
 * Stat-poll watcher — deliberately not fs.watch: Windows emits duplicate/
 * lossy events there, and mtime+size deltas are enough for report files.
 */
export function createReportWatcher(opts: WatcherOptions): ReportWatcher {
  const intervalMs = opts.intervalMs ?? 1000;
  const ignoreInitial = opts.ignoreInitial !== false;
  const state = new Map<string, { mtimeMs: number; size: number }>();
  let primed = false;

  /** One throwing consumer must never stop the watcher (or crash the process). */
  const emit = (ev: ReportChangeEvent): void => {
    try {
      opts.onEvent(ev);
    } catch {
      /* consumer failure is its own problem */
    }
  };

  const tick = (): void => {
    let names: string[];
    try {
      names = fs.readdirSync(opts.dir);
    } catch {
      return; // dir missing — keep polling
    }
    const files = names.filter(n => n.endsWith('.json') && isSafeReportId(n.slice(0, -5)));
    const seen = new Set<string>();
    const quiet = ignoreInitial && !primed;
    for (const name of files) {
      const id = name.slice(0, -5);
      seen.add(id);
      let st: fs.Stats;
      try {
        st = fs.statSync(path.join(opts.dir, name));
      } catch {
        continue;
      }
      const prev = state.get(id);
      if (!prev) {
        state.set(id, { mtimeMs: st.mtimeMs, size: st.size });
        if (!quiet) emit({ type: 'report-added', id, ts: Date.now() });
      } else if (prev.mtimeMs !== st.mtimeMs || prev.size !== st.size) {
        state.set(id, { mtimeMs: st.mtimeMs, size: st.size });
        if (!quiet) emit({ type: 'report-changed', id, ts: Date.now() });
      }
    }
    for (const id of [...state.keys()]) {
      if (!seen.has(id)) state.delete(id); // deleted → silent drop
    }
    primed = true;
  };

  tick(); // prime synchronously when dir exists
  const timer = setInterval(tick, intervalMs);
  return { stop: () => clearInterval(timer) };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/__tests__/dashboard-watch.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Full gate + commit**

Run: `npx tsc --noEmit && npx vitest run`
Expected: all green.

```bash
git add src/dashboard-watch.ts src/__tests__/dashboard-watch.test.ts
git commit -m "feat(dashboard): stat-poll report watcher (add/change events, allowlist)

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 3: UI Renderers (shell + partials)

**Files:**
- Create: `src/dashboard-ui.ts`
- Test: `src/__tests__/dashboard-ui.test.ts`

**Interfaces:**
- Consumes: `DashFinding`, `ReportSummary` from Task 1.
- Produces:
  - `escapeHtml(s: string): string`
  - `interface FeedItem { name: string; data: Record<string, unknown>; ts: number; }`
  - `shellHtml(): string`
  - `listPartial(summaries: ReportSummary[]): string`
  - `tablePartial(rows: DashFinding[]): string`
  - `detailPartial(summary: ReportSummary, rows: DashFinding[], raw: unknown): string`
  - `findingPartial(row: DashFinding): string`
  - `feedPartial(feed: FeedItem[]): string`
  - **hx contract:** each partial returns its complete `<section id="...">` carrying its own `hx-get`/`hx-trigger` so outerHTML swaps keep the refresh loop alive. Partials' `hx-trigger` must NOT include `load` (would loop); only the shell's first render includes `load`.

- [ ] **Step 1: Write the failing test**

```ts
// src/__tests__/dashboard-ui.test.ts
import { describe, it, expect } from 'vitest';
import {
  escapeHtml, shellHtml, listPartial, tablePartial, detailPartial, findingPartial, feedPartial,
  type FeedItem,
} from '../dashboard-ui';
import { flattenFindings, summarizeReport } from '../dashboard-findings';

const ID = 'parallax-report-1760000000000';
const SUMMARY = summarizeReport(ID, { junk: true });

describe('escapeHtml', () => {
  it('escapes the five specials', () => {
    expect(escapeHtml(`<a href="x">'&`)).toBe('&lt;a href=&quot;x&quot;&gt;&#39;&amp;');
  });
});

describe('shellHtml', () => {
  const shell = shellHtml();
  it('wires htmx + EventSource bootstrap + filter form + hx triggers', () => {
    expect(shell).toContain('src="/vendor/htmx.min.js"');
    expect(shell).toContain("new EventSource('/events')");
    expect(shell).toContain("htmx.trigger('body','refresh')");
    expect(shell).toContain('hx-include="#filters"');
    expect(shell).toContain('hx-trigger="load, refresh from:body, every 5s"');
    expect(shell).toContain('id="filters"');
    expect(shell).toContain('hx-target="#table"');
  });
  it('lists all three SSE event names', () => {
    expect(shell).toContain('report-added');
    expect(shell).toContain('report-changed');
    expect(shell).toContain('scan-event');
  });
});

describe('partials', () => {
  const rows = flattenFindings(ID, {
    probe: { cdn: { name: 'CF' }, proxy: {}, framework: {}, cacheKey: {}, hiddenCacheDetected: false },
    discover: { cachedUrls: [{ url: 'https://a.test/p', cacheStatus: 'HIT', cacheHeaders: {}, isTargetUrl: true }], uncacheableUrls: [], totalTested: 1 },
    diff: [], poison: [{ findings: [{ inputType: 'header', inputName: 'H', canary: 'c', classification: 'xss', confidence: 'CONFIRMED' }], statistics: {} }],
    weaponize: [], internal: [], deception: [],
  });

  it('tablePartial renders rows with detail links and keeps hx refresh loop (no load trigger)', () => {
    const html = tablePartial(rows);
    expect(html).toContain('id="table"');
    expect(html).toContain('/partials/finding?report=');
    expect(html).toContain('hx-target="#detail"');
    expect(html).not.toContain('load,'); // no load in swapped trigger
    expect(html).toContain('refresh from:body');
    expect(html).toContain('every 5s');
  });

  it('tablePartial escapes attacker-controlled evidence', () => {
    const evil = [{ ...rows[0], evidence: '<script>alert(1)</script>' }];
    const html = tablePartial(evil);
    expect(html).not.toContain('<script>alert(1)');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('empty states', () => {
    expect(listPartial([])).toContain('No reports yet');
    expect(tablePartial([])).toContain('No findings match');
    expect(feedPartial([])).toContain('No events yet');
  });

  it('listPartial cards link to detail with escaped id', () => {
    const html = listPartial([SUMMARY]);
    expect(html).toContain(`/partials/detail?id=${ID}`);
    expect(html).toContain('id="list"');
    expect(html).toContain('refresh from:body');
    expect(html).not.toMatch(/hx-trigger="[^"]*load/);
  });

  it('detailPartial shows report cards and escapes everything', () => {
    const raw = { junk: '<img src=x onerror=alert(1)>' };
    const html = detailPartial({ ...SUMMARY, target: '<b>t</b>' }, [], raw);
    expect(html).not.toContain('<b>t</b>');
    expect(html).toContain('&lt;b&gt;t&lt;/b&gt;');
    expect(html).toContain('id="detail"');
  });

  it('findingPartial renders full row', () => {
    const html = findingPartial(rows[0]);
    expect(html).toContain('id="detail"');
    expect(html).toContain(escapeHtml(rows[0].evidence));
    expect(html).toContain('xss');
  });

  it('feedPartial lists events with type names', () => {
    const feed: FeedItem[] = [{ name: 'report-added', data: { id: ID }, ts: 1760000000000 }];
    const html = feedPartial(feed);
    expect(html).toContain('report-added');
    expect(html).toContain(ID);
    expect(html).toContain('id="feed"');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/__tests__/dashboard-ui.test.ts`
Expected: FAIL — cannot resolve `../dashboard-ui`.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/dashboard-ui.ts
import { DashFinding, ReportSummary } from './dashboard-findings';

const ESCAPES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

export function escapeHtml(s: string): string {
  return String(s).replace(/[&<>"']/g, c => ESCAPES[c] ?? c);
}

export interface FeedItem {
  name: string;
  data: Record<string, unknown>;
  ts: number;
}

const LEVEL_CLASS = (v: string): string => `sev-${escapeHtml(v.toLowerCase()).replace(/\s+/g, '-')}`;

export function shellHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Parallax Dashboard</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:#0f1115; color:#e6e6e6; }
  header { padding:12px 16px; background:#161a21; border-bottom:1px solid #2a2f3a; display:flex; gap:12px; align-items:baseline; }
  header h1 { font-size:16px; margin:0; }
  header .hint { color:#8a919e; font-size:12px; }
  #filters { display:flex; flex-wrap:wrap; gap:8px; padding:10px 16px 0; }
  #filters input, #filters select, #filters button { background:#0f1115; color:#e6e6e6; border:1px solid #2a2f3a; border-radius:4px; padding:6px 8px; font-size:13px; }
  #filters button { cursor:pointer; background:#2563eb; border-color:#2563eb; }
  main { display:grid; grid-template-columns:260px 1fr 280px; gap:12px; padding:12px 16px; }
  @media (max-width:900px) { main { grid-template-columns:1fr; } }
  section { background:#161a21; border:1px solid #2a2f3a; border-radius:6px; padding:10px; min-height:120px; }
  section h2 { font-size:12px; text-transform:uppercase; letter-spacing:.08em; color:#8a919e; margin:0 0 8px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:6px 8px; border-bottom:1px solid #2a2f3a; vertical-align:top; }
  th { color:#8a919e; font-weight:600; }
  tr[data-hx-get] { cursor:pointer; }
  tr[data-hx-get]:hover { background:#1d2330; }
  .sev-critical, .sev-high, .sev-confirmed { color:#ff6b6b; }
  .sev-medium, .sev-likely { color:#ffd43b; }
  .sev-low, .sev-possible { color:#51cf66; }
  .muted { color:#8a919e; }
  .card { border-bottom:1px solid #2a2f3a; padding:8px 0; cursor:pointer; }
  .card:last-child { border-bottom:none; }
  .badge { display:inline-block; font-size:11px; padding:1px 6px; border-radius:10px; background:#252b36; color:#aab2bf; margin-right:6px; }
  pre { background:#0f1115; padding:8px; border-radius:4px; overflow-x:auto; font-size:12px; white-space:pre-wrap; word-break:break-all; }
  ul.feed { list-style:none; margin:0; padding:0; font-size:12px; }
  ul.feed li { padding:4px 0; border-bottom:1px dashed #2a2f3a; }
  .empty { color:#8a919e; font-size:13px; padding:8px 0; }
  #detail:empty::after { content:"Select a report or finding"; color:#8a919e; font-size:13px; }
  .kv { display:grid; grid-template-columns:140px 1fr; gap:4px 8px; font-size:13px; margin-bottom:10px; }
  .kv dt { color:#8a919e; } .kv dd { margin:0; }
</style>
</head>
<body>
<header>
  <h1>Parallax Dashboard</h1>
  <span class="hint">live &middot; SSE &middot; watching output/</span>
</header>
<form id="filters"
      hx-get="/partials/table"
      hx-target="#table"
      hx-swap="outerHTML">
  <input type="search" name="q" placeholder="search evidence / url"
         hx-get="/partials/table" hx-target="#table" hx-swap="outerHTML"
         hx-include="closest form" hx-trigger="keyup changed delay:300ms">
  <select name="source" hx-get="/partials/table" hx-target="#table" hx-swap="outerHTML" hx-trigger="change">
    <option value="">source</option>
    <option>poison</option><option>deception</option><option>internal</option><option>diff</option><option>weaponize</option>
  </select>
  <select name="severity" hx-get="/partials/table" hx-target="#table" hx-swap="outerHTML" hx-trigger="change">
    <option value="">severity</option>
    <option>critical</option><option>high</option><option>medium</option><option>low</option>
    <option>CONFIRMED</option><option>LIKELY</option><option>POSSIBLE</option>
  </select>
  <input type="search" name="type" placeholder="type / classification"
         hx-get="/partials/table" hx-target="#table" hx-swap="outerHTML"
         hx-include="closest form" hx-trigger="keyup changed delay:300ms">
  <button type="submit">Filter</button>
</form>
<main>
  <section id="list" hx-get="/partials/list" hx-trigger="load, refresh from:body" hx-swap="outerHTML"><div class="empty">Loading&hellip;</div></section>
  <section id="table" hx-get="/partials/table" hx-include="#filters" hx-trigger="load, refresh from:body, every 5s" hx-swap="outerHTML"><div class="empty">Loading&hellip;</div></section>
  <section id="feed" hx-get="/partials/feed" hx-trigger="load, refresh from:body" hx-swap="outerHTML"><div class="empty">Loading&hellip;</div></section>
</main>
<section id="detail" style="margin:0 16px 16px;"></section>
<script src="/vendor/htmx.min.js"></script>
<script>
(function () {
  var es = new EventSource('/events');
  ['report-added', 'report-changed', 'scan-event'].forEach(function (name) {
    es.addEventListener(name, function () { htmx.trigger('body', 'refresh'); });
  });
})();
</script>
</body>
</html>`;
}

export function listPartial(summaries: ReportSummary[]): string {
  const cards = summaries.length === 0
    ? '<div class="empty">No reports yet &mdash; run <code>parallax scan &lt;url&gt;</code></div>'
    : summaries.map(s => `
    <div class="card" hx-get="/partials/detail?id=${encodeURIComponent(s.id)}" hx-target="#detail" hx-swap="innerHTML">
      <div><strong>${escapeHtml(s.target)}</strong></div>
      <div class="muted">${escapeHtml(s.id)} &middot; ${s.total} finding(s)${s.cdn ? ' &middot; ' + escapeHtml(s.cdn) : ''}</div>
    </div>`).join('');
  return `<section id="list" hx-get="/partials/list" hx-trigger="refresh from:body" hx-swap="outerHTML">
    <h2>Reports (${summaries.length})</h2>${cards}
  </section>`;
}

export function tablePartial(rows: DashFinding[]): string {
  const body = rows.length === 0
    ? '<div class="empty">No findings match.</div>'
    : `<table>
    <thead><tr><th>Source</th><th>Target</th><th>Type</th><th>Level</th><th>Evidence</th></tr></thead>
    <tbody>
${rows.map(r => `      <tr hx-get="/partials/finding?report=${encodeURIComponent(r.report)}&fid=${encodeURIComponent(r.id)}" hx-target="#detail" hx-swap="innerHTML">
        <td><span class="badge">${escapeHtml(r.source)}</span></td>
        <td>${escapeHtml(r.url)}</td>
        <td>${escapeHtml(r.classification ?? '')}</td>
        <td class="${LEVEL_CLASS(r.severity ?? r.confidence ?? '')}">${escapeHtml(r.severity ?? r.confidence ?? '')}</td>
        <td>${escapeHtml(r.evidence.slice(0, 160))}${r.evidence.length > 160 ? '&hellip;' : ''}</td>
      </tr>`).join('\n')}
    </tbody>
  </table>`;
  return `<section id="table" hx-get="/partials/table" hx-include="#filters" hx-trigger="refresh from:body, every 5s" hx-swap="outerHTML">
    <h2>Findings (${rows.length})</h2>${body}
  </section>`;
}

function chainsOf(raw: unknown): any[] {
  const list = Array.isArray(raw) ? raw : [raw];
  const chains: any[] = [];
  for (const entry of list) {
    if (entry && typeof entry === 'object' && Array.isArray((entry as any).weaponize)) {
      for (const w of (entry as any).weaponize) chains.push(...(w.chains ?? []));
    }
  }
  return chains;
}

export function detailPartial(summary: ReportSummary, rows: DashFinding[], raw: unknown): string {
  const counts = Object.entries(summary.counts)
    .map(([k, v]) => `<span class="badge">${escapeHtml(k)}: ${v}</span>`).join(' ');
  const chains = chainsOf(raw).map(c => `
    <div class="card">
      <div><span class="badge ${LEVEL_CLASS(c.impact?.severity ?? '')}">${escapeHtml(c.impact?.severity ?? '')}</span>
        <strong>${escapeHtml(c.finding?.classification ?? '')}</strong>
        <span class="muted">CVSS ${escapeHtml(String(c.impact?.cvss ?? '?'))}</span></div>
      <div class="muted">${escapeHtml(c.finding?.inputName ?? '')}</div>
      <pre>${escapeHtml(c.poc?.curlCommand ?? c.poc?.description ?? '')}</pre>
      <div class="muted">${(c.phases ?? []).map((p: any) => escapeHtml(`${p.phase}: ${p.detail}`)).join(' &middot; ')}</div>
    </div>`).join('');
  return `<section id="detail" style="border:1px solid #2a2f3a; border-radius:6px; padding:10px; background:#161a21;">
    <h2>Report ${escapeHtml(summary.id)}</h2>
    <dl class="kv">
      <dt>Target</dt><dd>${escapeHtml(summary.target)}</dd>
      <dt>CDN</dt><dd>${escapeHtml(summary.cdn || 'unknown')}</dd>
      <dt>Findings</dt><dd>${summary.total} ${counts}</dd>
    </dl>
    <h2>Exploit Chains (${chains.length})</h2>
    ${chains.length === 0 ? '<div class="empty">No chains in this report.</div>' : chains}
  </section>`;
}

export function findingPartial(row: DashFinding): string {
  return `<section id="detail" style="border:1px solid #2a2f3a; border-radius:6px; padding:10px; background:#161a21;">
    <h2>${escapeHtml(row.source)} finding</h2>
    <dl class="kv">
      <dt>Report</dt><dd>${escapeHtml(row.report)}</dd>
      <dt>URL</dt><dd>${escapeHtml(row.url)}</dd>
      <dt>Classification</dt><dd>${escapeHtml(row.classification ?? '-')}</dd>
      <dt>Severity</dt><dd class="${LEVEL_CLASS(row.severity ?? row.confidence ?? '')}">${escapeHtml(row.severity ?? '-')}</dd>
      <dt>Confidence</dt><dd>${escapeHtml(row.confidence ?? '-')}</dd>
      <dt>Evidence</dt><dd><pre>${escapeHtml(row.evidence)}</pre></dd>
    </dl>
    <button hx-get="/partials/detail?id=${encodeURIComponent(row.report)}" hx-target="#detail" hx-swap="innerHTML">Back to report</button>
  </section>`;
}

export function feedPartial(feed: FeedItem[]): string {
  const items = feed.length === 0
    ? '<div class="empty">No events yet.</div>'
    : `<ul class="feed">${[...feed].reverse().map(e => `
      <li><span class="muted">${new Date(e.ts).toLocaleTimeString()}</span> <span class="badge">${escapeHtml(e.name)}</span> ${escapeHtml(String((e.data as any).id ?? (e.data as any).stage ?? ''))}</li>`).join('')}
    </ul>`;
  return `<section id="feed" hx-get="/partials/feed" hx-trigger="refresh from:body" hx-swap="outerHTML">
    <h2>Live Feed</h2>${items}
  </section>`;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/__tests__/dashboard-ui.test.ts`
Expected: PASS.

- [ ] **Step 5: Full gate + commit**

Run: `npx tsc --noEmit && npx vitest run`
Expected: all green.

```bash
git add src/dashboard-ui.ts src/__tests__/dashboard-ui.test.ts
git commit -m "feat(dashboard): UI renderers — shell, partials, escapeHtml (XSS-safe)

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 4: Dashboard Server Core (routes, vendor, lifecycle)

**Files:**
- Create: `src/vendor/htmx.min.js` (downloaded)
- Create: `src/dashboard-server.ts`
- Test: `src/__tests__/dashboard-server.test.ts`

**Interfaces:**
- Consumes: Tasks 1-3 exports (exact signatures above).
- Produces:
  - `interface DashboardOptions { outputDir: string; port?: number; host?: string; pollMs?: number; maxSseClients?: number; heartbeatMs?: number; logger?: Logger; }`
  - `interface DashboardHandle { url: string; port: number; close(): Promise<void>; }`
  - `startDashboard(opts: DashboardOptions): Promise<DashboardHandle>`
  - Routes (all GET): `/`, `/healthz`, `/vendor/htmx.min.js`, `/api/reports`, `/api/report?id=`, `/api/findings?…`, `/partials/list|table|detail|finding|feed`, 404 otherwise. `/events` SSE arrives in Task 5 (its route block is added there).
  - Vendor resolution: candidate `path.join(__dirname, 'vendor', 'htmx.min.js')` (vitest/src run), then `path.join(__dirname, '..', 'src', 'vendor', 'htmx.min.js')` (dist run) — first existing wins; missing → 404.
  - Per-request try/catch → 500 JSON `{error}`; process never crashes.

- [ ] **Step 1: Vendor htmx (one-time download, committed)**

Run:

```bash
mkdir -p src/vendor
curl -fsSL https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js -o src/vendor/htmx.min.js
wc -c src/vendor/htmx.min.js
grep -c htmx src/vendor/htmx.min.js
```

Expected: size ~14000-20000 bytes, grep ≥ 1. Then:

```bash
git check-ignore src/vendor/htmx.min.js && git add -f src/vendor/htmx.min.js || git add src/vendor/htmx.min.js
```

(Note the exact file size and version `2.0.4` in the Task 4 commit message.)

- [ ] **Step 2: Write the failing test**

```ts
// src/__tests__/dashboard-server.test.ts
import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { startDashboard, type DashboardHandle } from '../dashboard-server';

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

  it('non-GET methods and unknown paths 404; malformed request path keeps server alive', async () => {
    const h = await boot();
    expect((await fetch(h.url + '/nope')).status).toBe(404);
    expect((await fetch(h.url + '/healthz', { method: 'POST' })).status).toBe(404);
    // odd encoding — must not crash the process
    try { await fetch(h.url + '/%'); } catch { /* client-side URL rejection is fine */ }
    expect((await fetch(h.url + '/healthz')).status).toBe(200);
  });

  it('close() releases the port (second start on same port works)', async () => {
    const h = await boot({ port: 0 });
    const port = h.port;
    await h.close();
    handle = null;
    await expect(startDashboard({ outputDir: dir, port })).resolves.toBeDefined();
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `npx vitest run src/__tests__/dashboard-server.test.ts`
Expected: FAIL — cannot resolve `../dashboard-server`.

- [ ] **Step 4: Write minimal implementation**

```ts
// src/dashboard-server.ts
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

  const watcher = createReportWatcher({
    dir: outDir,
    intervalMs: opts.pollMs ?? 1000,
    onEvent: ev => pushEvent(ev.type, { id: ev.id, ts: ev.ts }),
  });

  const heartbeat = setInterval(() => {
    for (const res of sseClients) {
      try { res.write(': hb\n\n'); } catch { /* client gone — close handler cleans up */ }
    }
  }, heartbeatMs);

  log.info(`dashboard listening on ${`http://${host}:${actualPort}`} (watching ${outDir})`);

  let closed = false;
  const close = async (): Promise<void> => {
    if (closed) return;
    closed = true;
    watcher.stop();
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
```

Note: the `/events` SSE route is deliberately absent here — Task 5 adds it (with `res.setTimeout(0)` and the 429 cap) plus wires `pushEvent` to the watcher. The `sseClients`/`pushEvent`/`heartbeat` scaffolding above already exists so Task 5 only adds the route + tests.

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run src/__tests__/dashboard-server.test.ts`
Expected: PASS (9 tests).

- [ ] **Step 6: Full gate + commit**

Run: `npx tsc --noEmit && npx vitest run`
Expected: all green.

```bash
git add src/vendor/htmx.min.js src/dashboard-server.ts src/__tests__/dashboard-server.test.ts
git commit -m "feat(dashboard): stdlib http server — JSON APIs, partials, healthz, vendor htmx 2.0.4 (~15KB)

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 5: SSE `/events` Route (stream, cap, heartbeat, push wiring)

**Files:**
- Modify: `src/dashboard-server.ts` (add `/events` route block + cap enforcement; existing scaffolding `sseClients`, `pushEvent`, `heartbeat`, `close()` already present from Task 4)
- Test: `src/__tests__/dashboard-sse.test.ts`

**Interfaces:**
- Consumes (Task 4, exact): `startDashboard(opts)` / `DashboardHandle`; internal `sseClients: Set<http.ServerResponse>`, `pushEvent(name, data)`, heartbeat interval writing `: hb\n\n`.
- Produces:
  - `GET /events` → `200 text/event-stream`; immediate comment `: connected\n\n`; named events `report-added` / `report-changed` (from watcher via `pushEvent`) with `data: {"id":...,"ts":...}`.
  - Beyond `opts.maxSseClients` (default 32) → `429 {"error":"too many sse clients"}`.
  - Client `close`/`error` → removed from `sseClients` (no leak); `DashboardHandle.close()` ends every stream.
  - SSE response exempt from request timeout: `res.setTimeout(0)`.

- [ ] **Step 1: Write the failing test**

```ts
// src/__tests__/dashboard-sse.test.ts
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
    const seen = readSse(h.url + '/events', s => s.includes('event: report-added'));
    // give the stream a tick to connect before the write
    await new Promise(r => setTimeout(r, 50));
    fs.writeFileSync(path.join(dir, `${ID}.json`), REPORT);
    const text = await seen;
    expect(text).toContain('event: report-added');
    expect(text).toContain(`"id":"${ID}"`);
    // second write of same content but different size/mtime → report-changed (or add if watcher raced)
    fs.writeFileSync(path.join(dir, `${ID}.json`), REPORT + ' ');
    const h2 = await readSse(h.url + '/events', s => s.includes('event: report-'));
    expect(h2).toMatch(/event: report-(added|changed)/);
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/__tests__/dashboard-sse.test.ts`
Expected: FAIL — no `/events` route (404, `res.body` null → test errors).

- [ ] **Step 3: Implement the `/events` route**

In `src/dashboard-server.ts`, inside `route()` — add before `notFound(res)` (and only in this task; Task 4 left the slot):

```ts
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
```

The watcher→`pushEvent` wiring, heartbeat interval, and `close()` stream teardown already exist from Task 4 — no other edits.

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/__tests__/dashboard-sse.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Full gate + commit**

Run: `npx tsc --noEmit && npx vitest run`
Expected: all green.

```bash
git add src/dashboard-server.ts src/__tests__/dashboard-sse.test.ts
git commit -m "feat(dashboard): SSE /events — named events, 25s heartbeat, 32-client cap, clean teardown

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 6: CLI Command + Export Barrel

**Files:**
- Modify: `src/cli.ts` (USAGE lines; target-required check excludes `dashboard`; `dashboard` command branch; `--port/--host/--poll` parsing; SIGINT/SIGTERM shutdown)
- Modify: `src/index.ts` (export dashboard modules)
- Test: covered by gate + manual smoke (cli is a script-style module; existing repo has no cli unit tests — do not add a new harness)

**Interfaces:**
- Consumes (Tasks 4-5, exact): `startDashboard(opts: DashboardOptions): Promise<DashboardHandle>`, `DashboardHandle { url, port, close() }`, option keys `outputDir/port/host/pollMs/maxSseClients/heartbeatMs/logger`.
- Produces: `parallax dashboard [--port <n>] [--host <addr>] [--output <dir>] [--poll <ms>]`; USAGE documents it; `index.ts` re-exports `startDashboard`, `flattenFindings`, `summarizeReport`, `createReportWatcher`, renderers.

- [ ] **Step 1: Read current CLI structure first**

Run: `grep -n "USAGE\|target\|const command\|case '" src/cli.ts | head -40`
Note exact variable names (`command`, `target`, `config`) and where the target-required check lives (~line 48) so edits land in the right spots. The code below assumes the repo's existing `command`/`target`/`config` names from the earlier read (target check at ~48, `config.target = target` at 55); adjust identifiers if grep shows different names — behavior must match.

- [ ] **Step 2: Edit `src/cli.ts`**

2a. USAGE string — add after the `scan`/`batch`/`discover` lines:

```
  dashboard [options]            Serve live dashboard over report files (no target needed)
    --port <n>                   Dashboard port (default 7700)
    --host <addr>                Bind address (default 127.0.0.1)
    --output <dir>               Watched output dir (default ./output)
    --poll <ms>                  Watcher poll interval (default 1000)
```

2b. Target-required check — extend the condition so `dashboard` is exempt. Change the check (conceptually):

```ts
if (command !== 'dashboard' && !target) { /* existing usage+exit(1) */ }
```

(Exact existing form: keep whatever error text/exit the file already uses; only add the command exemption.)

2c. After the existing option-parsing loop, add cases in the same switch/if-chain style the file uses:

```ts
// inside option loop (same shape as existing --port/--flag handling)
} else if (arg === '--port') { dashOpts.port = Number(args[++i]);
} else if (arg === '--host') { dashOpts.host = args[++i];
} else if (arg === '--poll') { dashOpts.pollMs = Number(args[++i]);
} else if (arg === '--output' && command === 'dashboard') { dashOpts.outputDir = args[++i];
```

Declare near the top of main-equivalent scope:

```ts
const dashOpts: { port?: number; host?: string; pollMs?: number; outputDir?: string } = {};
```

If the file already parses `--output` generically into `config.outputDir`, reuse that instead of adding a second `--output` case (grep `output` first).

2d. Command dispatch — add a branch (before or alongside existing `scan`/`batch`/`discover` dispatch):

```ts
if (command === 'dashboard') {
  const outputDir = dashOpts.outputDir ?? config.outputDir ?? './output';
  const handle = await startDashboard({
    outputDir,
    port: dashOpts.port,
    host: dashOpts.host,
    pollMs: dashOpts.pollMs,
    logger: undefined, // default Logger inside startDashboard
  });
  console.log(`[Parallax] Dashboard: ${handle.url}  (output: ${outputDir})`);
  console.log('[Parallax] Ctrl+C to stop');
  let stopping = false;
  const shutdown = async (sig: string) => {
    if (stopping) { process.exit(1); } // second signal force-exits
    stopping = true;
    console.log(`\n[Parallax] ${sig} — shutting down dashboard`);
    await handle.close();
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  // resolve never: server keeps the loop alive
  await new Promise<never>(() => {});
}
```

If the file's dispatch is not `if (command === ...)`, use its actual structure (grep `discover` shows the pattern).

2e. Import at top:

```ts
import { startDashboard } from './dashboard-server';
```

- [ ] **Step 3: Edit `src/index.ts` barrel**

Append (match the file's existing export style — named vs star):

```ts
export { startDashboard } from './dashboard-server';
export type { DashboardOptions, DashboardHandle } from './dashboard-server';
export { flattenFindings, summarizeReport, isSafeReportId, filterFindings } from './dashboard-findings';
export type { DashFinding, ReportSummary } from './dashboard-findings';
export { createReportWatcher } from './dashboard-watch';
export { shellHtml, listPartial, tablePartial, detailPartial, findingPartial, feedPartial, escapeHtml } from './dashboard-ui';
```

- [ ] **Step 4: Full gate + typecheck of CLI path**

Run: `npx tsc --noEmit && npx vitest run`
Expected: all green (cli.ts compiles; no new unit tests required here).

- [ ] **Step 5: Build + manual smoke**

```bash
npm run build
node dist/cli.js 2>&1 | head -30          # USAGE shows dashboard lines
node dist/cli.js dashboard --port 7799 --output ./output > dash-smoke.log 2>&1 &
sleep 2
curl -s http://127.0.0.1:7799/healthz     # expect {"ok":true,"reports":N}
curl -s http://127.0.0.1:7799/ | grep -o "EventSource" | head -1
kill -INT %1                               # graceful stop; dash-smoke.log shows shutdown line
rm -f dash-smoke.log
```

Expected: healthz 200, EventSource present, Ctrl+C path logs shutdown and exits 0.

- [ ] **Step 6: Commit**

```bash
git add src/cli.ts src/index.ts
git commit -m "feat(dashboard): parallax dashboard CLI command — --port/--host/--poll, graceful SIGINT

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 7: Phase 2 — NDJSON Scan Events + Pipeline Hooks (flag-gated)

**Files:**
- Create: `src/scan-events.ts`
- Modify: `src/types.ts` — `PipelineConfig` gains `enableDashboardEvents?: boolean` and `outputDir?: string` (additive only)
- Modify: `src/pipeline.ts` — private `emitEvent(stage, detail)` + calls at stage anchors (purely additive; every call inside try/catch semantics of `appendScanEvent`)
- Modify: `src/cli.ts` — `--no-scan-events` flag + USAGE line; set `enableDashboardEvents: false`
- Test: `src/__tests__/scan-events.test.ts` (new); update `src/__tests__/pipeline.test.ts` only if a test constructs a full config (verify with grep; construction-only tests need no change)
- Verify: `src/__tests__/dashboard-ndjson.test.ts` additions deferred to Task 8 (tail consumer)

**Interfaces:**
- Consumes: `PipelineConfig` (types.ts:54-85), pipeline stage anchors (line numbers from HEAD read: probe ~89, harvest ~101, timing ~114, discover ~119, deception block ~147, diff ~159, internal ~180, poison ~186, weaponize ~194, result-build/return ~216), `Logger` pattern.
- Produces:
  - `appendScanEvent(outputDir: string, ev: { ts: number; stage: string; detail?: string }): void` — **never throws**; appends one JSON line + `\n` to `outputDir/scan-events.ndjson` (appendFileSync inside try/catch).
  - `ScanEvent = { ts: number; stage: string; detail?: string }` (exported type).
  - `PipelineConfig.enableDashboardEvents?: boolean` — gate is `=== true` **during this task's tests**; after all hook tests pass, flip the production gate to `!== false` (default-on per spec) as the final commit step. `outputDir?: string` on PipelineConfig (mirror of ParallaxConfig).
  - Pipeline `emitEvent(stage: string, detail: string)` — private; no-op unless gated on; resolves dir from `this.config.outputDir ?? './output'`.
  - `--no-scan-events` → `config.enableDashboardEvents = false`.

- [ ] **Step 1: Write the failing test**

```ts
// src/__tests__/scan-events.test.ts
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
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

  it('emitEvent writes when enableDashboardEvents === true', () => {
    const p = pipelineWith(true, dir);
    p.emitEvent('probe', 'cdn=Cloudflare');
    expect(ndjson()).toContain('"stage":"probe"');
  });

  it('emitEvent is a no-op when flag undefined (opt-in phase) or false', () => {
    const p1 = pipelineWith(undefined, dir);
    p1.emitEvent('probe', 'x');
    expect(ndjson()).toBe('');
    const p2 = pipelineWith(false, dir);
    p2.emitEvent('probe', 'x');
    expect(ndjson()).toBe('');
  });

  it('emitEvent never throws even when outputDir is unwritable', () => {
    const asFile = path.join(dir, 'blocked');
    fs.writeFileSync(asFile, 'x');
    const p = pipelineWith(true, asFile);
    expect(() => p.emitEvent('probe', 'x')).not.toThrow();
  });
});
```

Note the gate tests above pin `=== true` (opt-in). Step 6 flips the gate and **rewrites these two tests** to default-on semantics — that flip is an explicit, final micro-step.

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/__tests__/scan-events.test.ts`
Expected: FAIL — `../scan-events` missing.

- [ ] **Step 3: Write `src/scan-events.ts`**

```ts
// src/scan-events.ts
import * as fs from 'fs';
import * as path from 'path';

export interface ScanEvent {
  ts: number;
  stage: string;
  detail?: string;
}

/**
 * Append one NDJSON line to <outputDir>/scan-events.ndjson.
 * NEVER throws — dashboard plumbing must not be able to fail a scan.
 */
export function appendScanEvent(outputDir: string, ev: ScanEvent): void {
  try {
    fs.mkdirSync(outputDir, { recursive: true });
    fs.appendFileSync(
      path.join(outputDir, 'scan-events.ndjson'),
      `${JSON.stringify(ev)}\n`,
      'utf8',
    );
  } catch {
    // best-effort telemetry; swallow (spec: phase-2 append fails → scan unaffected)
  }
}
```

- [ ] **Step 4: Wire `pipeline.ts` + `types.ts`**

4a. `src/types.ts` — inside `PipelineConfig` (after the existing `enableWeaponize?: boolean` or at the flag block), add exactly:

```ts
  /** Phase-2 dashboard telemetry: emit NDJSON scan events (default off until flipped). */
  enableDashboardEvents?: boolean;
  /** Where reports + scan-events.ndjson are written; defaults to './output'. */
  outputDir?: string;
```

4b. `src/pipeline.ts` — add private helper (near `calculatePoisonStats`):

```ts
  /** Phase-2 dashboard telemetry — best-effort, never throws, gate is opt-in. */
  private emitEvent(stage: string, detail: string): void {
    if (this.config.enableDashboardEvents !== true) return;
    appendScanEvent(this.config.outputDir ?? './output', { ts: Date.now(), stage, detail });
  }
```

Import at top:

```ts
import { appendScanEvent } from './scan-events';
```

4c. Insert calls at these anchors (line numbers from HEAD; insert **after** each stage completes):

| After line (approx) | Stage | Call |
|---|---|---|
| 89 `const probeResult = await this.probe.run();` | probe | `this.emitEvent('probe', \`cdn=${probeResult.cdn.name}\`);` |
| 100 `const harvestResult = await this.harvest.run();` | harvest | `this.emitEvent('harvest', 'complete');` |
| 113 (timing block end, inside the `if`) | timing | `this.emitEvent('timing', \`hiddenCache=${probeResult.hiddenCacheDetected}\`);` |
| 119 `const discoverResult = await this.discover(probeResult);` | discover | `this.emitEvent('discover', \`${discoverResult.cachedUrls.length} cached urls\`);` |
| 147 (deception block end — after `findings.length > 0` logging, still inside `if`) | deception | `this.emitEvent('deception', \`${findings.length} finding(s)\`);` — place after `const findings = await deception.run(candidates);` |
| 159 `await this.diff.run(discoverResult.cachedUrls);` | diff | `this.emitEvent('diff', 'complete');` |
| 176 (internal block, after `const findings = await internal.run();`) | internal | `this.emitEvent('internal', \`${findings.length} finding(s)\`);` |
| 186 `await this.poison.run(...)` | poison | `this.emitEvent('poison', \`${this.poison.findings.length} finding(s)\`);` |
| 193 `await this.weaponize.run(this.poison.findings);` | weaponize | `this.emitEvent('weaponize', \`${this.weaponize.results.length} chain(s)\`);` |
| 218 (before `return result;`, after `Pipeline complete` log) | complete | `this.emitEvent('complete', 'pipeline finished');` |

Every call is one line, inside the existing control flow (stage's own `if (enableX !== false)` guards mean skipped stages emit nothing — correct).

- [ ] **Step 5: CLI flag**

`src/cli.ts` option loop:

```ts
} else if (arg === '--no-scan-events') { config.enableDashboardEvents = false;
```

USAGE line:

```
  --no-scan-events            Disable NDJSON stage telemetry (on by default after phase 2)
```

And where the scan/batch config defaults are built, set `config.enableDashboardEvents = true` unless the flag was seen (respect `!== false` gate: simply set `config.enableDashboardEvents ??= true` before dispatch so explicit false wins).

- [ ] **Step 6: Run tests — then FLIP the gate (explicit step)**

Run: `npx vitest run src/__tests__/scan-events.test.ts`
Expected: PASS with `=== true` semantics.

Now flip production default per spec (phase 2 default-on):

In `pipeline.ts` `emitEvent`, change the guard to:

```ts
    if (this.config.enableDashboardEvents === false) return;
```

Rewrite the gate tests in `scan-events.test.ts` accordingly:

```ts
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
```

Run again: PASS.

- [ ] **Step 7: Full gate + commit**

Run: `npx tsc --noEmit && npx vitest run`
Expected: 166 baseline + Tasks 1-6 + scan-events all green.

```bash
git add src/scan-events.ts src/types.ts src/pipeline.ts src/cli.ts src/__tests__/scan-events.test.ts
git commit -m "feat(dashboard): phase-2 NDJSON scan events — emitEvent hooks, flag default-on, --no-scan-events

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 8: NDJSON Tail → SSE `scan-event` + Final Verification

**Files:**
- Create: `src/dashboard-tail.ts`
- Modify: `src/dashboard-server.ts` — create tail next to watcher; `onEvent` → `pushEvent('scan-event', {...})`; stop tail in `close()`
- Modify: `src/index.ts` — export `createNdjsonTail`
- Test: `src/__tests__/dashboard-ndjson.test.ts`

**Interfaces:**
- Consumes: `appendScanEvent` output format (`{ts,stage,detail?}\n` at `outputDir/scan-events.ndjson`), Task 5 `pushEvent` (in server closure).
- Produces:
  - `createNdjsonTail(opts: { file: string; intervalMs?: number; onEvent: (ev: ScanEvent) => void }): { stop(): void }`
  - Semantics: byte-offset poll (stat size > offset → read from offset; new data must end on `\n`; hold back partial last line by keeping `offset` at the last newline boundary; parse each line JSON, skip bad lines; **first successful size observation primes the offset without emitting history** (same quiet-start contract as the watcher)).
  - Server wires: `scan-event` frames `{ts, stage, detail?}`; feed partial shows them; `/partials/feed` includes recent scan events after a scan runs.

- [ ] **Step 1: Write the failing test**

```ts
// src/__tests__/dashboard-ndjson.test.ts
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/__tests__/dashboard-ndjson.test.ts`
Expected: FAIL — `../dashboard-tail` missing; server lacks scan-event wiring.

- [ ] **Step 3: Implement `src/dashboard-tail.ts`**

```ts
// src/dashboard-tail.ts
import * as fs from 'fs';
import type { ScanEvent } from './scan-events';

export interface NdjsonTailOptions {
  file: string;
  /** Poll interval ms, default 1000. */
  intervalMs?: number;
  onEvent: (ev: ScanEvent) => void;
}

export interface NdjsonTail { stop(): void; }

/**
 * Byte-offset NDJSON tail. First successful size observation primes the
 * offset (history never re-emits). Partial last lines are held back until
 * their newline lands. Unparseable lines are skipped. Never throws.
 */
export function createNdjsonTail(opts: NdjsonTailOptions): NdjsonTail {
  let offset = -1; // -1 = unprimed
  let stopped = false;

  const tick = (): void => {
    if (stopped) return;
    try {
      const st = fs.statSync(opts.file);
      if (offset === -1) { offset = st.size; return; } // prime: skip history
      if (st.size <= offset) return;
      const fd = fs.openSync(opts.file, 'r');
      try {
        const len = st.size - offset;
        const buf = Buffer.alloc(len);
        const read = fs.readSync(fd, buf, 0, len, offset);
        const text = buf.subarray(0, read).toString('utf8');
        const lastNl = text.lastIndexOf('\n');
        if (lastNl === -1) return; // still partial — wait for newline
        const complete = text.slice(0, lastNl + 1);
        offset += Buffer.byteLength(complete, 'utf8');
        for (const line of complete.split('\n')) {
          if (!line.trim()) continue;
          try {
            const ev = JSON.parse(line) as ScanEvent;
            if (ev && typeof ev.stage === 'string') opts.onEvent(ev);
          } catch { /* torn/corrupt line — skip */ }
        }
      } finally {
        fs.closeSync(fd);
      }
    } catch {
      // file missing/rotated — retry next tick
    }
  };

  const timer = setInterval(tick, opts.intervalMs ?? 1000);
  tick(); // prime synchronously so history is skipped from the start
  return { stop: () => { stopped = true; clearInterval(timer); } };
}
```

- [ ] **Step 4: Wire into `src/dashboard-server.ts`**

After the existing `watcher` creation:

```ts
  const tail = createNdjsonTail({
    file: path.join(outDir, 'scan-events.ndjson'),
    intervalMs: opts.pollMs ?? 1000,
    onEvent: ev => pushEvent('scan-event', { ts: ev.ts, stage: ev.stage, detail: ev.detail }),
  });
```

Import: `import { createNdjsonTail } from './dashboard-tail';`
In `close()`, add `tail.stop();` next to `watcher.stop();`.
In `src/index.ts` barrel: `export { createNdjsonTail } from './dashboard-tail'; export type { NdjsonTail, NdjsonTailOptions } from './dashboard-tail';`

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run src/__tests__/dashboard-ndjson.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 6: Full gate + commit**

Run: `npx tsc --noEmit && npx vitest run`
Expected: all green (baseline 166 + Tasks 1-8 additions).

```bash
git add src/dashboard-tail.ts src/dashboard-server.ts src/index.ts src/__tests__/dashboard-ndjson.test.ts
git commit -m "feat(dashboard): NDJSON byte-offset tail → SSE scan-event; server wiring + feed

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 9: Final Verification (no new code)

**Files:** none (verification only; fix-forward only if a check fails)

- [ ] **Step 1: Full suite**

```bash
npx tsc --noEmit && npx vitest run
```

Expected: 0 failures. Baseline 166 still present; ~40+ new tests across `dashboard-findings`, `dashboard-watch`, `dashboard-ui`, `dashboard-server`, `dashboard-sse`, `scan-events`, `dashboard-ndjson`.

- [ ] **Step 2: Live end-to-end smoke**

```bash
npm run build
mkdir -p ./output
node dist/cli.js dashboard --port 7700 --output ./output &
sleep 1
curl -s http://127.0.0.1:7700/healthz
# in another moment: drop a report file
node -e "require('fs').writeFileSync('output/parallax-report-'+Date.now()+'.json', JSON.stringify({probe:{cdn:{name:'Cloudflare',confidence:1},proxy:{},framework:{name:'None'},cacheKey:{},hiddenCacheDetected:false},discover:{cachedUrls:[{url:'https://x.test/',cacheStatus:'HIT',cacheHeaders:{},isTargetUrl:true}],uncacheableUrls:[],totalTested:1},diff:[],poison:[],weaponize:[]}))')"
sleep 2
curl -s http://127.0.0.1:7700/api/reports | head -c 300
curl -sN --max-time 2 http://127.0.0.1:7700/events | head -5   # should show : connected + possibly report-added
kill -INT %1
```

Expected: healthz ok; reports list shows the file; events stream connects; SIGINT exits 0 with shutdown log.

- [ ] **Step 3: Spec compliance sweep (manual, 5 min)**

Check each against `docs/superpowers/specs/2026-10-07-dashboard-sse-design.md`:

| Spec item | Where |
|---|---|
| Routes table | Task 4/5 route() |
| XSS escaping partials | Task 3 `escapeHtml` + Task 4 test |
| healthz shape | Task 4 |
| SSE 25s hb / 32 cap / cleanup | Task 5 |
| Graceful shutdown + second-signal force | Task 6 |
| Stat-poll, allowlist, no fs.watch | Task 2 |
| No new deps (package.json unchanged) | `git diff HEAD -- package.json` empty |
| Phase-1 zero pipeline edits / phase-2 flag | Task 7 |
| Vendor htmx 2.0.4 committed, no runtime fetch | Task 4 |
| Bind 127.0.0.1 default | Task 4/6 |
| Baseline 166 intact | Step 1 |

- [ ] **Step 4: Report completion**

Summarize: tasks done, test counts before/after, smoke output, any deviations from plan (none expected). No final mega-commit — history is per-task commits from Tasks 1-8.

---

## Notes for Executors

- Every task ends with `npx tsc --noEmit && npx vitest run` green before commit. Do not batch failures.
- Never change existing tests except the explicit gate-flip rewrite inside Task 7 Step 6.
- `package.json` must remain dependency-identical (`node-fetch` only).
- If vitest watch mode interferes: always `npx vitest run` (no watch).
- Windows: use Git Bash for curl smoke steps; PowerShell lacks `curl` alias semantics for `-sN`.
- Partially-written report files are a normal condition (writer mid-flush), not a bug — parsers skip, next poll retries.
