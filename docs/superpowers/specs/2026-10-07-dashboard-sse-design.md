# Parallax Live Dashboard (SSE + htmx) — Design

Date: 2026-10-07 · Repo: `work/engines/parallax` (HEAD 3fd03f9) · Status: approved design, pre-plan

## Intent

Parallax reports are static files written only after `pipeline.run()` completes; competitor ships a Flask+htmx+SSE dashboard (~892 LOC), we ship static HTML export. Build a live dashboard that reads pipeline JSON reports and streams updates — proxy-agnostic (explicitly not Caido-coupled; B-25's Caido half stays deferred).

User decisions (2026-10-07):
1. **Scope C** — file-watch on report files now; pipeline stage-event hooks (NDJSON) designed in, second phase.
2. **UI scope C** — full dashboard: findings table with server-side filters, per-finding detail panes, chain views, live event feed (htmx-class, not a bare list).
3. **Stack** — stdlib `node:http` + vendored htmx + SSE; NDJSON as the cross-process progress channel. Industry-standard per SSE (Grafana Live / GitHub), htmx+partials (matches competitor's stack), NDJSON (Docker/journald-JSON class).

## Constraints

- No new npm deps. Repo deps stay `node-fetch` only; build stays `tsc` → CommonJS. htmx vendored as a file, served from disk (offline-safe).
- Additive only. No deletions, no changes to pipeline behavior or report schema.
- CLI-first: dashboard is a separate long-lived process watching the output dir; scans and dashboard never couple in-process.
- Default bind `127.0.0.1` (no auth — local tool; do not expose without a reverse proxy).
- Windows dev host: no `fs.watch` (unreliable/double-fire) — use stat polling (`fs.stat` every poll interval, compare `mtimeMs`+`size`). No chokidar.
- Phase 2 event emission hooks must not fail scans (try/catch, best-effort — same rule as pipeline stages).

## Architecture

### Components

**1. `src/dashboard-server.ts`** — stdlib HTTP server, exportable class for tests + CLI entry.

| Route | Serves |
|---|---|
| `GET /` | App shell: inline CSS, `<script src="/vendor/htmx.min.js">`, ~15-line bootstrap (`EventSource('/events')` → `htmx.trigger('body','refresh')`) |
| `GET /vendor/htmx.min.js` | Vendored file `src/vendor/htmx.min.js` (official 2.x min build, committed) |
| `GET /events` | SSE stream (`text/event-stream`, heartbeat every 25s): `report-added`, `report-changed`, `scan-event` |
| `GET /api/reports` | Summary list `[{id, file, target, ts, cdn, counts}]` (id = safe basename) |
| `GET /api/report?id=` | Full `PipelineResult` JSON (or batch file → array, error entries skipped) |
| `GET /api/findings?severity=&type=&q=&source=` | Flattened findings, server-side filter |
| `GET /healthz` | `200 {"ok":true,"reports":N}` liveness probe (no auth needed — localhost) |
| `GET /partials/list` `/partials/table` `/partials/detail?id=` `/partials/feed` | Server-rendered HTML fragments — htmx swaps |

No SSE extension needed: bootstrap calls `htmx.trigger('body', 'refresh')`; partials declare `hx-trigger="refresh from:body"` (plus `every 5s` poll fallback if SSE drops).

**2. `src/dashboard-findings.ts`** — pure normalizer. `flattenFindings(result: PipelineResult | PipelineErrorEntry[]) → DashFinding[]` where

```ts
interface DashFinding {
  id: string;            // stable hash of source+url+kind
  source: 'poison' | 'deception' | 'internal' | 'diff' | 'weaponize';
  url: string;
  classification?: string;  // ExploitClassification or InternalCacheFinding.signal
  confidence?: string;
  severity?: string;        // weaponize chains
  evidence?: string;        // truncated
}
```

Tolerant of absent optional stages (deception/internal only present when 4b/5b ran). Unknown shapes skipped, never thrown.

**3. `src/dashboard-watch.ts`** — output-dir stat-poller (interval injectable, default 1000ms):
- discovers `parallax-report-*.json` + `batch-summary-*.json`
- new/changed (mtimeMs or size delta) → callback → SSE broadcast
- malformed/partial JSON (writer mid-flush) → parse attempt fails → skip, retry next tick, log at debug
- filename allowlist `/^(parallax-report|batch-summary)-[\d-]+\.json$/` — `id` params are basenames only, never path-joined from raw input (traversal guard)

**4. `src/vendor/htmx.min.js`** — committed vendor artifact (~14KB). Retrieved once from official release at implementation time; never fetched at runtime.

**5. Phase 2 — `src/scan-events.ts`** + pipeline hooks:
- `appendScanEvent(outputDir, {ts, stage, detail})` → appends one JSON line to `output/scan-events.ndjson` (try/catch, never throws)
- `pipeline.ts` best-effort calls at stage boundaries (after probe/discover/diff/poison/weaponize, plus Stage 4b/5b), gated by `enableDashboardEvents !== false` on `PipelineConfig` (default **false** in phase 1 so scans are unchanged until wired; default flips to true in phase 2 once tests exist)
- watcher tails ndjson (byte-offset poll) → SSE `scan-event` → feed partial

Filesystem-as-interface: dashboard process never imports pipeline; any other writer (manual, batch) that drops files into output/ just works.

### CLI

```
parallax dashboard [options]
  --port <n>       default 7700
  --output <dir>   default ./output (same default as scan)
  --host <addr>    default 127.0.0.1
  --poll <ms>      watcher interval, default 1000
```

Help text line added; `scan`/`batch`/`discover` untouched.

### Data flow

```
pipeline.run() ──writes──► output/*.json
[batch, phase-2] ──appends──► output/scan-events.ndjson
                                    │ stat-poll / tail (dashboard-watch)
                                    ▼
                          SSE /events ──► browser EventSource
                                    │ htmx.trigger('refresh')
                                    ▼
                     re-fetch /partials/* (filters as query params)
```

## Error handling

| Failure | Behavior |
|---|---|
| Output dir missing/empty | Empty-state partial; watcher creates nothing, keeps polling |
| Malformed report JSON | Skipped + debug log; other reports unaffected |
| Report file half-written | Next tick re-read (stat-delta loop) |
| Port in use | Exit 1, clear message |
| SSE client disconnects | Listener removed, no leak |
| Phase-2 append fails | Swallowed — scan never fails on dashboard |
| Unknown `id` / traversal attempt | 404, allowlist match only |

## Testing (vitest, no real network beyond 127.0.0.1 ephemeral ports)

1. **Normalizer** — full PipelineResult → expected DashFinding rows; error-entry batches skipped; absent optional stages tolerated; unknown classification preserved as string.
2. **Watcher** — temp dir: create → event; modify → event; malformed → no event, no throw; non-matching filename → ignored; injectable interval, no wall-clock sleeps beyond tick.
3. **Server** — start on port 0: `/` shell contains htmx vendor tag; `/api/reports` lists temp-dir files; `/api/report?id=bad` → 404; `/api/findings?severity=high` filters; `/vendor/htmx.min.js` 200; SSE emits `report-added` when watcher fires (read first event, close).
4. **Production behaviors** — XSS: report evidence containing `<script>` comes back escaped from partials; `/healthz` 200 with report count; handler throw → 500, process alive; SIGINT → clean exit; SSE cap → 429.
5. **Phase 2** — `appendScanEvent` writes parseable line; pipeline hook failure → scan unaffected; tail → SSE `scan-event`.

Baseline: 166/166 must stay green; additions land as new test files.

## Phasing

- **Phase 1 (this plan's first deliverable):** server + watcher + normalizer + UI + CLI + vendor. Dashboard works against any completed report on disk. No pipeline.ts edits.
- **Phase 2:** scan-events emission + ndjson tail + feed. Pipeline touch is additive, flag-gated, try/catch.

Both phases in this spec; plan execution delivers phase 1 fully, then phase 2 (user may cut phase 2 at review).

## Production readiness (requirement, 2026-10-07)

Industry-standard bar for a local HTTP service — all mandatory:

| Item | Behavior |
|---|---|
| **XSS escaping** | Reports embed attacker-controlled strings (URLs, headers, evidence). Every value interpolated into server-rendered partials HTML-escaped (`&<>"'`); JSON routes served `application/json` (never re-embedded into HTML unescaped). Test: report containing `<script>` renders inert. |
| **Graceful shutdown** | SIGINT/SIGTERM → stop watcher, close all SSE streams, `server.close()`; process exits 0. Second signal force-exits. |
| **Health** | `GET /healthz` → `200 {"ok":true,"reports":N}` (platform `/health` precedent) — probes liveness without hitting UI. |
| **SSE production behavior** | Heartbeat every 25s (have); concurrent-client cap (default 32) → 429 beyond; per-client listener cleanup on `close`/`error`. |
| **Handler isolation** | Route handler throw → logged 500 JSON, process never crashes; unhandled rejection guard at entrypoint. |
| **Logging** | Existing `Logger` — startup logs bind addr + poll interval; report-change events at debug, warnings on malformed files. |
| **Timeouts** | Node defaults kept (`headersTimeout`/`requestTimeout`); SSE response exempt from body timeout via `res.setTimeout(0)`. |
| **Portability** | Windows-safe stat-poll (have); no POSIX-only APIs; paths via `path`. |

Scope note: external-binary gaps (katana, GAU — R12/R13) are discover-stage items handled by `child_process` spawn against PATH binaries; no Python rewrite, nothing dashboard-side. Platform's own "enterprise bar" (CI, S-1/S-3 hardening, lockfiles — gap-analysis §7) stays platform backlog, not this spec.

## Out of scope

- Auth / TLS / reverse-proxy config (localhost assumption documented; bind 127.0.0.1 is the security boundary).
- Caido/Burp/ZAP integration — dashboard is proxy-agnostic by design.
- Any pipeline behavior change, report schema change, or deletions.
- Mid-scan *findings* streaming (findings only appear when a report file lands; stage progress is phase 2).
- External binary acquisition (katana/GAU) — discover concern, PATH-spawn pattern.
- Auto-opening browser, hot reload, multi-user sessions.

## Risks

1. **htmx vendor provenance** — one-time download from official release, committed, checksum noted in commit message; never executed as a download-at-runtime step.
2. **Poll latency** — 1s default: acceptable for scan-duration events; `--poll` tunable.
3. **Phase-2 default flag** — starts `false`, flips only with tests green; zero behavior change to existing scans in phase 1.
