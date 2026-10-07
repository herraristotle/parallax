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

const LEVEL_CLASS = (v: string): string => `sev-${v.toLowerCase()}`;

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
    es.addEventListener(name, function () { htmx.trigger('body','refresh'); });
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