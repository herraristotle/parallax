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

  it('escapes quote-bearing severity so it cannot break out of the class attribute', () => {
    const evil = [{ ...rows[0], severity: 'x" onmouseover="alert(1)' }];
    for (const html of [tablePartial(evil), findingPartial(evil[0]), detailPartial(SUMMARY, [], { weaponize: [{ chains: [{ impact: { severity: 'x" onmouseover="alert(1)' } }] }] })]) {
      expect(html).toContain('&quot;');
      expect(html).not.toContain('onmouseover="alert(1)"');
      expect(html).not.toMatch(/class="[^"]*x"/); // raw quote terminating the attribute
    }
  });

  it('collapses whitespace in level class so it stays a single CSS class', () => {
    const spaced = [{ ...rows[0], severity: 'HIGH RISK' }];
    expect(tablePartial(spaced)).toContain('class="sev-high-risk"');
  });
});