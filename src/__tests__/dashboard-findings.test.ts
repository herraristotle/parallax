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
      originServed: true, cached: true, confirmed: false,
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

  it('poison rows differing only by canary get distinct ids', () => {
    const r = fixture();
    r.poison[0].findings.push({ ...r.poison[0].findings[0], canary: 'c2' });
    const rows = flattenFindings(ID, r).filter(x => x.source === 'poison');
    expect(rows).toHaveLength(2);
    expect(new Set(rows.map(x => x.id)).size).toBe(2);
  });

  it('weaponize chains differing only by poc get distinct ids', () => {
    const r = fixture();
    r.weaponize[0].chains.push({
      ...r.weaponize[0].chains[0],
      poc: { curlCommand: 'curl -X POST https://a.test/page' },
    });
    const rows = flattenFindings(ID, r).filter(x => x.source === 'weaponize');
    expect(rows).toHaveLength(2);
    expect(new Set(rows.map(x => x.id)).size).toBe(2);
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