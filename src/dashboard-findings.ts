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