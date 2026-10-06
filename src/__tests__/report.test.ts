import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { ReportExporter } from '../report';
import { PipelineResult } from '../types';

const SAMPLE_RESULT: PipelineResult = {
  probe: {
    cdn: { name: 'cloudflare', confidence: 0.95, allMatches: { cloudflare: 0.95 } },
    proxy: { name: 'unknown', confidence: 0, allMatches: {} },
    framework: { name: 'nextjs', confidence: 0.90, version: '14.0', allMatches: { nextjs: 0.90 } },
    cacheKey: {
      scheme: true, host: true, hostCaseSensitive: false,
      path: true, pathCaseSensitive: true, pathNormalized: false,
      queryString: true, querySorted: true, port: false,
      headersKeyed: [], fragmentStripped: true,
      rawHeaders: {}, timestamp: '2026-01-01T00:00:00Z',
    },
    hiddenCacheDetected: false,
  },
  discover: { cachedUrls: [], uncacheableUrls: [], totalTested: 32 },
  diff: [],
  poison: [],
  weaponize: [],
};

describe('ReportExporter', () => {
  const outputDir = path.join(process.cwd(), '__test_output');

  beforeEach(() => {
    if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
  });

  afterEach(() => {
    const files = fs.readdirSync(outputDir);
    for (const f of files) fs.unlinkSync(path.join(outputDir, f));
    fs.rmdirSync(outputDir);
  });

  it('should export as JSON', () => {
    const exporter = new ReportExporter(outputDir);
    const filePath = exporter.export(SAMPLE_RESULT, 'json', 'test-report');
    expect(fs.existsSync(filePath)).toBe(true);
    const content = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    expect(content.probe.cdn.name).toBe('cloudflare');
  });

  it('should export as Markdown', () => {
    const exporter = new ReportExporter(outputDir);
    const filePath = exporter.export(SAMPLE_RESULT, 'markdown', 'test-report');
    expect(fs.existsSync(filePath)).toBe(true);
    const content = fs.readFileSync(filePath, 'utf-8');
    expect(content).toContain('# Parallax Cache Analysis Report');
    expect(content).toContain('cloudflare');
  });

  it('should export as HTML', () => {
    const exporter = new ReportExporter(outputDir);
    const filePath = exporter.export(SAMPLE_RESULT, 'html', 'test-report');
    expect(fs.existsSync(filePath)).toBe(true);
    const content = fs.readFileSync(filePath, 'utf-8');
    expect(content).toContain('<!DOCTYPE html>');
    expect(content).toContain('Parallax Report');
  });

  it('should throw on unknown format', () => {
    const exporter = new ReportExporter(outputDir);
    // @ts-expect-error intentional invalid format
    expect(() => exporter.export(SAMPLE_RESULT, 'xml')).toThrow('Unknown format: xml');
  });

  it('should generate filename with timestamp when not provided', () => {
    const exporter = new ReportExporter(outputDir);
    const filePath = exporter.export(SAMPLE_RESULT, 'json');
    expect(fs.existsSync(filePath)).toBe(true);
    expect(path.basename(filePath)).toMatch(/^parallax-report-\d+\.json$/);
  });

  it('should generate markdown with findings when present', () => {
    const resultWithFindings: PipelineResult = {
      ...SAMPLE_RESULT,
      poison: [{
        findings: [{
          inputType: 'header',
          inputName: 'X-Forwarded-Host',
          canary: 'evil.com',
          classification: 'Host Header Injection',
          confidence: 0.9,
          attackClass: 'web-cache-deception',
          blastRadius: { scope: 'site-wide', affectedUrls: 10 },
          reproductionSteps: ['step1'],
        }],
        statistics: { headersTested: 10, headersReflected: 1, headersUnkeyed: 0, classifications: {} },
      }],
    };
    const exporter = new ReportExporter(outputDir);
    const md = exporter.toMarkdown(resultWithFindings);
    expect(md).toContain('Poison Findings');
    expect(md).toContain('Host Header Injection');
  });

  it('summary counts items, not buckets (B-23 metrics fix)', () => {
    const finding = (n: number) => ({
      inputType: 'header',
      inputName: `x-test-${n}`,
      canary: `canary${n}`,
      classification: 'xss',
      confidence: 'CONFIRMED',
      attackClass: 'content_poison',
      blastRadius: { scope: 'global', deviceTypes: ['desktop'] },
    });
    const result: PipelineResult = {
      ...SAMPLE_RESULT,
      diff: [{
        url: 'https://example.com/',
        fuzzResults: [{}, {}, {}, {}],
        unkeyedDelimiters: [],
      }] as any,
      poison: [{
        findings: [finding(1), finding(2), finding(3)] as any,
        statistics: { headersTested: 3, headersReflected: 0, headersUnkeyed: 0, classifications: {} },
      }],
      weaponize: [{
        chains: [
          { finding: finding(1), impact: { severity: 'high', cvss: 8, description: 'd' }, poc: { steps: ['s'], curlCommand: 'curl' }, prerequisites: [] },
          { finding: finding(2), impact: { severity: 'low', cvss: 3, description: 'd' }, poc: { steps: ['s'], curlCommand: 'curl' }, prerequisites: [] },
        ] as any,
        summary: { total: 2, bySeverity: {}, byClass: {} },
      }],
    };
    const exporter = new ReportExporter(outputDir);
    const md = exporter.toMarkdown(result);
    expect(md).toContain('| Diff Results | 4 |');
    expect(md).toContain('| Poison Findings | 3 |');
    expect(md).toContain('| Exploit Chains | 2 |');
  });
});
