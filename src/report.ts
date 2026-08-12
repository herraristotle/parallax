import * as fs from 'fs';
import * as path from 'path';
import { PipelineResult, PoisonFinding, ExploitChain } from './types';

export type ReportFormat = 'json' | 'markdown' | 'html';

export class ReportExporter {
  private outputDir: string;

  constructor(outputDir: string = './output') {
    this.outputDir = outputDir;
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
  }

  export(result: PipelineResult, format: ReportFormat, filename?: string): string {
    const base = filename || `parallax-report-${Date.now()}`;
    let content: string;
    let ext: string;

    switch (format) {
      case 'json':
        content = this.toJSON(result);
        ext = '.json';
        break;
      case 'markdown':
        content = this.toMarkdown(result);
        ext = '.md';
        break;
      case 'html':
        content = this.toHTML(result);
        ext = '.html';
        break;
      default:
        throw new Error(`Unknown format: ${format}`);
    }

    const filePath = path.join(this.outputDir, `${base}${ext}`);
    fs.writeFileSync(filePath, content);
    return filePath;
  }

  toJSON(result: PipelineResult): string {
    return JSON.stringify(result, null, 2);
  }

  toMarkdown(result: PipelineResult): string {
    const lines: string[] = [
      '# Parallax Cache Analysis Report',
      '',
      `**Date:** ${new Date().toISOString()}`,
      '',
      '## Summary',
      '',
      `| Metric | Value |`,
      `|--------|-------|`,
      `| CDN Detected | ${result.probe.cdn.name} (${Math.round(result.probe.cdn.confidence * 100)}%) |`,
      `| Proxy Detected | ${result.probe.proxy.name} (${Math.round(result.probe.proxy.confidence * 100)}%) |`,
      `| Framework Detected | ${result.probe.framework.name} |`,
      `| Hidden Cache Detected | ${result.probe.hiddenCacheDetected ? 'Yes' : 'No'} |`,
      `| Cached URLs Found | ${result.discover.cachedUrls.length} |`,
      `| Diff Results | ${result.diff.length} |`,
      `| Poison Findings | ${result.poison.length} |`,
      `| Exploit Chains | ${result.weaponize.length} |`,
      '',
    ];

    if (result.poison.length > 0) {
      lines.push('## Poison Findings', '');
      for (const pr of result.poison) {
        for (const f of pr.findings) {
          lines.push(`### ${f.classification} (${f.confidence})`, '');
          lines.push(`- **Input:** ${f.inputType} "${f.inputName}"`);
          lines.push(`- **Canary:** \`${f.canary}\``);
          lines.push(`- **Attack Class:** ${f.attackClass}`);
          lines.push(`- **Blast Radius:** ${f.blastRadius.scope}`);
          lines.push('');
        }
      }
    }

    if (result.weaponize.length > 0) {
      lines.push('## Exploit Chains', '');
      for (const wr of result.weaponize) {
        for (const chain of wr.chains) {
          lines.push(`### ${chain.impact.severity.toUpperCase()} — ${chain.finding.classification}`, '');
          lines.push(`**CVSS:** ${chain.impact.cvss}`, '');
          lines.push(`**Impact:** ${chain.impact.description}`, '');
          lines.push('**Steps:**', '');
          for (const step of chain.poc.steps) {
            lines.push(`${step}`);
          }
          lines.push('');
          lines.push('**curl Command:**', '```bash');
          lines.push(chain.poc.curlCommand);
          lines.push('```', '');
          lines.push('**Prerequisites:**');
          for (const prereq of chain.prerequisites) {
            lines.push(`- ${prereq}`);
          }
          lines.push('');
        }
      }
    }

    return lines.join('\n');
  }

  toHTML(result: PipelineResult): string {
    const markdown = this.toMarkdown(result);
    return `<!DOCTYPE html>
<html>
<head>
  <title>Parallax Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background: #f5f5f5; }
    code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; }
    pre { background: #f5f5f5; padding: 16px; border-radius: 4px; overflow-x: auto; }
    h1 { border-bottom: 2px solid #333; padding-bottom: 8px; }
    h2 { border-bottom: 1px solid #ccc; padding-bottom: 4px; }
    .critical { color: #d32f2f; font-weight: bold; }
    .high { color: #f57c00; font-weight: bold; }
    .medium { color: #fbc02d; }
    .low { color: #388e3c; }
  </style>
</head>
<body>
  <pre>${markdown.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>
</body>
</html>`;
  }
}
