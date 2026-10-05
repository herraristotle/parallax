#!/usr/bin/env node

import { ParallaxPipeline } from './pipeline';
import { ParallaxConfigLoader } from './config';
import { Logger } from './logger';
import { ReportExporter, ReportFormat } from './report';
import { PipelineResult } from './types';

const USAGE = `
Parallax Cache Toolkit — Differential cache analysis for web cache poisoning

Usage:
  parallax scan <target> [options]     Scan a target URL
  parallax batch <file> [options]      Scan multiple targets from file
  parallax discover <target>           Discover cacheable endpoints
  parallax --help                      Show this help

Options:
  --profile <name>          Use config profile (fast/full/stealth)
  --cookie <cookie>         Cookie header for authenticated scans
  --header <key:value>      Custom header (repeatable)
  --wordlist <tier>         Wordlist tier: fast (curated + top harvest) or all (full harvest)
  --output <dir>            Output directory (default: ./output)
  --format <fmt>            Report format: json, markdown, html
  --log-level <level>       Log level: debug, info, warn, error
  --no-timing               Disable hidden cache timing detection
  --no-diff                 Disable byte-level diff fuzzing
  --no-poison               Disable header poisoning scan
  --no-deception            Disable web cache deception probing
  --no-weaponize            Disable exploit chain generation
`;

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('--help')) {
    console.log(USAGE);
    process.exit(0);
  }

  const command = args[0];
  const target = args[1];

  if (!target && command !== '--help' && command !== 'batch') {
    console.error('Error: target required');
    console.log(USAGE);
    process.exit(1);
  }

  const config = ParallaxConfigLoader.load();
  config.target = target;

  // Parse CLI options
  for (let i = 2; i < args.length; i++) {
    switch (args[i]) {
      case '--profile':
        config.profile = args[++i] as 'fast' | 'full' | 'stealth';
        break;
      case '--cookie':
        config.cookie = args[++i];
        break;
      case '--header': {
        const headerArg = args[++i];
        const colonIdx = headerArg.indexOf(':');
        if (colonIdx > 0) {
          if (!config.headers) config.headers = {};
          config.headers[headerArg.substring(0, colonIdx)] = headerArg.substring(colonIdx + 1).trim();
        } else {
          console.warn(`Warning: Invalid header format (missing colon): ${headerArg}`);
        }
        break;
      }
      case '--wordlist':
        config.wordlistTier = args[++i] as 'fast' | 'all';
        break;
      case '--output':
        config.outputDir = args[++i];
        break;
      case '--log-level':
        config.logLevel = args[++i] as 'debug' | 'info' | 'warn' | 'error';
        break;
      case '--no-timing':
        config.enableTiming = false;
        break;
      case '--no-diff':
        config.enableDiff = false;
        break;
      case '--no-poison':
        config.enablePoison = false;
        break;
      case '--no-deception':
        config.enableDeception = false;
        break;
      case '--no-weaponize':
        config.enableWeaponize = false;
        break;
    }
  }

  const logger = new Logger('cli', config.logLevel || 'info');

  if (command === 'scan') {
    logger.info(`Starting scan of ${target}`, {
      profile: config.wordlistTier,
      timing: config.enableTiming,
      diff: config.enableDiff,
      poison: config.enablePoison,
    });

    const pipeline = new ParallaxPipeline(config);
    const result = await pipeline.run();

    const exporter = new ReportExporter(config.outputDir);
    const reportPath = exporter.export(result, 'json');
    logger.info(`Report saved to ${reportPath}`);

    const mdPath = exporter.export(result, 'markdown');
    logger.info(`Markdown report saved to ${mdPath}`);

    // Summary
    const totalFindings = result.poison.reduce((sum, p) => sum + p.findings.length, 0);
    const totalChains = result.weaponize.reduce((sum, w) => sum + w.chains.length, 0);

    console.log('\n=== Scan Complete ===');
    console.log(`CDN: ${result.probe.cdn.name} (${Math.round(result.probe.cdn.confidence * 100)}%)`);
    console.log(`Cached URLs: ${result.discover.cachedUrls.length}`);
    console.log(`Findings: ${totalFindings}`);
    console.log(`Exploit Chains: ${totalChains}`);
    console.log(`Reports: ${reportPath}, ${mdPath}`);
  } else if (command === 'batch') {
    // Batch command: read targets from file
    const fs = await import('fs');
    const filePath = target; // for batch, target is the file path
    if (!fs.existsSync(filePath)) {
      console.error(`Error: file not found: ${filePath}`);
      process.exit(1);
    }
    const content = fs.readFileSync(filePath, 'utf-8');
    const urls = content.split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));
    
    if (urls.length === 0) {
      console.error('No URLs found in file');
      process.exit(1);
    }
    
    console.log(`[Parallax] Batch scanning ${urls.length} targets from ${filePath}`);
    
    const exporter = new ReportExporter(config.outputDir);
    const allResults: PipelineResult[] = [];
    
    for (let i = 0; i < urls.length; i++) {
      const url = urls[i];
      console.log(`\n[${i + 1}/${urls.length}] Scanning ${url}`);
      config.target = url;
      
      try {
        const pipeline = new ParallaxPipeline(config);
        const result = await pipeline.run();
        allResults.push(result);
        
        const reportPath = exporter.export(result, 'json');
        const mdPath = exporter.export(result, 'markdown');
        
        const totalFindings = result.poison.reduce((sum: number, p: any) => sum + p.findings.length, 0);
        const totalChains = result.weaponize.reduce((sum: number, w: any) => sum + w.chains.length, 0);
        console.log(`  CDN: ${result.probe.cdn.name} (${Math.round(result.probe.cdn.confidence * 100)}%)`);
        console.log(`  Cached URLs: ${result.discover.cachedUrls.length}`);
        console.log(`  Findings: ${totalFindings}`);
        console.log(`  Exploit Chains: ${totalChains}`);
        console.log(`  Reports: ${reportPath}, ${mdPath}`);
      } catch (err) {
        console.error(`  Error scanning ${url}:`, err);
        allResults.push({ target: url, error: String(err) } as any);
      }
    }
    
    // Write batch summary
    const summaryPath = `${config.outputDir}/batch-summary-${Date.now()}.json`;
    fs.writeFileSync(summaryPath, JSON.stringify(allResults, null, 2));
    console.log(`\n=== Batch Complete ===`);
    console.log(`Scanned: ${urls.length} targets`);
    console.log(`Summary: ${summaryPath}`);
    const totalFindings = allResults.reduce(
      (sum, r) => sum + ((r.poison ?? []).reduce((s: number, p: any) => s + p.findings.length, 0) ?? 0),
      0
    );
    const totalChains = allResults.reduce(
      (sum, r) => sum + ((r.weaponize ?? []).reduce((s: number, w: any) => s + w.chains.length, 0) ?? 0),
      0
    );
    console.log(`Targets scanned: ${urls.length}`);
    console.log(`Total findings: ${totalFindings}`);
    console.log(`Total exploit chains: ${totalChains}`);
  } else if (command === 'discover') {
    const { Discover } = await import('./discover');
    const discover = new Discover({
      target,
      cookie: config.cookie,
      headers: config.headers,
    });

    const probeResult = await new ParallaxPipeline(config).getProbe().run();
    const result = await discover.run(probeResult);

    console.log(`\n=== Discovery Complete ===`);
    console.log(`Cached URLs: ${result.cachedUrls.length}`);
    console.log(`Uncacheable URLs: ${result.uncacheableUrls.length}`);
    console.log(`Total Tested: ${result.totalTested}`);

    for (const url of result.cachedUrls) {
      console.log(`  [${url.cacheStatus}] ${url.url}`);
    }
  } else {
    console.error(`Unknown command: ${command}`);
    console.log(USAGE);
    process.exit(1);
  }
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
