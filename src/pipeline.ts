import { PipelineConfig, PipelineResult, ProbeResult, CachedUrl, PathFuzzResult, PoisonFinding, ExploitChain, CacheKeyOracle } from './types';
import { CacheProbe } from './cache-probe';
import { HeaderHarvest } from './header-harvest';
import { CacheDiff, buildWCDUrls } from './cache-diff';
import { CachePoison } from './cache-poison';
import { CacheDeception } from './cache-deception';
import { Weaponize } from './weaponize';
import { Discover } from './discover';
import { CacheTiming } from './cache-timing';
import { HttpClient } from './http-client';

/**
 * ParallaxPipeline — Five-stage differential cache analysis pipeline
 * 
 * Stages:
 * 1. Probe — CDN fingerprint + cache key reversal
 * 2. Discover — Endpoint discovery + cacheability confirmation
 * 3. Timing — Hidden cache detection via timing analysis
 * 4. Diff — Byte-level path delimiter fuzzing (WCD)
 * 5. Poison — Binary search header testing + exploit classification (WCP)
 * 6. Weaponize — PoC generation + blast radius assessment
 */
export class ParallaxPipeline {
  private config: PipelineConfig;
  private probe: CacheProbe;
  private harvest: HeaderHarvest;
  private diff: CacheDiff;
  private poison: CachePoison;
  private weaponize: Weaponize;
  private httpClient: HttpClient;

  constructor(config: PipelineConfig) {
    this.config = config;
    this.httpClient = new HttpClient({ timeoutMs: 10000, rateLimitPerSec: 10 });
    this.probe = new CacheProbe({ target: config.target, cookie: config.cookie, headers: config.headers }, this.httpClient);
    this.harvest = new HeaderHarvest();
    this.diff = new CacheDiff({ target: config.target, cookie: config.cookie, headers: config.headers }, undefined, this.httpClient);
    this.poison = new CachePoison({ 
      target: config.target, 
      cookie: config.cookie, 
      headers: config.headers,
      cdnName: 'unknown', // Will be updated after probe
      framework: 'unknown'
    }, this.httpClient);
    this.weaponize = new Weaponize(config.target);
  }

  async run(): Promise<PipelineResult> {
    console.log(`[Parallax] Starting pipeline for ${this.config.target}`);
    const startTime = Date.now();
    const timeBudget = this.config.timeBudgetMs || 300000;

    const checkTimeBudget = () => {
      if (Date.now() - startTime > timeBudget) {
        throw new Error('Time budget exceeded');
      }
    };

    // Stage 1: Probe
    console.log('[Parallax] Stage 1: Fingerprinting + Cache Key Reversal');
    checkTimeBudget();
    const probeResult = await this.probe.run();
    
    // Update poison config with detected CDN and framework
    (this.poison as any).config.cdnName = probeResult.cdn.name;
    (this.poison as any).config.framework = probeResult.framework.name.toLowerCase();
    // Diff probes framework delimiters first (framework-aware byte priority)
    this.diff.setFramework(probeResult.framework.name);

    // Stage 2: Header Harvest (BigQuery/HTTP Archive wordlist)
    console.log('[Parallax] Stage 2: Header Harvesting');
    checkTimeBudget();
    const harvestResult = await this.harvest.run();
    this.poison.setHarvestedWordlist(harvestResult);

    // Stage 3: Timing (Hidden Cache Detection)
    if (this.config.enableTiming !== false) {
      console.log('[Parallax] Stage 3: Hidden Cache Timing Analysis');
      checkTimeBudget();
      const timing = new CacheTiming({ 
        target: this.config.target, 
        pairsPerGroup: 10,
        pValueThreshold: 0.01
      }, this.httpClient);
      const timingResult = await timing.detectHiddenCache();
      probeResult.hiddenCacheDetected = timingResult.hiddenCacheDetected;
    }

    // Stage 4: Discover
    console.log('[Parallax] Stage 4: Endpoint Discovery + Cacheability');
    checkTimeBudget();
    const discoverResult = await this.discover(probeResult);

    // Stage 4b: Web Cache Deception (Gil 2017) — cache stores dynamic content
    // under static-looking suffixes. Runs over candidate dynamic endpoints
    // (discovered URLs + target itself); cheap and best-effort.
    let deceptionFindings: PipelineResult['deception'];
    if (this.config.enableDeception !== false) {
      console.log('[Parallax] Stage 4b: Web Cache Deception probing');
      checkTimeBudget();
      try {
        const deception = new CacheDeception({
          target: this.config.target,
          cookie: this.config.cookie,
          headers: this.config.headers,
        }, this.httpClient);
        const candidates = [
          this.config.target,
          ...discoverResult.cachedUrls.map(u => u.url),
          ...discoverResult.uncacheableUrls,
        ];
        const findings = await deception.run(candidates);
        if (findings.length > 0) {
          deceptionFindings = findings;
          console.log(`[Parallax]   ${findings.length} deception finding(s), ${findings.filter(f => f.confirmed).length} confirmed`);
        }
      } catch {
        // Deception pass is best-effort; never fail the scan.
      }
    }

    // Stage 5: Diff (WCD) - Byte-level path fuzzing + WCD payloads
    if (this.config.enableDiff !== false) {
      console.log('[Parallax] Stage 5: Byte-level Path Delimiter Fuzzing + WCD');
      checkTimeBudget();
      // Add WCD payloads to test
      const wcdUrls = buildWCDUrls(this.config.target);
      for (const { url } of wcdUrls) {
        discoverResult.cachedUrls.push({ url, cacheStatus: 'UNKNOWN', cacheHeaders: {}, isTargetUrl: false });
      }
      await this.diff.run(discoverResult.cachedUrls);
    }

    // Stage 6: Poison (WCP)
    if (this.config.enablePoison !== false) {
      console.log('[Parallax] Stage 6: Binary Search Header Testing + Classification');
      checkTimeBudget();
      await this.poison.run(discoverResult.cachedUrls, this.config.wordlistTier || 'fast');
    }

    // Stage 7: Weaponize
    if (this.config.enableWeaponize !== false) {
      console.log('[Parallax] Stage 7: PoC Generation + Blast Radius');
      checkTimeBudget();
      await this.weaponize.run(this.poison.findings);
    }

    const result: PipelineResult = {
      probe: probeResult,
      discover: discoverResult,
      diff: this.diff.results.length > 0
        ? [{ url: this.config.target, fuzzResults: this.diff.results, unkeyedDelimiters: this.diff.getUnkeyedDelimiters() }]
        : [],
      poison: this.poison.findings.length > 0
        ? [{
            findings: this.poison.findings,
            statistics: this.calculatePoisonStats()
          }]
        : [],
      weaponize: this.weaponize.results.length > 0
        ? [{
            chains: this.weaponize.results,
            summary: this.calculateWeaponizeSummary()
          }]
        : []
    };
    if (deceptionFindings) result.deception = deceptionFindings;

    console.log('[Parallax] Pipeline complete');
    return result;
  }

  private calculatePoisonStats() {
    const findings = this.poison.findings;
    const headersTested = findings.length; // Approximation
    const headersReflected = findings.filter(f => f.signals.bodyReflection || Object.keys(f.signals.headerReflection).length > 0).length;
    const headersUnkeyed = findings.filter(f => f.oracle?.canaryPersisted).length;
    const classifications: Record<string, number> = {};
    for (const f of findings) {
      classifications[f.classification] = (classifications[f.classification] || 0) + 1;
    }
    return { headersTested, headersReflected, headersUnkeyed, classifications };
  }

  private calculateWeaponizeSummary() {
    const chains = this.weaponize.results;
    const bySeverity: Record<string, number> = {};
    const byClass: Record<string, number> = {};
    for (const chain of chains) {
      bySeverity[chain.impact.severity] = (bySeverity[chain.impact.severity] || 0) + 1;
      byClass[chain.finding.classification] = (byClass[chain.finding.classification] || 0) + 1;
    }
    return { total: chains.length, bySeverity, byClass };
  }

  private async discover(probeResult: ProbeResult): Promise<{ cachedUrls: CachedUrl[]; uncacheableUrls: string[]; totalTested: number }> {
    const discover = new Discover({
      target: this.config.target,
      cookie: this.config.cookie,
      headers: this.config.headers,
    }, this.httpClient);
    return discover.run(probeResult);
  }

  getProbe() { return this.probe; }
  getDiff() { return this.diff; }
  getPoison() { return this.poison; }
  getWeaponize() { return this.weaponize; }
}