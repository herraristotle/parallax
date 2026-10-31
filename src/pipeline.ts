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
import { InteractshClient } from './oob';
import { CacheInternal } from './cache-internal';
import { TraceSink } from './trace';
import { appendScanEvent } from './scan-events';
import { ExploitExecutor } from './exploit';

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
  private oob: InteractshClient | null = null;
  private trace?: TraceSink;
  /** Query params found unkeyed by probe — counted as findings in run.summary. */
  private unkeyedParams: string[] = [];
  /** Deception findings from stage 4b — counted in run.summary. */
  private deceptionCount: number = 0;
  /** Confirmed exploit executions (stage 8) — counted in run.summary. */
  private executedSolved: number = 0;

  constructor(config: PipelineConfig) {
    this.config = config;
    if (config.traceFile) {
      this.trace = new TraceSink(config.traceFile);
      this.trace.event('run.start', { target: config.target });
    }
    this.httpClient = new HttpClient({
      timeoutMs: 10000,
      rateLimitPerSec: config.rateLimitPerSec ?? 10,
      http2: config.http2 === true,
      trace: this.trace,
    });
    this.probe = new CacheProbe({ target: config.target, cookie: config.cookie, headers: config.headers }, this.httpClient);
    this.harvest = new HeaderHarvest({
      bigQueryProject: config.bigQueryProject,
      bigQueryCredentialsPath: config.bigQueryCredentialsPath,
      bigQuerySql: config.bigQuerySql,
    });
    this.diff = new CacheDiff({ target: config.target, cookie: config.cookie, headers: config.headers }, undefined, this.httpClient);
    this.poison = new CachePoison({ 
      target: config.target, 
      cookie: config.cookie, 
      headers: config.headers,
      cdnName: 'unknown', // Will be updated after probe
      framework: 'unknown'
    }, this.httpClient);
    this.weaponize = new Weaponize(config.target);
    // OOB client: only when configured and not disabled; register() is
    // attempted lazily at run() so constructor never does I/O.
    if (config.oob && config.enableOob !== false) {
      this.oob = new InteractshClient(config.oob);
      this.poison.setOob(this.oob);
    }
  }

  async run(): Promise<PipelineResult> {
    try {
      return await this.runStages();
    } finally {
      this.trace?.summary({
        findings: this.summaryFindings(),
        tools: { external: this.config.external === true },
      });
    }
  }

  /** Pull probe-side findings (unkeyed query params) into summary scope. */
  private captureProbeFindings(probeResult: { cacheKey?: { unkeyedParams?: string[] } }): void {
    this.unkeyedParams = probeResult.cacheKey?.unkeyedParams ?? [];
  }

  private summaryFindings(): number {
    return (
      this.poison.findings.length +
      this.weaponize.results.length +
      (this.diff.results.length > 0 ? 1 : 0) +
      this.unkeyedParams.length +
      this.deceptionCount +
      this.executedSolved
    );
  }

  private async runStages(): Promise<PipelineResult> {
    console.log(`[Parallax] Starting pipeline for ${this.config.target}`);
    const startTime = Date.now();
    const timeBudget = this.config.timeBudgetMs || 300000;
    this.trace?.setStage('init');

    // OOB registration is best-effort — failure disables the client, scan continues.
    if (this.oob) {
      const ok = await this.oob.register();
      if (!ok) {
        console.log('[Parallax]   OOB register failed — continuing without callback evidence');
        this.oob = null;
        this.poison.setOob(null);
      }
    }

    const checkTimeBudget = () => {
      if (Date.now() - startTime > timeBudget) {
        throw new Error('Time budget exceeded');
      }
    };

    // Stage 1: Probe
    console.log('[Parallax] Stage 1: Fingerprinting + Cache Key Reversal');
    this.trace?.setStage('probe');
    checkTimeBudget();
    const probeResult = await this.probe.run();
    this.captureProbeFindings(probeResult);
    this.emitEvent('probe', `cdn=${probeResult.cdn.name}`);
    
    // Update poison config with detected CDN and framework
    (this.poison as any).config.cdnName = probeResult.cdn.name;
    (this.poison as any).config.framework = probeResult.framework.name.toLowerCase();
    // Diff probes framework delimiters first (framework-aware byte priority)
    this.diff.setFramework(probeResult.framework.name);

    // Stage 2: Header Harvest (BigQuery/HTTP Archive wordlist)
    console.log('[Parallax] Stage 2: Header Harvesting');
    this.trace?.setStage('harvest');
    checkTimeBudget();
    const harvestResult = await this.harvest.run();
    this.emitEvent('harvest', 'complete');
    this.poison.setHarvestedWordlist(harvestResult);

    // Stage 3: Timing (Hidden Cache Detection)
    if (this.config.enableTiming !== false) {
      console.log('[Parallax] Stage 3: Hidden Cache Timing Analysis');
      this.trace?.setStage('timing');
      checkTimeBudget();
      const timing = new CacheTiming({ 
        target: this.config.target, 
        pairsPerGroup: 10,
        pValueThreshold: 0.01
      }, this.httpClient);
      const timingResult = await timing.detectHiddenCache();
      probeResult.hiddenCacheDetected = timingResult.hiddenCacheDetected;
      this.emitEvent('timing', `hiddenCache=${probeResult.hiddenCacheDetected}`);
    }

    // Stage 4: Discover
    console.log('[Parallax] Stage 4: Endpoint Discovery + Cacheability');
    this.trace?.setStage('discover');
    checkTimeBudget();
    const discoverResult = await this.discover(probeResult);
    this.emitEvent('discover', `${discoverResult.cachedUrls.length} cached urls`);

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
        this.emitEvent('deception', `${findings.length} finding(s)`);
        if (findings.length > 0) {
          deceptionFindings = findings;
          this.deceptionCount = findings.length;
          console.log(`[Parallax]   ${findings.length} deception finding(s), ${findings.filter(f => f.confirmed).length} confirmed`);
        }
      } catch {
        // Deception pass is best-effort; never fail the scan.
      }
    }

    // Stage 5: Diff (WCD) - Byte-level path fuzzing + WCD payloads
    if (this.config.enableDiff !== false) {
      console.log('[Parallax] Stage 5: Byte-level Path Delimiter Fuzzing + WCD');
      this.trace?.setStage('diff');
      checkTimeBudget();
      // Add WCD payloads to test
      const wcdUrls = buildWCDUrls(this.config.target);
      for (const { url } of wcdUrls) {
        discoverResult.cachedUrls.push({ url, cacheStatus: 'UNKNOWN', cacheHeaders: {}, isTargetUrl: false });
      }
      await this.diff.run(discoverResult.cachedUrls);
      this.emitEvent('diff', 'complete');
    }

    // Stage 5b: Internal cache / ESI detection (Kettle) — best-effort like 4b.
    let internalFindings: PipelineResult['internal'];
    if (this.config.enableInternalCache !== false) {
      console.log('[Parallax] Stage 5b: Internal cache + ESI detection');
      checkTimeBudget();
      try {
        const internal = new CacheInternal(
          { target: this.config.target, cookie: this.config.cookie, headers: this.config.headers },
          this.httpClient,
          this.oob,
        );
        const findings = await internal.run();
        this.emitEvent('internal', `${findings.length} finding(s)`);
        if (findings.length > 0) {
          internalFindings = findings;
          console.log(`[Parallax]   ${findings.length} internal-cache finding(s)`);
        }
      } catch {
        // Internal-cache pass is best-effort; never fail the scan.
      }
    }

    // Stage 6: Poison (WCP)
    if (this.config.enablePoison !== false) {
      console.log('[Parallax] Stage 6: Binary Search Header Testing + Classification');
      this.trace?.setStage('poison');
      checkTimeBudget();
      await this.poison.run(discoverResult.cachedUrls, this.config.wordlistTier || 'fast');
      this.emitEvent('poison', `${this.poison.findings.length} finding(s)`);
    }

    // Stage 7: Weaponize
    if (this.config.enableWeaponize !== false) {
      console.log('[Parallax] Stage 7: PoC Generation + Blast Radius');
      this.trace?.setStage('weaponize');
      checkTimeBudget();
      try {
        await this.weaponize.run(this.poison.findings);
      } catch {
        // Weaponize is best-effort — never fail the scan.
      }
      this.emitEvent('weaponize', `${this.weaponize.results.length} chain(s)`);
    }

    // Stage 8: Execute — replay weaponize PoCs against the target (autonomous exploit).
    // Best-effort: never fails the scan. Skipped unless explicitly enabled.
    if (this.config.enableExecute === true) {
      console.log('[Parallax] Stage 8: Autonomous exploit execution');
      this.trace?.setStage('execute');
      checkTimeBudget();
      try {
        const executor = new ExploitExecutor({
          target: this.config.target,
          cookie: this.config.cookie,
          headers: this.config.headers,
          payloadHost: this.config.payloadHost,
          http: this.httpClient,
        });
        let solved = 0;
        let browserWarned = false;
        for (const finding of this.poison.findings) {
          try {
            // Browser confirmation fires alert() → PortSwigger-style lab hooks report the solve.
            const r = await executor.execute(finding);
            if (r.cachePoisoned) {
              solved++;
              console.log(`[Parallax]   executed ${finding.classification} via ${finding.inputName} → cache poisoned`);
            }
            // A cache poison with no browser confirmation is HTTP-only evidence.
            // Say so once per cause instead of dropping it on the floor.
            if (r.browserError && !browserWarned) {
              browserWarned = true;
              console.warn(`[Parallax]   ${r.browserError} — cache poisons below are HTTP-confirmed only`);
            }
          } catch {
            // Per-finding failure — keep executing the rest.
          }
        }
        // Deception execution: prime with auth, verify unauthenticated leak.
        if (deceptionFindings) {
          for (const d of deceptionFindings) {
            try {
              const r = await executor.executeDeception(d.endpoint, d.attackUrl, this.config.cookie);
              if (r.leaked) {
                solved++;
                console.log(`[Parallax]   executed deception leak on ${d.attackUrl}`);
              }
            } catch {
              // Best-effort.
            }
          }
        }
        // Reflection-gadget execution (Param Miner / HCache style): brute-force
        // params for unkeyed+reflected sinks, then poison with context-correct
        // XSS payload and confirm in headless browser.
        try {
          const extras =
            this.config.wordlistTier === 'all' ? CacheProbe.bundledParamWordlist() : undefined;
          const gadgets = await this.probe.discoverReflectionGadgets(this.httpClient, extras, { mineTarget: true });
          if (gadgets.length > 0) {
            this.emitEvent('gadgets', `${gadgets.length} found`);
            console.log(`[Parallax]   ${gadgets.length} reflection gadget(s): ${gadgets.map(g => `${g.param}(${g.context})`).join(', ')}`);
          }
          for (const gadget of gadgets) {
            try {
              const r = await executor.executeGadget(gadget);
              if (r.cachePoisoned) {
                solved++;
                console.log(`[Parallax]   executed gadget ${gadget.param} (${gadget.context}) → cache poisoned${r.alertFired ? ', alert fired' : ''}`);
                if (r.browserError && !browserWarned) {
                  browserWarned = true;
                  console.warn(`[Parallax]   ${r.browserError} — cache poisons below are HTTP-confirmed only`);
                }
              }
            } catch {
              // Per-gadget failure — keep going.
            }
          }
        } catch {
          // Gadget discovery is best-effort.
        }
        this.executedSolved = solved;
        this.emitEvent('execute', `${solved} confirmed`);
      } catch {
        // Execution pass is best-effort; never fail the scan.
      }
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
    if (internalFindings) result.internal = internalFindings;

    console.log('[Parallax] Pipeline complete');
    this.emitEvent('complete', 'pipeline finished');
    return result;
  }

  /** Phase-2 dashboard telemetry — best-effort, never throws, on unless explicitly disabled. */
  private emitEvent(stage: string, detail: string): void {
    if (this.config.enableDashboardEvents === false) return;
    appendScanEvent(this.config.outputDir ?? './output', { ts: Date.now(), stage, detail });
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
      wordlist: this.config.wordlistTier === 'all' ? 'all' : 'fast',
      external: this.config.external,
      exec: this.config.exec,
    }, this.httpClient);
    return discover.run(probeResult);
  }

  getProbe() { return this.probe; }
  getDiff() { return this.diff; }
  getPoison() { return this.poison; }
  getWeaponize() { return this.weaponize; }
  getOob() { return this.oob; }
}