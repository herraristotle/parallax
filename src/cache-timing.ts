import { HttpClient } from './http-client';

export interface CacheTimingConfig {
  target: string;
  cookie?: string;
  headers?: Record<string, string>;
  pairsPerGroup?: number;
  pValueThreshold?: number;
  outlierStddevMultiplier?: number;
  negativeAmplification?: number;
}

export interface TimingResult {
  url: string;
  hiddenCacheDetected: boolean;
  pValue: number;
  meanRandomized: number;
  meanFixed: number;
  sampleSize: number;
}

export interface TTestResult {
  tStatistic: number;
  pValue: number;
  significant: boolean;
}

export interface CacheBusters {
  query: string;
  origin: string;
  'user-agent': string;
  'x-forwarded-host': string;
  'x-forwarded-scheme': string;
  'x-method-override': string;
  varyHeaders: string[];
}

export class CacheTiming {
  private config: Required<CacheTimingConfig>;
  private http: HttpClient;

  constructor(config: CacheTimingConfig, httpClient?: HttpClient) {
    this.config = {
      target: config.target,
      pairsPerGroup: config.pairsPerGroup ?? 10,
      pValueThreshold: config.pValueThreshold ?? 0.01,
      outlierStddevMultiplier: config.outlierStddevMultiplier ?? 2,
      negativeAmplification: config.negativeAmplification ?? 5,
    };
    this.http = httpClient || new HttpClient({ timeoutMs: 10000, rateLimitPerSec: 4 });
  }

  async detectHiddenCache(): Promise<TimingResult> {
    const randomizedTimings: number[] = [];
    const fixedTimings: number[] = [];
    const previouslyUsedCacheBusters: string[] = [];

    for (let i = 0; i < this.config.pairsPerGroup; i++) {
      await this.sleep(500);

      // Randomized group: both fresh cache busters
      const randBuster1 = this.randomString(8);
      const randBuster2 = this.randomString(8);
      const [t1, t2] = await this.sendPairedRequests(randBuster1, randBuster2);
      randomizedTimings.push(t2 - t1);

      // Fixed group: first fresh, second previously used
      const freshBuster = this.randomString(8);
      const fixedBuster = previouslyUsedCacheBusters[0] || this.randomString(8);
      previouslyUsedCacheBusters.push(freshBuster);

      const [t3, t4] = await this.sendPairedRequests(freshBuster, fixedBuster);
      fixedTimings.push(t4 - t3);
    }

    // Outlier removal
    const cleanedRandomized = this.removeOutliers(randomizedTimings);
    const cleanedFixed = this.removeOutliers(fixedTimings);

    // Negative amplification for fixed group
    const meanFixed = this.mean(cleanedFixed);
    const amplifiedFixed = meanFixed < 0
      ? cleanedFixed.map(v => v < 0 ? v * this.config.negativeAmplification : v)
      : cleanedFixed;

    // Welch's t-test
    const tTest = this.welchTTest(cleanedRandomized, amplifiedFixed);

    return {
      url: this.config.target,
      hiddenCacheDetected: tTest.significant && meanFixed < 0,
      pValue: tTest.pValue,
      meanRandomized: this.mean(cleanedRandomized),
      meanFixed,
      sampleSize: cleanedRandomized.length,
    };
  }

  async sendPairedRequests(cacheBuster1: string, cacheBuster2: string): Promise<[number, number]> {
    const url1 = this.appendCacheBuster(this.config.target, cacheBuster1);
    const url2 = this.appendCacheBuster(this.config.target, cacheBuster2);

    const start1 = Date.now();
    await this.http.get(url1);
    const t1 = Date.now() - start1;

    const start2 = Date.now();
    await this.http.get(url2);
    const t2 = Date.now() - start2;

    return [t1, t2];
  }

  welchTTest(sample1: number[], sample2: number[]): TTestResult {
    const n1 = sample1.length;
    const n2 = sample2.length;
    if (n1 < 2 || n2 < 2) return { tStatistic: 0, pValue: 1, significant: false };

    const mean1 = this.mean(sample1);
    const mean2 = this.mean(sample2);
    const var1 = this.variance(sample1);
    const var2 = this.variance(sample2);

    const se = Math.sqrt(var1 / n1 + var2 / n2);
    if (se === 0) return { tStatistic: 0, pValue: 1, significant: false };

    const t = (mean1 - mean2) / se;

    // Welch-Satterthwaite degrees of freedom
    const num = Math.pow(var1 / n1 + var2 / n2, 2);
    const den = Math.pow(var1 / n1, 2) / (n1 - 1) + Math.pow(var2 / n2, 2) / (n2 - 1);
    const df = num / den;

    // Approximate p-value using t-distribution
    const pValue = this.tDistPValue(Math.abs(t), df);

    return {
      tStatistic: t,
      pValue,
      significant: pValue < this.config.pValueThreshold,
    };
  }

  removeOutliers(data: number[]): number[] {
    const m = this.mean(data);
    const s = Math.sqrt(this.variance(data));
    if (s === 0) return [...data];
    return data.filter(v => Math.abs(v - m) <= this.config.outlierStddevMultiplier * s);
  }

  generateCacheBusters(): CacheBusters {
    return {
      query: `_cb=${this.randomString(12)}`,
      origin: `Origin: https://${this.randomString(8)}.example.com`,
      'user-agent': `Parallax/${this.randomString(6)}`,
      'x-forwarded-host': this.randomString(10),
      'x-forwarded-scheme': this.randomString(8),
      'x-method-override': this.randomString(8),
      varyHeaders: [],
    };
  }

  private appendCacheBuster(url: string, buster: string): string {
    const parsed = new URL(url);
    parsed.searchParams.set('_cache_buster', buster);
    return parsed.toString();
  }

  private mean(arr: number[]): number {
    return arr.reduce((a, b) => a + b, 0) / arr.length;
  }

  private variance(arr: number[]): number {
    const m = this.mean(arr);
    return arr.reduce((sum, v) => sum + Math.pow(v - m, 2), 0) / (arr.length - 1);
  }

  private tDistPValue(t: number, df: number): number {
    const x = df / (df + t * t);
    const a = df / 2;
    const b = 0.5;
    const p = this.incompleteBeta(x, a, b);
    return Math.min(1, Math.max(0, p));
  }

  private incompleteBeta(x: number, a: number, b: number): number {
    if (x === 0 || x === 1) return x;
    const lnBeta = this.lnGamma(a) + this.lnGamma(b) - this.lnGamma(a + b);
    const front = Math.exp(Math.log(x) * a + Math.log(1 - x) * b - lnBeta) / a;

    let f = 1, c = 1, d = 0;
    for (let i = 0; i <= 200; i++) {
      const m = Math.floor(i / 2);
      let numerator: number;
      if (i === 0) numerator = 1;
      else if (i % 2 === 0) numerator = (m * (b - m) * x) / ((a + 2 * m - 1) * (a + 2 * m));
      else numerator = -((a + m) * (a + b + m) * x) / ((a + 2 * m) * (a + 2 * m + 1));

      d = 1 + numerator * d;
      if (Math.abs(d) < 1e-30) d = 1e-30;
      d = 1 / d;

      c = 1 + numerator / c;
      if (Math.abs(c) < 1e-30) c = 1e-30;

      f *= d * c;
    }

    return front * (f - 1);
  }

  private lnGamma(x: number): number {
    const c = [76.18009172947146, -86.50532032941677, 24.01409824083091,
      -1.231739572450155, 0.1208650973866179e-2, -0.5395239384953e-5];
    let y = x;
    let tmp = x + 5.5;
    tmp -= (x + 0.5) * Math.log(tmp);
    let ser = 1.000000000190015;
    for (let j = 0; j < 6; j++) ser += c[j] / ++y;
    return -tmp + Math.log(2.5066282746310005 * ser / x);
  }

  private randomString(length: number): string {
    return Math.random().toString(36).substring(2, 2 + length);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
