import { HeaderHarvestConfig, HeaderWordlist } from './types';
import * as fs from 'fs';
import * as path from 'path';

/**
 * HeaderHarvest — BigQuery HTTP Archive queries for uncommon headers + Vary analysis
 *
 * From Parallax blog: "The wordlist_builder merges BigQuery results with 145 CDN-internal
 * headers and 39 IANA-registered headers. Deduplication, filtering, and frequency-based
 * prioritisation produce two output wordlists."
 */
export class HeaderHarvest {
  private config: HeaderHarvestConfig;
  private headersFile: string;
  private parametersFile: string;

  constructor(config: HeaderHarvestConfig = {}) {
    this.config = {
      lowThreshold: 10,
      highThreshold: 5000,
      ...config,
    };
    this.headersFile = config.headersFile || path.join(__dirname, '..', '..', '..', '..', 'cache', 'HCache', 'headers.txt');
    this.parametersFile = config.parametersFile || path.join(__dirname, '..', '..', '..', '..', 'cache', 'HCache', 'parameters.txt');
  }

  async harvestUncommonHeaders(): Promise<string[]> {
    return this.loadFromFile(this.headersFile);
  }

  async harvestVaryHeaders(): Promise<string[]> {
    const all = await this.loadFromFile(this.headersFile);
    const standardVary = new Set([
      'accept-encoding', 'user-agent', 'accept', 'accept-language',
      'accept-charset', 'cookie', 'origin', 'referer',
    ]);
    return all.filter(h => !standardVary.has(h.toLowerCase()));
  }

  async buildWordlists(): Promise<HeaderWordlist> {
    const uncommon = await this.harvestUncommonHeaders();
    const vary = await this.harvestVaryHeaders();
    const cdnInternal = this.getCDNInternalHeaders();
    const iana = this.getIANAHeaders();

    const allHeaders = new Set([...uncommon, ...vary, ...cdnInternal, ...iana]);
    const scored = Array.from(allHeaders).map(h => ({
      header: h,
      priority: this.scoreHeader(h, uncommon, vary, cdnInternal),
    })).sort((a, b) => b.priority - a.priority);

    return {
      fast: scored.slice(0, 379).map(s => s.header),
      all: scored.map(s => s.header),
      totalUncommon: uncommon.length,
      totalVary: vary.length,
      totalCDNInternal: cdnInternal.length,
      totalIANA: iana.length,
    };
  }

  async loadParameters(): Promise<string[]> {
    return this.loadFromFile(this.parametersFile);
  }

  private async loadFromFile(filePath: string): Promise<string[]> {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      return content.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    } catch {
      return [];
    }
  }

  private scoreHeader(header: string, uncommon: string[], vary: string[], cdn: string[]): number {
    let score = 0;
    if (uncommon.includes(header)) score += 100;
    if (vary.includes(header)) score += 50;
    if (cdn.includes(header)) score += 30;
    if (header.startsWith('x-') || header.startsWith('cf-') || header.startsWith('x-amz-')) score += 10;
    return score;
  }

  private getCDNInternalHeaders(): string[] {
    return [
      'akamai-origin-hop', 'cf-bgj', 'cf-cache-key', 'cf-connecting-ipv6',
      'cf-ew-via', 'cf-ray', 'cf-request-id', 'cf-visitor',
      'fastly-debug-digest', 'fastly-debug-path', 'fastly-debug-ttl', 'fastly-ff',
      'x-amz-cf-pop', 'x-amz-cf-id', 'x-amz-request-id', 'x-amz-id-2',
      'x-azure-ref', 'x-vercel-id', 'x-vercel-cache', 'x-nf-request-id',
    ];
  }

  private getIANAHeaders(): string[] {
    return [
      'accept', 'accept-charset', 'accept-encoding', 'accept-language',
      'accept-ranges', 'age', 'allow', 'authorization', 'cache-control',
      'connection', 'content-encoding', 'content-language', 'content-length',
      'content-location', 'content-md5', 'content-range', 'content-type',
      'date', 'etag', 'expect', 'expires', 'from', 'host', 'if-match',
      'if-modified-since', 'if-none-match', 'if-range', 'if-unmodified-since',
      'last-modified', 'location', 'max-forwards', 'pragma', 'range', 'referer',
      'server', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'user-agent',
      'vary', 'via', 'warning', 'www-authenticate',
    ];
  }

  async run(): Promise<HeaderWordlist> {
    return this.buildWordlists();
  }
}
