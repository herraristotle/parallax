import { DiffConfig, PathFuzzResult, DiffSignal } from './types';
import { HttpClient } from './http-client';

const SECURITY_HEADERS = [
  'content-security-policy', 'x-frame-options', 'strict-transport-security',
  'x-content-type-options', 'x-xss-protection', 'permissions-policy',
  'cross-origin-resource-policy', 'cross-origin-opener-policy', 'cross-origin-embedder-policy',
];

const CF_EMAIL_RE = /data-cfemail="[a-f0-9]+"/gi;

export const WCD_PAYLOADS = [
  { name: 'path-parameter', suffix: '.css' },
  { name: 'encoded-newline', suffix: '%0A' },
  { name: 'encoded-question-mark', suffix: '%3F' },
  { name: 'encoded-semicolon', suffix: '%3B' },
  { name: 'encoded-sharp', suffix: '%23' },
  { name: 'encoded-slash', suffix: '%2F' },
  { name: 'double-encoded-newline', suffix: '%25%30%41' },
  { name: 'double-encoded-null', suffix: '%25%30%30' },
  { name: 'double-encoded-question-mark', suffix: '%25%33%46' },
  { name: 'double-encoded-semicolon', suffix: '%25%33%42' },
  { name: 'double-encoded-sharp', suffix: '%25%32%33' },
  { name: 'double-encoded-slash', suffix: '%25%32%46' },
];

export function buildWCDUrls(baseUrl: string): Array<{ name: string; url: string }> {
  const parsed = new URL(baseUrl);
  const path = parsed.pathname;
  const filename = path.split('/').pop() || 'page';
  return WCD_PAYLOADS.map(p => {
    const attackPath = `${path}${p.suffix}${filename}.css`;
    const attackUrl = new URL(baseUrl);
    attackUrl.pathname = attackPath;
    return { name: p.name, url: attackUrl.toString() };
  });
}

export class CacheDiff {
  public results: PathFuzzResult[] = [];
  private config: DiffConfig;
  private http: HttpClient;
  private byteRange: [number, number];
  private positions: ('prefix' | 'infix' | 'suffix')[];
  private encodings: ('raw' | 'single' | 'double' | 'triple')[];

  constructor(cacheConfig: { target: string; cookie?: string; headers?: Record<string, string> }, diffConfig?: Partial<DiffConfig>, httpClient?: HttpClient) {
    this.http = httpClient || new HttpClient({ timeoutMs: 10000, rateLimitPerSec: 10 });
    this.config = {
      targetUrls: [cacheConfig.target],
      byteRange: [0x00, 0xFF],
      positions: ['prefix', 'infix', 'suffix'],
      encodings: ['raw', 'single', 'double'],
      ...diffConfig,
    };
    this.byteRange = this.config.byteRange || [0x00, 0xFF];
    this.positions = this.config.positions || ['prefix', 'infix', 'suffix'];
    this.encodings = this.config.encodings || ['raw', 'single', 'double'];
  }

  async run(cachedUrls: Array<{ url: string }>): Promise<PathFuzzResult[]> {
    for (const { url } of cachedUrls) {
      await this.fuzzUrl(url);
    }
    return this.results;
  }

  private async fuzzUrl(baseUrl: string): Promise<void> {
    const parsed = new URL(baseUrl);
    const path = parsed.pathname;

    for (let byte = this.byteRange[0]; byte <= this.byteRange[1]; byte++) {
      for (const position of this.positions) {
        for (const encoding of this.encodings) {
          const fuzzedUrl = this.injectByte(baseUrl, path, byte, position, encoding);
          try {
            const [originalResp, fuzzedResp] = await Promise.all([
              this.http.get(baseUrl),
              this.http.get(fuzzedUrl),
            ]);

            const signals = this.compareResponses(
              originalResp.body, fuzzedResp.body,
              originalResp.headers, fuzzedResp.headers,
              originalResp.status, fuzzedResp.status
            );

            if (this.hasSignal(signals)) {
              this.results.push({
                originalUrl: baseUrl,
                fuzzedUrl,
                byte,
                position,
                encoding,
                signals,
                cacheHit: fuzzedResp.fromCache,
              });
            }
          } catch {
            // Skip failed requests
          }
        }
      }
    }
  }

  injectByte(
    baseUrl: string, path: string, byte: number,
    position: 'prefix' | 'infix' | 'suffix',
    encoding: 'raw' | 'single' | 'double' | 'triple'
  ): string {
    let byteStr: string;

    if (encoding === 'single') {
      byteStr = `%${byte.toString(16).padStart(2, '0').toUpperCase()}`;
    } else if (encoding === 'double') {
      byteStr = `%25${byte.toString(16).padStart(2, '0').toUpperCase()}`;
    } else if (encoding === 'triple') {
      byteStr = `%2525${byte.toString(16).padStart(2, '0').toUpperCase()}`;
    } else {
      // Raw: control chars must be percent-encoded to form valid URL
      if (byte < 0x20 || byte > 0x7E) {
        byteStr = `%${byte.toString(16).padStart(2, '0').toUpperCase()}`;
      } else {
        byteStr = String.fromCharCode(byte);
      }
    }

    let newPath: string;
    if (position === 'prefix') {
      newPath = byteStr + path;
    } else if (position === 'suffix') {
      newPath = path + byteStr;
    } else {
      const segments = path.split('/').filter(Boolean);
      if (segments.length > 1) {
        segments[segments.length - 1] = byteStr + segments[segments.length - 1];
        newPath = '/' + segments.join('/');
      } else {
        newPath = path + byteStr;
      }
    }

    const parsed = new URL(baseUrl);
    parsed.pathname = newPath;
    return parsed.toString();
  }

  compareResponses(
    body1: string, body2: string,
    headers1: Record<string, string>, headers2: Record<string, string>,
    status1: number, status2: number,
    canary?: string
  ): DiffSignal {
    // Normalize Cloudflare email obfuscation before body comparison
    const norm1 = body1.replace(CF_EMAIL_RE, 'data-cfemail="REMOVED"');
    const norm2 = body2.replace(CF_EMAIL_RE, 'data-cfemail="REMOVED"');

    let bodyReflection = false;
    if (canary) {
      bodyReflection = norm2.includes(canary);
    } else {
      bodyReflection = norm2.includes(norm1.substring(0, 50)) && norm1 !== norm2;
    }

    const headerReflection: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers1)) {
      if (headers2[key] && headers2[key] !== value) {
        headerReflection[key] = value;
      }
    }

    const statusChanged = status1 !== status2;
    const sizeDeltaPercent = body1.length > 0
      ? Math.abs(body2.length - body1.length) / body1.length * 100
      : 0;

    const newHeaders: string[] = [];
    for (const key of Object.keys(headers2)) {
      if (!headers1[key]) newHeaders.push(key);
    }

    const securityHeaderChanges: Record<string, { before: string; after: string }> = {};
    for (const h of SECURITY_HEADERS) {
      if (headers1[h] && headers2[h] && headers1[h] !== headers2[h]) {
        securityHeaderChanges[h] = { before: headers1[h], after: headers2[h] };
      }
    }

    let bodyContext: DiffSignal['bodyContext'] = 'generic';
    if (body2.includes('<script')) bodyContext = 'script_tag';
    else if (body2.includes('href=') || body2.includes('src=')) bodyContext = 'attribute_url';
    else if (body2.includes('<link')) bodyContext = 'link_tag';
    else if (body2.includes('<meta')) bodyContext = 'meta_tag';
    else if (body2.includes('<img')) bodyContext = 'image_tag';
    else if (body2.includes('<form')) bodyContext = 'form_tag';
    else if (body2.includes('style=')) bodyContext = 'inline_style';

    return {
      bodyReflection,
      headerReflection,
      statusChanged,
      sizeDeltaPercent,
      newHeaders,
      securityHeaderChanges,
      bodyContext,
    };
  }

  private hasSignal(signals: DiffSignal): boolean {
    return signals.bodyReflection ||
      Object.keys(signals.headerReflection).length > 0 ||
      signals.statusChanged ||
      signals.sizeDeltaPercent > 5 ||
      signals.newHeaders.length > 0 ||
      Object.keys(signals.securityHeaderChanges).length > 0;
  }

  getResults(): PathFuzzResult[] {
    return this.results;
  }

  getUnkeyedDelimiters(): string[] {
    const unkeyed = new Set<string>();
    for (const result of this.results) {
      if (result.cacheHit && result.signals.bodyReflection) {
        unkeyed.add(String.fromCharCode(result.byte));
      }
    }
    return Array.from(unkeyed);
  }
}
