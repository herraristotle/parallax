import { describe, it, expect } from 'vitest';
import { CacheDiff, WCD_PAYLOADS, buildWCDUrls, FRAMEWORK_DELIMITERS, frameworkByteOrder } from '../cache-diff';
import type { HttpClient, HttpResponse } from '../http-client';

describe('CacheDiff', () => {
  it('should correctly inject percent-encoded bytes', () => {
    const diff = new CacheDiff({ target: 'https://example.com/page' });
    const url = diff.injectByte('https://example.com/page', '/page', 0x2F, 'suffix', 'single');
    expect(url).toContain('%2F');
  });

  it('should percent-encode control chars in raw mode', () => {
    const diff = new CacheDiff({ target: 'https://example.com/page' });
    const url = diff.injectByte('https://example.com/page', '/page', 0x01, 'suffix', 'raw');
    expect(url).toContain('%01');
  });

  it('should not percent-encode printable ASCII in raw mode', () => {
    const diff = new CacheDiff({ target: 'https://example.com/page' });
    const url = diff.injectByte('https://example.com/page', '/page', 0x41, 'suffix', 'raw');
    expect(url).toContain('/pageA');
  });

  it('should detect body reflection signal', () => {
    const diff = new CacheDiff({ target: 'https://example.com' });
    const signal = diff.compareResponses(
      '<div>normal</div>',
      '<div>normal</div><script>alert(1)</script>',
      { 'content-type': 'text/html' },
      { 'content-type': 'text/html' },
      200, 200
    );
    expect(signal.bodyReflection).toBe(true);
  });

  it('should detect header reflection', () => {
    const diff = new CacheDiff({ target: 'https://example.com' });
    const signal = diff.compareResponses(
      'ok', 'ok',
      { 'x-custom': 'reflected-value' },
      { 'x-custom': 'different' },
      200, 200
    );
    expect(signal.headerReflection['x-custom']).toBe('reflected-value');
  });

  it('should detect status change', () => {
    const diff = new CacheDiff({ target: 'https://example.com' });
    const signal = diff.compareResponses(
      'ok', 'forbidden',
      {}, {},
      200, 403
    );
    expect(signal.statusChanged).toBe(true);
  });

  it('should detect size delta > 5%', () => {
    const diff = new CacheDiff({ target: 'https://example.com' });
    const body1 = 'a'.repeat(100);
    const body2 = 'a'.repeat(110);
    const signal = diff.compareResponses(body1, body2, {}, {}, 200, 200);
    expect(signal.sizeDeltaPercent).toBeGreaterThan(5);
  });

  it('should detect security header changes', () => {
    const diff = new CacheDiff({ target: 'https://example.com' });
    const signal = diff.compareResponses(
      'ok', 'ok',
      { 'content-security-policy': "default-src 'self'" },
      { 'content-security-policy': "default-src 'none'" },
      200, 200
    );
    expect(signal.securityHeaderChanges['content-security-policy']).toBeDefined();
  });

  it('should normalize CF email before body comparison', () => {
    const diff = new CacheDiff({ target: 'https://example.com' });
    const body1 = 'Contact us at <span data-cfemail="abc123">email</span>';
    const body2 = 'Contact us at <span data-cfemail="def456">email</span> extra content';
    const signal = diff.compareResponses(body1, body2, {}, {}, 200, 200);
    // After normalization, both have "REMOVED" — body1 is substring of body2, diff is only " extra content"
    expect(signal.bodyReflection).toBe(true);
  });

  it('should detect body context (script tag)', () => {
    const diff = new CacheDiff({ target: 'https://example.com' });
    const signal = diff.compareResponses(
      '', '<script>var x = 1;</script>',
      {}, {}, 200, 200
    );
    expect(signal.bodyContext).toBe('script_tag');
  });

  it('should generate 12 WCD attack URLs', () => {
    const urls = buildWCDUrls('https://example.com/profile');
    expect(urls).toHaveLength(12);
    expect(urls[0].name).toBe('path-parameter');
    expect(urls[0].url).toContain('.css');
  });

  it('should include encoded semicolon payload', () => {
    const urls = buildWCDUrls('https://example.com/page');
    const semicolon = urls.find(u => u.name === 'encoded-semicolon');
    expect(semicolon?.url).toContain('%3B');
  });

  it('should have all 12 WCD payload types', () => {
    expect(WCD_PAYLOADS).toHaveLength(12);
    const names = WCD_PAYLOADS.map(p => p.name);
    expect(names).toContain('encoded-newline');
    expect(names).toContain('double-encoded-slash');
  });
});

describe('framework-aware delimiter priority (B-12)', () => {
  const RANGE: [number, number] = [0x00, 0xff];

  it('probes Spring `;` (0x3B) before the rest of the range', () => {
    const order = frameworkByteOrder('Spring', RANGE);
    expect(order[0]).toBe(0x3b);
    expect(order).toHaveLength(256);
    expect(new Set(order).size).toBe(256);
  });

  it('probes Rails `.` first, OpenLiteSpeed `%00` first, nginx `/` first', () => {
    expect(frameworkByteOrder('rails', RANGE)[0]).toBe(0x2e);
    expect(frameworkByteOrder('OpenLiteSpeed', RANGE)[0]).toBe(0x00);
    expect(frameworkByteOrder('nginx', RANGE)[0]).toBe(0x2f);
  });

  it('covers PHP, Django, ASP.NET with framework-relevant delimiters up front', () => {
    const php = frameworkByteOrder('php', RANGE);
    expect(php.slice(0, 4)).toEqual([0x2f, 0x3f, 0x2e, 0x00]);
    const django = frameworkByteOrder('django', RANGE);
    expect(django[0]).toBe(0x2f);
    expect(django).toContain(0x3b);
    const asp = frameworkByteOrder('asp.net', RANGE);
    expect(asp[0]).toBe(0x3b);
  });

  it('unknown framework → plain ascending range order', () => {
    const order = frameworkByteOrder('cobol-cics', RANGE);
    expect(order[0]).toBe(0x00);
    expect(order[255]).toBe(0xff);
  });

  it('clamps priority bytes to the configured byteRange', () => {
    const order = frameworkByteOrder('spring', [0x40, 0x50]);
    expect(order[0]).toBe(0x40); // 0x3B below range → dropped, plain order
    expect(order).toHaveLength(17);
  });

  it('fuzzes in priority order end-to-end (stub client)', async () => {
    const client = {
      get: async (url: string): Promise<HttpResponse> => ({
        status: url.includes('%') || /[;<]/.test(new URL(url).pathname.slice(1)) ? 404 : 200,
        headers: {},
        body: url === 'https://example.com/page' ? 'ok' : 'missing',
        fromCache: false,
      }),
    } as unknown as HttpClient;
    const diff = new CacheDiff(
      { target: 'https://example.com/page' },
      { byteRange: [0x3a, 0x3c], encodings: ['single'], positions: ['suffix'] },
      client,
    );
    diff.setFramework('spring');
    await diff.run([{ url: 'https://example.com/page' }]);

    // priority byte `;` (0x3B) must be fuzzed before `:` (0x3A) and `<` (0x3C)
    const order = diff.getResults().map(r => r.byte);
    expect(order).toEqual([0x3b, 0x3a, 0x3c]);
  });

  it('FRAMEWORK_DELIMITERS keys normalize case-insensitively', () => {
    expect(Object.keys(FRAMEWORK_DELIMITERS)).toContain('asp.net');
    expect(FRAMEWORK_DELIMITERS['spring']).toEqual([0x3b, 0x2e, 0x2f]);
  });
});

describe('batched fuzzing (B-22)', () => {
  it('fetches baseline once per URL, not per probe', async () => {
    let baselineGets = 0;
    const client = {
      get: async (url: string): Promise<HttpResponse> => {
        if (url === 'https://example.com/page') baselineGets++;
        return { status: 200, headers: {}, body: 'ok', bodyHash: '', timingMs: 1, fromCache: false };
      },
    } as unknown as HttpClient;
    const diff = new CacheDiff(
      { target: 'https://example.com/page' },
      { byteRange: [0x41, 0x43], encodings: ['single'], positions: ['suffix'] },
      client,
    );
    await diff.run([{ url: 'https://example.com/page' }]);
    expect(baselineGets).toBe(1);
  });

  it('preserves probe order across concurrent batches', async () => {
    const client = {
      get: async (url: string): Promise<HttpResponse> => ({
        // fuzzed URLs 404 → every probe records, order observable
        status: url === 'https://example.com/page' ? 200 : 404,
        headers: {},
        body: url === 'https://example.com/page' ? 'ok' : 'missing',
        bodyHash: '',
        timingMs: 1,
        fromCache: false,
      }),
    } as unknown as HttpClient;
    const diff = new CacheDiff(
      { target: 'https://example.com/page' },
      { byteRange: [0x40, 0x4f], encodings: ['single'], positions: ['suffix'] }, // 16 bytes = 2 batches
      client,
    );
    await diff.run([{ url: 'https://example.com/page' }]);
    const bytes = diff.getResults().map(r => r.byte);
    expect(bytes).toEqual(Array.from({ length: 16 }, (_, i) => 0x40 + i));
  });
});
