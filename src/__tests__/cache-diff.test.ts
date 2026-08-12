import { describe, it, expect } from 'vitest';
import { CacheDiff, WCD_PAYLOADS, buildWCDUrls } from '../cache-diff';

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
