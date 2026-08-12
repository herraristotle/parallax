import { describe, it, expect } from 'vitest';
import { Discover } from '../discover';

describe('Discover', () => {
  it('should have default paths', () => {
    const discover = new Discover({ target: 'https://example.com' });
    expect(discover.defaultPaths.length).toBeGreaterThanOrEqual(32);
    expect(discover.defaultPaths).toContain('/');
    expect(discover.defaultPaths).toContain('/index.html');
    expect(discover.defaultPaths).toContain('/robots.txt');
    expect(discover.defaultPaths).toContain('/api/health');
  });

  it('should deduplicate URLs by pathname', () => {
    const discover = new Discover({ target: 'https://example.com' });
    const urls = [
      'https://example.com/foo',
      'https://example.com/foo?a=1',
      'https://example.com/foo?b=2',
      'https://example.com/bar',
    ];
    const deduped = discover.deduplicateUrls(urls);
    expect(deduped).toEqual([
      'https://example.com/foo',
      'https://example.com/bar',
    ]);
  });

  it('should return empty array for empty input', () => {
    const discover = new Discover({ target: 'https://example.com' });
    expect(discover.deduplicateUrls([])).toEqual([]);
  });

  it('should accept custom config', () => {
    const discover = new Discover({
      target: 'https://example.com',
      cookie: 'session=abc',
      headers: { 'Authorization': 'Bearer token' },
    });
    expect(discover.defaultPaths.length).toBeGreaterThanOrEqual(32);
  });
});
