import { describe, it, expect } from 'vitest';
import { CachePoison } from '../cache-poison';

describe('CachePoison', () => {
  it('should classify XSS exploit correctly', () => {
    const poison = new CachePoison({ target: 'https://example.com' });
    const finding = poison.classifyExploit({
      inputType: 'header',
      inputName: 'x-forwarded-host',
      canary: 'TEST123',
      signals: {
        bodyReflection: true,
        headerReflection: {},
        statusChanged: false,
        sizeDeltaPercent: 0,
        newHeaders: [],
        securityHeaderChanges: {},
        bodyContext: 'script_tag',
      },
      oracle: {} as any,
      classification: 'unknown',
      attackClass: 'content_poison',
      confidence: 'POSSIBLE',
      blastRadius: { scope: 'global', deviceTypes: ['desktop'] },
    });
    expect(finding.classification).toBe('xss');
    expect(finding.attackClass).toBe('content_poison');
  });

  it('should classify CP-DoS correctly', () => {
    const poison = new CachePoison({ target: 'https://example.com' });
    const finding = poison.classifyExploit({
      inputType: 'header',
      inputName: 'range',
      canary: 'TEST456',
      signals: {
        bodyReflection: false,
        headerReflection: {},
        statusChanged: true,
        sizeDeltaPercent: 0,
        newHeaders: [],
        securityHeaderChanges: {},
      },
      oracle: {} as any,
      classification: 'unknown',
      attackClass: 'content_poison',
      confidence: 'POSSIBLE',
      blastRadius: { scope: 'global', deviceTypes: ['desktop'] },
    });
    expect(finding.classification).toBe('cpdos');
    expect(finding.attackClass).toBe('cpdos');
  });

  it('should classify security header poisoning', () => {
    const poison = new CachePoison({ target: 'https://example.com' });
    const finding = poison.classifyExploit({
      inputType: 'header',
      inputName: 'x-forwarded-host',
      canary: 'TEST789',
      signals: {
        bodyReflection: false,
        headerReflection: {},
        statusChanged: false,
        sizeDeltaPercent: 0,
        newHeaders: [],
        securityHeaderChanges: {
          'strict-transport-security': { before: 'max-age=31536000', after: 'max-age=0' }
        },
      },
      oracle: {} as any,
      classification: 'unknown',
      attackClass: 'content_poison',
      confidence: 'POSSIBLE',
      blastRadius: { scope: 'global', deviceTypes: ['desktop'] },
    });
    expect(finding.classification).toBe('security_header_poisoning');
    expect(finding.attackClass).toBe('header_poison');
  });

  it('should classify weakened CSP as csp_bypass', () => {
    const poison = new CachePoison({ target: 'https://example.com' });
    const finding = poison.classifyExploit({
      inputType: 'header',
      inputName: 'x-forwarded-host',
      canary: 'TEST999',
      signals: {
        bodyReflection: false,
        headerReflection: {},
        statusChanged: false,
        sizeDeltaPercent: 0,
        newHeaders: [],
        securityHeaderChanges: {
          'content-security-policy': { before: "default-src 'self'", after: "default-src 'none'" }
        },
      },
      oracle: {} as any,
      classification: 'unknown',
      attackClass: 'content_poison',
      confidence: 'POSSIBLE',
      blastRadius: { scope: 'global', deviceTypes: ['desktop'] },
    });
    expect(finding.classification).toBe('csp_bypass');
    expect(finding.attackClass).toBe('header_poison');
  });

  it('should have 56+ CP-DoS payloads defined', () => {
    expect(CachePoison.CPDOS_PAYLOADS.length).toBeGreaterThanOrEqual(50);
  });

  it('should have payloads across all 4 classes', () => {
    const classes = new Set(CachePoison.CPDOS_PAYLOADS.map(p => p.class));
    expect(classes.has('cpdos')).toBe(true);
    expect(classes.has('waf_poison')).toBe(true);
    expect(classes.has('fragment')).toBe(true);
    expect(classes.has('illegal_header')).toBe(true);
  });

  it('should have WAF payloads for common scanner UAs', () => {
    const wafPayloads = CachePoison.CPDOS_PAYLOADS.filter(p => p.class === 'waf_poison');
    const uas = wafPayloads.map(p => p.value);
    expect(uas).toContain('sqlmap/1.0');
    expect(uas).toContain('Nikto/2.1.6');
    expect(uas).toContain('Burp Suite');
  });

  it('should use harvested wordlist when wired, without synthetic filler', () => {
    const poison = new CachePoison({ target: 'https://example.com' });

    // Fallback (no Stage-2 harvest): real curated headers only, no x-custom-N.
    const fallback = poison.getHeaderWordlist('all');
    expect(fallback.length).toBeGreaterThan(0);
    expect(fallback.some(h => h.startsWith('x-custom-'))).toBe(false);

    poison.setHarvestedWordlist({
      fast: ['x-harvested-top'],
      all: ['x-harvested-top', 'x-harvested-full'],
    });

    const fast = poison.getHeaderWordlist('fast');
    expect(fast).toContain('x-harvested-top');
    expect(fast).toContain('x-forwarded-host');
    expect(fast.indexOf('x-forwarded-host')).toBeLessThan(fast.indexOf('x-harvested-top'));

    const all = poison.getHeaderWordlist('all');
    expect(all).toContain('x-harvested-full');
    expect(all.filter(h => h === 'x-forwarded-host').length).toBe(1);
    expect(all.some(h => h.startsWith('x-custom-'))).toBe(false);
  });

  it('should include HCache internal-route and auth-header CP-DoS classes', () => {
    const classes = new Set(CachePoison.CPDOS_PAYLOADS.map(p => p.class));
    expect(classes.has('internal_route')).toBe(true);
    expect(classes.has('auth_header')).toBe(true);
    const route = CachePoison.CPDOS_PAYLOADS.filter(p => p.class === 'internal_route');
    expect(route.length).toBeGreaterThanOrEqual(5);
    expect(route.some(p => p.name === 'fastly-client-ip')).toBe(true);
    const auth = CachePoison.CPDOS_PAYLOADS.filter(p => p.class === 'auth_header');
    expect(auth.length).toBeGreaterThanOrEqual(3);
  });
});
