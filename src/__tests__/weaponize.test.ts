import { describe, it, expect } from 'vitest';
import { Weaponize } from '../weaponize';
import { canonicalClassification } from '../cache-poison';
import type { PoisonFinding } from '../types';

function makeFinding(overrides: Partial<PoisonFinding> = {}): PoisonFinding {
  return {
    inputType: 'header',
    inputName: 'x-forwarded-host',
    canary: 'CANARY123',
    signals: {
      bodyReflection: false,
      headerReflection: {},
      statusChanged: false,
      sizeDeltaPercent: 0,
      newHeaders: [],
      securityHeaderChanges: {},
    },
    oracle: {
      header: 'x-forwarded-host',
      canary: 'CANARY123',
      cachebuster: 'cb',
      pinnedUA: 'test-agent',
      primeResponse: {
        status: 200,
        headers: { vary: 'accept-encoding' },
        bodyPreview: '',
        bodyHash: 'aa',
        cacheStatus: 'HIT',
        timing: 12,
      },
      verifyResponse: {
        status: 200,
        headers: {},
        bodyPreview: '',
        bodyHash: 'bb',
        cacheStatus: 'HIT',
        timing: 11,
      },
      canaryPersisted: true,
    },
    classification: 'xss',
    attackClass: 'content_poison',
    confidence: 'CONFIRMED',
    blastRadius: { scope: 'global', deviceTypes: ['desktop'] },
    ...overrides,
  } as PoisonFinding;
}

describe('Weaponize (B-14)', () => {
  it('PoC curl + steps use the configured real target URL', async () => {
    const weaponize = new Weaponize('https://shop.example/cart');
    const [chain] = await weaponize.run([makeFinding()]);

    expect(chain.poc.curlCommand).toContain('https://shop.example/cart');
    expect(chain.poc.curlCommand).not.toContain('https://target.com/');
    expect(chain.poc.steps[0]).toContain('https://shop.example/cart');
  });

  it('falls back to UNKNOWN (never a fake target.com) when no target configured', async () => {
    const weaponize = new Weaponize();
    const [chain] = await weaponize.run([makeFinding()]);

    expect(chain.poc.curlCommand).toContain('UNKNOWN');
    expect(chain.poc.curlCommand).not.toContain('https://target.com/');
  });

  it('records a 4-phase generation transcript', async () => {
    const weaponize = new Weaponize('https://example.com/');
    const [chain] = await weaponize.run([makeFinding()]);

    expect(chain.phases.map(p => p.phase)).toEqual(['blast-radius', 'classify', 'reproduce', 'report']);
    expect(chain.phases.every(p => p.status === 'complete')).toBe(true);
    expect(chain.phases[1].detail).toContain('xss');
  });

  it('classifies waf_poison with full severity + impact (no fallback)', async () => {
    const weaponize = new Weaponize('https://example.com/');
    const [chain] = await weaponize.run([
      makeFinding({ classification: 'waf_poison', attackClass: 'header_poison' }),
    ]);

    expect(chain.impact.severity).toBe('high');
    expect(chain.impact.cvss).toBeGreaterThanOrEqual(7.5);
    expect(chain.impact.description).toContain('WAF rule poisoning');
    expect(chain.prerequisites.some(p => p.includes('WAF rule'))).toBe(true);
  });
});

describe('canonicalClassification', () => {
  it('normalizes CP-DoS payload classes to union names', () => {
    expect(canonicalClassification('import_hijack')).toBe('import_hijacking');
    expect(canonicalClassification('oauth')).toBe('oauth_hijacking');
    expect(canonicalClassification('multi_cdn')).toBe('multi_cdn_mismatch');
    expect(canonicalClassification('cpdos')).toBe('cpdos');
    expect(canonicalClassification('waf_poison')).toBe('waf_poison');
  });
});
