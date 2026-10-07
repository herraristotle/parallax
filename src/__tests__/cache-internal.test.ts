import { describe, it, expect } from 'vitest';
import { CacheInternal } from '../cache-internal';
import type { HttpClient, HttpResponse } from '../http-client';

function stubClient(handler: (url: string, n: number) => HttpResponse): HttpClient {
  let n = 0;
  return {
    get: async (url: string) => handler(url, n++),
  } as unknown as HttpClient;
}

function resp(overrides: Partial<HttpResponse> = {}): HttpResponse {
  return { status: 200, headers: {}, body: '', ...overrides };
}

/** Extract the marker a probe URL sent as its first query value. */
function paramValue(url: string): string {
  return new URL(url).searchParams.values().next().value as string;
}

const TARGET = 'https://example.com/page';

describe('CacheInternal', () => {
  it('returns [] with bounded calls when nothing reflects', async () => {
    let calls = 0;
    const client = stubClient(() => {
      calls++;
      return resp({ body: '<html>static</html>' });
    });
    const cache = new CacheInternal({ target: TARGET }, client);
    const findings = await cache.run();
    expect(findings).toEqual([]);
    expect(calls).toBeLessThanOrEqual(8); // PROBE_PARAMS length
  });

  it('finds the first reflected param', async () => {
    const client = stubClient((url) => {
      const v = new URL(url).searchParams.get('q');
      return resp({ body: v ? `results for ${v}` : 'static' });
    });
    const cache = new CacheInternal({ target: TARGET }, client);
    expect(await cache.findReflectedParam({})).toBe('q');
  });

  it('ESI tag echoed verbatim → no finding', async () => {
    const client = stubClient((url) => {
      const v = new URL(url).searchParams.get('q') || '';
      // First call = reflection probe, second = ESI payload echo.
      return resp({ body: `echo: ${v}` });
    });
    const cache = new CacheInternal({ target: TARGET }, client);
    const findings = await cache.testEsiTransform('q', {});
    expect(findings).toEqual([]);
  });

  it('ESI tag consumed by edge → esi_transform LIKELY (no OOB)', async () => {
    const client = stubClient((url) => {
      const v = new URL(url).searchParams.get('q') || '';
      // Tag stripped by the edge, canary marker still present.
      const canary = v.match(/kettle[0-9a-f]+/)?.[0] ?? '';
      return resp({ body: `processed ${canary}` });
    });
    const cache = new CacheInternal({ target: TARGET }, client);
    const findings = await cache.testEsiTransform('q', {});
    expect(findings).toHaveLength(1);
    expect(findings[0].signal).toBe('esi_transform');
    expect(findings[0].confidence).toBe('LIKELY');
    expect(findings[0].oobConfirmed).toBeUndefined();
  });

  it('ESI tag consumed + OOB callback → CONFIRMED, oobConfirmed', async () => {
    const client = stubClient(() => resp({ body: 'processed' }));
    const waits: number[] = [];
    const oob = {
      isReady: () => true,
      nextPayload: () => 'lbl1.cid1.oast.example',
      waitForInteraction: async () => {
        waits.push(1);
        return { protocol: 'http', remoteAddress: '1.2.3.4' };
      },
    };
    const cache = new CacheInternal({ target: TARGET }, client, oob as any);
    const findings = await cache.testEsiTransform('q', {});
    expect(findings).toHaveLength(1);
    expect(findings[0].confidence).toBe('CONFIRMED');
    expect(findings[0].oobConfirmed).toBe(true);
    expect(waits).toHaveLength(1);
  });

  it('ESI tag consumed but OOB timeout → LIKELY, oobConfirmed unset', async () => {
    const client = stubClient(() => resp({ body: 'processed' }));
    const oob = {
      isReady: () => true,
      nextPayload: () => 'lbl1.cid1.oast.example',
      waitForInteraction: async () => null,
    };
    const cache = new CacheInternal({ target: TARGET }, client, oob as any);
    const findings = await cache.testEsiTransform('q', {});
    expect(findings).toHaveLength(1);
    expect(findings[0].confidence).toBe('LIKELY');
    expect(findings[0].oobConfirmed).toBeUndefined();
  });

  it('keyless cross-serve: r2 receives r1 body → CONFIRMED finding', async () => {
    let call = 0;
    let firstBody = '';
    const client = stubClient((url) => {
      call++;
      const v = new URL(url).searchParams.get('q') || '';
      if (call === 1) {
        firstBody = `cached page with ${v}`;
        return resp({ body: firstBody });
      }
      // Keyless cache serves the first response regardless of marker.
      return resp({ body: firstBody });
    });
    const cache = new CacheInternal({ target: TARGET }, client);
    const findings = await cache.testKeylessCrossServe('q', {});
    expect(findings).toHaveLength(1);
    expect(findings[0].signal).toBe('keyless_cross_serve');
    expect(findings[0].confidence).toBe('CONFIRMED');
  });

  it('keyless cross-serve: r2 echoes own marker → no finding', async () => {
    const client = stubClient((url) => {
      const v = new URL(url).searchParams.get('q') || '';
      return resp({ body: `page ${v}` });
    });
    const cache = new CacheInternal({ target: TARGET }, client);
    expect(await cache.testKeylessCrossServe('q', {})).toEqual([]);
  });

  it('ESI headers → esi_header finding; absent → none', async () => {
    const withHeaders = CacheInternal.headerFinding(TARGET, {
      'surrogate-control': 'max-age=60',
      'content-type': 'text/html',
    });
    expect(withHeaders).not.toBeNull();
    expect(withHeaders!.signal).toBe('esi_header');
    expect(withHeaders!.confidence).toBe('POSSIBLE');
    expect(withHeaders!.evidence).toContain('surrogate-control');

    expect(CacheInternal.headerFinding(TARGET, { 'content-type': 'text/html' })).toBeNull();
  });

  it('run() with reflection: collects esi_header from target fetch', async () => {
    let call = 0;
    const client = stubClient((url) => {
      call++;
      const v = new URL(url).searchParams.get('q');
      if (call === 1) return resp({ body: v ? `echo ${v}` : 'x' });
      // ESI payload echoed → no transform finding; second marker run echoes too.
      const v2 = new URL(url).searchParams.get('q') || '';
      return resp({ body: `echo ${v2}` });
    });
    const cache = new CacheInternal({ target: TARGET }, client);
    const findings = await cache.run();
    // ESI echo + keyless echo → no findings from those; header fetch has no ESI headers.
    expect(findings.every((f) => f.signal !== 'esi_transform')).toBe(true);
    expect(findings.every((f) => f.signal !== 'keyless_cross_serve')).toBe(true);
  });

  it('OOB absent → zero OOB calls during full run', async () => {
    let oobCalls = 0;
    const oob = {
      isReady: () => false,
      nextPayload: () => { oobCalls++; return 'x'; },
      waitForInteraction: async () => { oobCalls++; return null; },
    };
    const client = stubClient((url) => {
      const v = new URL(url).searchParams.get('q') || '';
      return resp({ body: `echo ${v}` });
    });
    const cache = new CacheInternal({ target: TARGET }, client, oob as any);
    await cache.run();
    expect(oobCalls).toBe(0);
  });
});
