import { describe, it, expect } from 'vitest';
import * as net from 'node:net';
import { rawHeaderRequest } from '../raw-http';
import { CachePoison } from '../cache-poison';
import type { HttpClient, HttpResponse } from '../http-client';

function stubClient(handler: (url: string, headers?: Record<string, string>) => HttpResponse): HttpClient {
  return {
    get: async (url: string, headers?: Record<string, string>) => handler(url, headers),
    head: async (url: string, headers?: Record<string, string>) => handler(url, headers),
  } as unknown as HttpClient;
}

function resp(overrides: Partial<HttpResponse> = {}): HttpResponse {
  return { status: 200, headers: {}, body: 'ok', bodyHash: 'aa', timingMs: 10, fromCache: false, ...overrides };
}

/** Local HTTP server that records raw request bytes and answers 500 iff it
 *  sees the SOH control byte (0x01) anywhere in the request. */
function startCapturingServer(): Promise<{ port: number; requests: string[]; close: () => Promise<void> }> {
  const requests: string[] = [];
  const server = net.createServer((socket) => {
    let buf = '';
    socket.on('data', (d) => {
      buf += d.toString('latin1');
    });
    socket.on('end', () => {
      requests.push(buf);
      const response = buf.includes('\x01')
        ? 'HTTP/1.1 500 Parser Crash\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
        : 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok';
      socket.end(response);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as net.AddressInfo;
      resolve({
        port,
        requests,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

describe('rawHeaderRequest (B-9)', () => {
  it('sends an illegal header line verbatim over the wire', async () => {
    const server = await startCapturingServer();
    try {
      const result = await rawHeaderRequest(`http://127.0.0.1:${server.port}/probe`, 'X-Illegal\x01Test');
      expect(result.status).toBe(500); // server saw 0x01 → crash response
      expect(result.connected).toBe(true);
      expect(server.requests[0]).toContain('X-Illegal\x01Test');
      expect(server.requests[0]).toContain('GET /probe HTTP/1.1');
    } finally {
      await server.close();
    }
  });

  it('parses status line and headers from the raw response', async () => {
    const server = net.createServer((socket) => {
      socket.resume(); // flowing mode so 'end' fires after client FIN
      socket.on('end', () => socket.end('HTTP/1.1 431 Header Fields Too Large\r\nX-Edge: cdn\r\n\r\n'));
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const { port } = server.address() as net.AddressInfo;
    try {
      const result = await rawHeaderRequest(`http://127.0.0.1:${port}/`, 'X-Illegal Test');
      expect(result.status).toBe(431);
      expect(result.headers['x-edge']).toBe('cdn');
      expect(result.error).toBeUndefined();
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it('reports connection failure without ever connecting', async () => {
    // grab a port that is definitely closed
    const probe = net.createServer();
    await new Promise<void>((r) => probe.listen(0, '127.0.0.1', () => r()));
    const { port } = probe.address() as net.AddressInfo;
    await new Promise<void>((r) => probe.close(() => r()));

    const result = await rawHeaderRequest(`http://127.0.0.1:${port}/`, 'X-Illegal\x01Test', {}, 2000);
    expect(result.connected).toBe(false);
    expect(result.status).toBe(0);
    expect(result.error).toBeTruthy();
  });
});

describe('testCPDoS illegal_header via raw socket (B-9)', () => {
  it('confirms when a malformed header name makes the hop return 5xx', async () => {
    const server = await startCapturingServer();
    try {
      const poison = new CachePoison(
        { target: `http://127.0.0.1:${server.port}/` },
        stubClient(() => resp()), // baseline + non-raw payloads stay 200
      );
      const findings = await poison.testCPDoS(`http://127.0.0.1:${server.port}/`);

      const illegal = findings.filter(f => f.classification === 'illegal_header');
      expect(illegal.length).toBeGreaterThanOrEqual(1);
      expect(illegal[0].confidence).toBe('CONFIRMED');
      expect(illegal[0].signals.statusChanged).toBe(true);
      // SOH payload actually reached the server raw
      expect(server.requests.some(r => r.includes('\x01'))).toBe(true);
    } finally {
      await server.close();
    }
  });

  it('does not confirm illegal names the server rejects with a clean 4xx', async () => {
    const server = net.createServer((socket) => {
      socket.resume(); // flowing mode so 'end' fires after client FIN
      socket.on('end', () => socket.end('HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'));
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const { port } = server.address() as net.AddressInfo;
    try {
      const poison = new CachePoison(
        { target: `http://127.0.0.1:${port}/` },
        stubClient(() => resp()),
      );
      const findings = await poison.testCPDoS(`http://127.0.0.1:${port}/`);
      expect(findings.filter(f => f.classification === 'illegal_header')).toHaveLength(0);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
});
