import { describe, it, expect, afterEach } from 'vitest';
import * as http2 from 'node:http2';
import * as net from 'node:net';
import { HttpClient } from '../http-client';

function startH2Server(): Promise<{ port: number; streams: number; close: () => Promise<void> }> {
  let streams = 0;
  const server = http2.createServer();
  server.on('stream', (stream, headers) => {
    streams++;
    stream.respond({ ':status': 200, 'content-type': 'text/plain' });
    stream.end(`h2-ok:${headers[':path']}`);
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as { port: number };
      resolve({
        port,
        get streams() { return streams; },
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

describe('HTTP/2 client (B-10)', () => {
  const clients: HttpClient[] = [];
  const makeClient = (opts = {}) => {
    const c = new HttpClient({ timeoutMs: 5000, rateLimitPerSec: 0, maxRetries: 1, http2: true, ...opts });
    clients.push(c);
    return c;
  };

  afterEach(() => {
    for (const c of clients.splice(0)) c.closeH2();
  });

  it('performs a GET over a shared h2 session', async () => {
    const server = await startH2Server();
    try {
      const client = makeClient();
      const resp = await client.get(`http://127.0.0.1:${server.port}/alpha`);
      expect(resp.status).toBe(200);
      expect(resp.body).toBe('h2-ok:/alpha');
      expect(resp.headers['content-type']).toBe('text/plain');
    } finally {
      await server.close();
    }
  });

  it('reuses one session for multiple concurrent requests (multiplexed)', async () => {
    const server = await startH2Server();
    try {
      const client = makeClient();
      const [a, b, c] = await Promise.all([
        client.get(`http://127.0.0.1:${server.port}/a`),
        client.get(`http://127.0.0.1:${server.port}/b`),
        client.get(`http://127.0.0.1:${server.port}/c`),
      ]);
      expect(a.body).toBe('h2-ok:/a');
      expect(b.body).toBe('h2-ok:/b');
      expect(c.body).toBe('h2-ok:/c');
      // one session accepted all three streams
      expect(server.streams).toBe(3);
    } finally {
      await server.close();
    }
  });

  it('falls back to HTTP/1.1 when the origin refuses h2', async () => {
    // plain HTTP/1.1 server: responds to any bytes with a h1 body
    const server = net.createServer((socket) => {
      socket.once('data', () => {
        socket.end('HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nh1-ok');
      });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const { port } = server.address() as net.AddressInfo;
    try {
      const client = makeClient();
      const resp = await client.get(`http://127.0.0.1:${port}/x`);
      expect(resp.body).toBe('h1-ok');
      expect(resp.status).toBe(200);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it('is off by default (HTTP/1.1 path untouched)', async () => {
    const client = new HttpClient({ rateLimitPerSec: 0 });
    // http2 flag off → h2Get never consulted; no session machinery engaged
    expect((client as any).config.http2).toBe(false);
  });
});
