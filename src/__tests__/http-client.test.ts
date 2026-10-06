import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as net from 'node:net';
import { HttpClient } from '../http-client';

describe('HttpClient', () => {
  let client: HttpClient;

  beforeEach(() => {
    client = new HttpClient({
      timeoutMs: 5000,
      maxRetries: 2,
      rateLimitPerSec: 10,
    });
  });

  it('should have correct type exports', () => {
    expect(typeof HttpClient).toBe('function');
  });

  it('should accept config with defaults', () => {
    const defaultClient = new HttpClient();
    expect(defaultClient).toBeDefined();
  });

  it('should track request count', () => {
    expect(client.getRequestCount()).toBe(0);
  });

  it('should support cookie jar', () => {
    client.setCookie('session=abc123', 'https://example.com');
    const cookies = client.getCookies('https://example.com');
    expect(cookies).toContain('session=abc123');
  });

  it('should not leak cookies across domains', () => {
    client.setCookie('session=abc123', 'https://example.com');
    const cookies = client.getCookies('https://other.com');
    expect(cookies).toHaveLength(0);
  });

  it('should match cookies by domain suffix', () => {
    client.setCookie('session=abc123', 'example.com');
    const cookies = client.getCookies('https://sub.example.com');
    expect(cookies).toContain('session=abc123');
  });

  it('should reset request count', () => {
    client.resetRequestCount();
    expect(client.getRequestCount()).toBe(0);
  });

  it('spaces concurrent request starts (chain-safe rate limit, B-22)', async () => {
    const arrivals: number[] = [];
    const server = net.createServer((socket) => {
      socket.once('data', () => {
        arrivals.push(Date.now());
        socket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok');
      });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const { port } = server.address() as net.AddressInfo;
    try {
      const fast = new HttpClient({ timeoutMs: 5000, rateLimitPerSec: 5, maxRetries: 1 });
      // warm up: first dynamic node-fetch import adds ~150ms send latency
      await fast.get(`http://127.0.0.1:${port}/warmup`);
      arrivals.length = 0;
      await Promise.all([
        fast.get(`http://127.0.0.1:${port}/a`),
        fast.get(`http://127.0.0.1:${port}/b`),
        fast.get(`http://127.0.0.1:${port}/c`),
      ]);
      expect(arrivals).toHaveLength(3);
      const sorted = [...arrivals].sort((x, y) => x - y);
      // minInterval at 5 req/s = 200ms; allow small scheduler slack
      expect(sorted[1] - sorted[0]).toBeGreaterThanOrEqual(150);
      expect(sorted[2] - sorted[1]).toBeGreaterThanOrEqual(150);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
});
