import { describe, it, expect, vi, beforeEach } from 'vitest';
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
});
