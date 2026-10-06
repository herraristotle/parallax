import * as net from 'node:net';
import * as tls from 'node:tls';

export interface RawHttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  connected: boolean;
  error?: string;
}

interface ParsedResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

function parseHttpResponse(raw: string): ParsedResponse | null {
  if (!raw) return null;
  const idx = raw.indexOf('\r\n\r\n');
  const head = idx === -1 ? raw : raw.slice(0, idx);
  const body = idx === -1 ? '' : raw.slice(idx + 4);
  const statusLine = head.split('\r\n')[0] ?? '';
  const status = Number(statusLine.split(' ')[1]);
  if (!Number.isFinite(status) || status === 0) return null;
  const headers: Record<string, string> = {};
  for (const line of head.split('\r\n').slice(1)) {
    const c = line.indexOf(':');
    if (c > 0) headers[line.slice(0, c).trim().toLowerCase()] = line.slice(c + 1).trim();
  }
  return { status, headers, body };
}

/**
 * Send one HTTP/1.1 request with a header line that undici/h11 refuse to
 * serialize (control bytes, spaces, bare names). Generic transport plumbing:
 * the caller supplies the raw line; no payloads are generated here.
 */
export function rawHeaderRequest(
  targetUrl: string,
  headerLine: string,
  extraHeaders: Record<string, string> = {},
  timeoutMs = 5000,
): Promise<RawHttpResponse> {
  const u = new URL(targetUrl);
  const secure = u.protocol === 'https:';
  const port = u.port ? Number(u.port) : secure ? 443 : 80;
  const path = `${u.pathname || '/'}${u.search || ''}`;

  const request = [
    `GET ${path} HTTP/1.1`,
    `Host: ${u.host}`,
    ...Object.entries(extraHeaders).map(([k, v]) => `${k}: ${v}`),
    headerLine,
    'Connection: close',
    '',
    '',
  ].join('\r\n');

  return new Promise((resolve) => {
    let settled = false;
    let connected = false;
    let buf = '';
    const socket: net.Socket = secure
      ? tls.connect({ host: u.hostname, port, servername: u.hostname })
      : net.connect({ host: u.hostname, port });

    const finish = (error?: string) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      const parsed = parseHttpResponse(buf);
      if (parsed) {
        resolve({ ...parsed, connected, ...(error ? { error } : {}) });
      } else {
        resolve({
          status: 0,
          headers: {},
          body: '',
          connected,
          error: error || 'no response',
        });
      }
    };

    socket.setTimeout(timeoutMs, () => finish('timeout'));
    socket.once(secure ? 'secureConnect' : 'connect', () => {
      connected = true;
      socket.end(request); // half-close after write so servers see EOF
    });
    socket.on('data', (d: Buffer) => {
      buf += d.toString('latin1');
    });
    socket.on('end', () => finish());
    socket.on('close', () => finish());
    socket.on('error', (e: Error) => finish(e.message));
  });
}
