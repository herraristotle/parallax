import { describe, it, expect } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { DEFAULT_HEADER_SQL, loadServiceAccount, mintAccessToken, runQuery, ServiceAccount, FetchLike } from '../bigquery';

function makeServiceAccount(): { sa: ServiceAccount; credPath: string } {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const sa: ServiceAccount = {
    client_email: 'test@proj.iam.gserviceaccount.com',
    private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
  const credPath = path.join(os.tmpdir(), `sa-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  fs.writeFileSync(credPath, JSON.stringify(sa));
  return { sa, credPath };
}

describe('bigquery client (B-13)', () => {
  it('parses a service-account key and rejects malformed ones', () => {
    const { credPath } = makeServiceAccount();
    try {
      const sa = loadServiceAccount(credPath);
      expect(sa.client_email).toMatch(/@/);
      expect(sa.private_key).toContain('BEGIN PRIVATE KEY');
    } finally {
      fs.unlinkSync(credPath);
    }
    const badPath = path.join(os.tmpdir(), `bad-${Date.now()}.json`);
    fs.writeFileSync(badPath, JSON.stringify({ client_email: 'x@y.z' }));
    try {
      expect(() => loadServiceAccount(badPath)).toThrow(/missing/);
    } finally {
      fs.unlinkSync(badPath);
    }
  });

  it('mints an RS256 JWT and exchanges it for an access token', async () => {
    const { sa } = makeServiceAccount();
    const calls: Array<{ url: string; body?: string }> = [];
    const fetchImpl: FetchLike = async (url, init) => {
      calls.push({ url, body: init?.body });
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ access_token: 'tok-abc', token_type: 'Bearer' }),
      };
    };
    const token = await mintAccessToken(sa, 1_700_000_000_000, fetchImpl);
    expect(token).toBe('tok-abc');
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://oauth2.googleapis.com/token');
    const assertion = new URLSearchParams(calls[0].body!).get('assertion')!;
    const parts = assertion.split('.');
    expect(parts).toHaveLength(3);
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    expect(header).toEqual({ alg: 'RS256', typ: 'JWT' });
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    expect(claims.iss).toBe(sa.client_email);
    expect(claims.exp).toBe(1_700_000_000 + 3600);
    // signature verifies against the public key
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(`${parts[0]}.${parts[1]}`);
    const pub = crypto.createPublicKey(sa.private_key);
    expect(verifier.verify(pub, Buffer.from(parts[2], 'base64url'))).toBe(true);
  });

  it('surfaces OAuth exchange failures', async () => {
    const { sa } = makeServiceAccount();
    const fetchImpl: FetchLike = async () => ({
      ok: false,
      status: 400,
      text: async () => JSON.stringify({ error: 'invalid_grant' }),
    });
    await expect(mintAccessToken(sa, Date.now(), fetchImpl)).rejects.toThrow(/invalid_grant/);
  });

  it('runs a query and maps first-column rows', async () => {
    const seen: Array<{ url: string; body?: string }> = [];
    const fetchImpl: FetchLike = async (url, init) => {
      seen.push({ url, body: init?.body });
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({
          jobComplete: true,
          rows: [
            { f: [{ v: 'X-Custom-Header' }, { v: '12' }] },
            { f: [{ v: 'x-api-key' }, { v: '9' }] },
          ],
        }),
      };
    };
    const rows = await runQuery('SELECT header, sites', {
      project: 'bill-proj',
      accessToken: 'tok',
      fetchImpl,
    });
    expect(rows).toEqual([['X-Custom-Header', '12'], ['x-api-key', '9']]);
    expect(seen[0].url).toContain('/projects/bill-proj/queries');
    const sent = JSON.parse(seen[0].body!);
    expect(sent.useLegacySql).toBe(false);
    expect(sent.query).toBe('SELECT header, sites');
  });

  it('throws on BigQuery error payloads', async () => {
    const fetchImpl: FetchLike = async () => ({
      ok: false,
      status: 400,
      text: async () => JSON.stringify({ errors: [{ message: 'Permission denied: table httparchive.all.requests' }] }),
    });
    await expect(
      runQuery('SELECT 1', { project: 'p', accessToken: 't', fetchImpl }),
    ).rejects.toThrow(/Permission denied/);
  });

  it('default SQL targets httparchive.all.requests main documents', () => {
    expect(DEFAULT_HEADER_SQL).toContain('httparchive.all.requests');
    expect(DEFAULT_HEADER_SQL).toContain('request_headers');
    expect(DEFAULT_HEADER_SQL).toContain('is_main_document');
  });
});
