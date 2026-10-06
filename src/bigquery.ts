/**
 * BigQuery client for header harvest (B-13) — Youstin-style HTTP Archive
 * queries (kimi.md Phase 1). Stdlib only: service-account JWT is signed with
 * node:crypto and the REST API is called with global fetch, so no GCP SDK
 * dependency is added. All network calls accept an injectable fetch for tests.
 */
import * as crypto from 'crypto';
import * as fs from 'fs';

export interface ServiceAccount {
  client_email: string;
  private_key: string;
}

export type FetchLike = (url: string, init?: {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

/**
 * HTTP Archive header-frequency query (httparchive.all.requests — top-level
 * request_headers repeated structs). Restricted to main documents of the
 * latest crawl to keep the scan cost-bounded; override via bigQuerySql.
 */
export const DEFAULT_HEADER_SQL = `
SELECT LOWER(h.name) AS header, COUNT(DISTINCT page) AS sites, COUNT(*) AS freq
FROM \`httparchive.all.requests\`,
UNNEST(request_headers) AS h
WHERE date = (SELECT MAX(date) FROM \`httparchive.all.requests\`)
  AND is_main_document
GROUP BY 1
HAVING sites >= 10
ORDER BY sites DESC
LIMIT 25000
`.trim();

function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function loadServiceAccount(credPath: string): ServiceAccount {
  const raw = fs.readFileSync(credPath, 'utf-8');
  const parsed = JSON.parse(raw) as Partial<ServiceAccount>;
  if (!parsed.client_email || !parsed.private_key) {
    throw new Error(`Service account key missing client_email/private_key: ${credPath}`);
  }
  return { client_email: parsed.client_email, private_key: parsed.private_key };
}

/** Mint a Google OAuth2 access token from a service-account key (RS256 JWT). */
export async function mintAccessToken(
  sa: ServiceAccount,
  nowMs: number = Date.now(),
  fetchImpl: FetchLike = globalThis.fetch as FetchLike,
): Promise<string> {
  const iat = Math.floor(nowMs / 1000);
  const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claims = b64url(JSON.stringify({
    iss: sa.client_email,
    scope: 'https://www.googleapis.com/auth/bigquery',
    aud: 'https://oauth2.googleapis.com/token',
    iat,
    exp: iat + 3600,
  }));
  const unsigned = `${header}.${claims}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(unsigned);
  const signature = b64url(signer.sign(sa.private_key));
  const assertion = `${unsigned}.${signature}`;

  const resp = await fetchImpl('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${encodeURIComponent(assertion)}`,
  });
  const body = JSON.parse(await resp.text()) as { access_token?: string; error?: string };
  if (!resp.ok || !body.access_token) {
    throw new Error(`OAuth token exchange failed (${resp.status}): ${body.error || 'no access_token'}`);
  }
  return body.access_token;
}

/**
 * Run a SQL query via the BigQuery jobs.query REST API. Returns raw row
 * cells (each row = array of column values, jobComplete responses only).
 */
export async function runQuery(
  sql: string,
  opts: {
    project: string;
    accessToken: string;
    fetchImpl?: FetchLike;
    maxResults?: number;
    timeoutMs?: number;
  },
): Promise<unknown[][]> {
  const fetchImpl = opts.fetchImpl ?? (globalThis.fetch as FetchLike);
  const url = `https://bigquery.googleapis.com/bigquery/v2/projects/${encodeURIComponent(opts.project)}/queries`;
  const resp = await fetchImpl(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${opts.accessToken}`,
    },
    body: JSON.stringify({
      query: sql,
      useLegacySql: false,
      maxResults: opts.maxResults ?? 25000,
      timeoutMs: opts.timeoutMs ?? 120000,
    }),
  });
  const body = JSON.parse(await resp.text()) as {
    jobComplete?: boolean;
    errors?: Array<{ message: string }>;
    rows?: Array<{ f: Array<{ v?: string | null }> }>;
  };
  if (!resp.ok || body.jobComplete === false || body.errors?.length) {
    const msg = body.errors?.map((e) => e.message).join('; ') || `HTTP ${resp.status}`;
    throw new Error(`BigQuery query failed: ${msg}`);
  }
  return (body.rows ?? []).map((row) => row.f.map((cell) => cell.v ?? ''));
}
