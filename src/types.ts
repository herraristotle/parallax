// Core types for Parallax toolkit

export interface CacheProbeConfig {
  target: string;
  cookie?: string;
  headers?: Record<string, string>;
}

export interface CDNFingerprint {
  name: string;
  confidence: number;
  allMatches: Record<string, number>;
}

export interface ProxyFingerprint {
  name: string;
  confidence: number;
  allMatches: Record<string, number>;
}

export interface FrameworkFingerprint {
  name: string;
  confidence: number;
  version?: string;
  allMatches: Record<string, number>;
}

export interface HeaderWordlist {
  fast: string[];
  all: string[];
  totalUncommon: number;
  totalVary: number;
  totalCDNInternal: number;
  totalIANA: number;
}

export interface CachePoisonConfig {
  target: string;
  cookie?: string;
  headers?: Record<string, string>;
  cdnName?: string;
  wordlistTier?: 'fast' | 'all';
  framework?: string;
  /** Harvested (BigQuery/HCache-derived) header wordlist from Stage 2. */
  wordlist?: { fast: string[]; all: string[] };
}

export interface CacheDiffConfig {
  target: string;
  cookie?: string;
  headers?: Record<string, string>;
}

export interface PipelineConfig {
  target: string;
  timeBudgetMs?: number;
  cookie?: string;
  headers?: Record<string, string>;
  wordlistTier?: 'fast' | 'all';
  /** Shared HttpClient start-rate; default 10 req/s. Raise to cut wall-clock per URL. */
  rateLimitPerSec?: number;
  /** Route GETs over HTTP/2 sessions (falls back to HTTP/1.1 per origin). */
  http2?: boolean;
  /** Stage-2 BigQuery HTTP Archive harvest (B-13): billing project id. */
  bigQueryProject?: string;
  /** Service-account JSON path (defaults to GOOGLE_APPLICATION_CREDENTIALS). */
  bigQueryCredentialsPath?: string;
  /** Override the default header-frequency SQL. */
  bigQuerySql?: string;
  enableTiming?: boolean;
  enableDiff?: boolean;
  enablePoison?: boolean;
  enableWeaponize?: boolean;
  enableDeception?: boolean;
}

export interface PipelineResult {
  probe: ProbeResult;
  discover: DiscoverResult;
  diff: DiffResult[];
  poison: PoisonResult[];
  weaponize: WeaponizeResult[];
  /** Web Cache Deception findings (Gil 2017) — present when Stage 4b ran. */
  deception?: DeceptionFinding[];
}

/** Batch-scan failure record — schema for `error` entries in batch summaries. */
export interface PipelineErrorEntry {
  target: string;
  error: string;
}

export interface DeceptionFinding {
  /** Original dynamic endpoint the deceptive suffix was appended to. */
  endpoint: string;
  /** The deceptive URL that got cached. */
  attackUrl: string;
  /** Suffix/pattern that triggered caching (e.g. `.css`). */
  pattern: string;
  /** Server echoed the dynamic body under the deceptive URL. */
  originServed: boolean;
  /** Cache stored the response (confirmed by second-request HIT evidence). */
  cached: boolean;
  /** Cache-control / CDN header evidence, lowercased. */
  cacheEvidence: Record<string, string>;
  /** Content-type the origin returned for the deceptive URL. */
  originContentType?: string;
  confirmed: boolean;
}

export interface ProbeResult {
  cdn: CDNFingerprint;
  proxy: ProxyFingerprint;
  framework: FrameworkFingerprint;
  cacheKey: CacheKeySpec;
  hiddenCacheDetected: boolean;
}

export interface CDNSignature {
  name: string;
  confidence: number;
  matchedHeaders: string[];
  keyedHeaders: Set<string>;
}

export interface ProxySignature {
  name: string;
  confidence: number;
  headers: string[];
}

export interface FrameworkSignature {
  name: string;
  version?: string;
  confidence: number;
  cacheHeaders: string[];
}

export interface CacheKeyComponent {
  scheme: boolean;
  host: boolean;
  hostCaseSensitive: boolean;
  path: boolean;
  pathCaseSensitive: boolean;
  pathNormalized: boolean;
  queryString: boolean;
  querySorted: boolean;
  port: boolean;
  headersKeyed: string[];
  fragmentStripped: boolean;
}

export interface CacheKeySpec extends CacheKeyComponent {
  rawHeaders: Record<string, string>;
  timestamp: string;
}

export interface HeaderSource {
  name: string;
  source: 'bigquery-uncommon' | 'bigquery-vary' | 'cdn-internal' | 'iana';
  frequency: number;
  sites: number;
}

export interface HeaderHarvestConfig {
  /** GCP project that bills the HTTP Archive query; enables the BigQuery path. */
  bigQueryProject?: string;
  /** Service-account JSON path (defaults to GOOGLE_APPLICATION_CREDENTIALS). */
  bigQueryCredentialsPath?: string;
  /** Override the default httparchive.all.requests header-frequency SQL. */
  bigQuerySql?: string;
  lowThreshold?: number;
  highThreshold?: number;
  varyExclusions?: string[];
  headersFile?: string;
  parametersFile?: string;
}

export interface WordlistTier {
  fast: string[];
  all: string[];
}

export interface DiffConfig {
  targetUrls: string[];
  byteRange?: [number, number];
  positions?: ('prefix' | 'infix' | 'suffix')[];
  encodings?: ('raw' | 'single' | 'double' | 'triple')[];
}

export interface DiffSignal {
  bodyReflection: boolean;
  headerReflection: Record<string, string>;
  statusChanged: boolean;
  sizeDeltaPercent: number;
  newHeaders: string[];
  securityHeaderChanges: Record<string, { before: string; after: string }>;
  bodyContext?: 'script_tag' | 'attribute_url' | 'link_tag' | 'meta_tag' | 'image_tag' | 'form_tag' | 'inline_style' | 'generic';
  /** CSPT sink hit (B-26): reflected path sits in a client-side URL sink. */
  csptSink?: { sink: string; evidence: string };
}

export interface PathFuzzResult {
  originalUrl: string;
  fuzzedUrl: string;
  byte: number;
  position: 'prefix' | 'infix' | 'suffix';
  encoding: 'raw' | 'single' | 'double' | 'triple';
  signals: DiffSignal;
  cacheHit: boolean;
}

export interface PoisonConfig {
  targetUrl: string;
  wordlistTier: 'fast' | 'all';
  cookie?: string;
  headers?: Record<string, string>;
  enableCookies?: boolean;
  enableQueryString?: boolean;
  enableParameterCloaking?: boolean;
  enableFragmentForwarding?: boolean;
  enableCacheInvalidation?: boolean;
  enableNextJS?: boolean;
  enableImportHijacking?: boolean;
  enableIllegalHeaders?: boolean;
  enablePayloadSplitting?: boolean;
  enableSurrogateKeys?: boolean;
  enableOAuth?: boolean;
  enableMultiCDN?: boolean;
}

export interface CacheKeyOracle {
  header: string;
  canary: string;
  cachebuster: string;
  pinnedUA: string;
  primeResponse: PoisonResponse;
  verifyResponse: PoisonResponse;
  canaryPersisted: boolean;
}

export interface PoisonResponse {
  status: number;
  headers: Record<string, string>;
  bodyPreview: string;
  bodyHash: string;
  cacheStatus?: string;
  timing: number;
}

export interface PoisonFinding {
  inputType: 'header' | 'cookie' | 'query' | 'path' | 'body' | 'pseudo-header' | 'fragment' | 'illegal-header';
  inputName: string;
  canary: string;
  signals: DiffSignal;
  oracle: CacheKeyOracle;
  classification: ExploitClassification;
  attackClass: 'cpdos' | 'waf_poison' | 'content_poison' | 'header_poison';
  confidence: 'CONFIRMED' | 'LIKELY' | 'POSSIBLE';
  blastRadius: BlastRadius;
}

export type ExploitClassification =
  | 'xss'
  | 'open_redirect'
  | 'session_fixation'
  | 'csp_bypass'
  | 'cpdos'
  | 'security_header_poisoning'
  | 'behaviour_poisoning'
  | 'import_hijacking'
  | 'oauth_hijacking'
  | 'cache_invalidation'
  | 'surrogate_key_control'
  | 'payload_splitting'
  | 'multi_cdn_mismatch'
  | 'illegal_header'
  | 'fragment'
  | 'nextjs'
  | 'invalidation'
  | 'surrogate'
  | 'payload_split'
  | 'waf_poison'
  | 'unknown';

/** 4-phase weaponize generation (kimi.md parity: "4-phase PoC generation"). */
export type WeaponizePhase = 'blast-radius' | 'classify' | 'reproduce' | 'report';

export interface WeaponizePhaseResult {
  phase: WeaponizePhase;
  status: 'complete';
  detail: string;
}

export interface WeaponizeConfig {
  findings: PoisonFinding[];
  targetUrl: string;
}

export interface ExploitChain {
  finding: PoisonFinding;
  poc: ProofOfConcept;
  impact: ImpactAssessment;
  blastRadius: BlastRadius;
  prerequisites: string[];
  /** 4-phase generation transcript (blast-radius → classify → reproduce → report). */
  phases: WeaponizePhaseResult[];
}

export interface ProofOfConcept {
  description: string;
  steps: string[];
  curlCommand: string;
  expectedResult: string;
}

export interface ImpactAssessment {
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvss: number;
  description: string;
  affectedUsers: 'all' | 'vary-targeted' | 'device-specific';
}

export interface BlastRadius {
  scope: 'global' | 'vary-targeted' | 'device-specific' | 'user-specific';
  varyHeader?: string;
  deviceTypes: DeviceType[];
  estimatedUsers?: number;
}

export type DeviceType = 'desktop' | 'mobile' | 'googlebot' | 'custom';

export interface WeaponizeResult {
  chains: ExploitChain[];
  summary: {
    total: number;
    bySeverity: Record<string, number>;
    byClass: Record<string, number>;
  };
}

export interface DiscoverResult {
  cachedUrls: CachedUrl[];
  uncacheableUrls: string[];
  totalTested: number;
}

export interface CachedUrl {
  url: string;
  cacheStatus: string;
  cacheHeaders: Record<string, string>;
  isTargetUrl: boolean;
}

export interface DiffResult {
  url: string;
  fuzzResults: PathFuzzResult[];
  unkeyedDelimiters: string[];
}

export interface PoisonResult {
  findings: PoisonFinding[];
  statistics: {
    headersTested: number;
    headersReflected: number;
    headersUnkeyed: number;
    classifications: Record<string, number>;
  };
}