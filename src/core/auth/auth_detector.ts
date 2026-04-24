/**
 * Auth Detection Service (S6)
 *
 * Probes in-scope targets and analyzes program metadata to detect
 * authentication requirements. Returns structured results that drive
 * the AuthWizardModal UI.
 *
 * Three detection methods run concurrently:
 * 1. HTTP probing — GET each target, check for 401/403/redirect-to-login
 * 2. Program text analysis — keyword scan for auth patterns
 * 3. Tech fingerprinting — response header analysis
 *
 * Design constraints:
 * - No LLM calls — pure deterministic heuristics
 * - Probes are read-only (GET only)
 * - 5s timeout per target, max 8 targets
 * - All probes go through HttpClient (scope validation enforced)
 * - Graceful degradation on network errors
 */

import type { HttpClient, HttpResponse } from '../http/request_engine';
import type { AuthProfileConfig } from '../../contexts/SettingsContext';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AuthDetectionResult {
  /** Whether any target requires authentication */
  requiresAuth: boolean;
  /** Overall confidence in the detection (0-1) */
  confidence: number;
  /** Per-target probe results */
  probeResults: TargetProbeResult[];
  /** Auth types detected with evidence */
  detectedAuthTypes: DetectedAuthType[];
  /** Suggested auth profiles the user should create */
  suggestedProfiles: SuggestedAuthProfile[];
  /** Step-by-step instructions for manual setup (generated based on detected auth type) */
  manualSteps: string[];
  /** Keywords found in program text */
  programHints: string[];
}

export interface TargetProbeResult {
  url: string;
  status: number;
  authWall: boolean;
  redirectsToLogin: boolean;
  loginUrl?: string;
  wwwAuthenticate?: string;
  hasLoginForm: boolean;
  techFingerprint?: string;
  error?: string;
}

export interface DetectedAuthType {
  type: 'bearer' | 'cookie' | 'api_key' | 'custom_header' | 'oauth' | 'telegram_webapp' | 'basic';
  confidence: number;
  evidence: string;
  headerName?: string;
  loginUrl?: string;
}

export interface SuggestedAuthProfile {
  label: string;
  authType: AuthProfileConfig['authType'];
  url?: string;
  headerName?: string;
  /** Ordered instructions the user must follow */
  instructions: string[];
  /** Whether the platform can fully automate this */
  automationLevel: 'full' | 'partial' | 'manual';
}

// ─── Constants ───────────────────────────────────────────────────────────────

const PROBE_TIMEOUT_MS = 5000;
const MAX_PROBE_TARGETS = 8;

/** Login-related path patterns in redirect Location headers */
const LOGIN_PATH_PATTERNS = ['/login', '/signin', '/auth', '/sso', '/oauth', '/sign-in', '/log-in'];

/** Patterns for detecting login forms in HTML response bodies */
const LOGIN_FORM_PATTERNS = [
  /<input[^>]*type\s*=\s*["']password["']/i,
  /<input[^>]*name\s*=\s*["']username["']/i,
  /<input[^>]*name\s*=\s*["']email["']/i,
  /<form[^>]*action\s*=\s*["'][^"']*login[^"']*["']/i,
];

// ─── Program Text Pattern Groups ─────────────────────────────────────────────

interface PatternGroup {
  type: DetectedAuthType['type'];
  profileType: AuthProfileConfig['authType'];
  patterns: RegExp[];
  baseConfidence: number;
  label: string;
}

const PATTERN_GROUPS: PatternGroup[] = [
  {
    type: 'telegram_webapp',
    profileType: 'custom_header',
    patterns: [
      /\btelegram\b/i,
      /\bmini\s*app\b/i,
      /\bwebapp\b/i,
      /\btwa\b/i,
      /\binitData\b/i,
      /\b@\w+bot\b/i,
    ],
    baseConfidence: 0.7,
    label: 'Telegram WebApp',
  },
  {
    type: 'oauth',
    profileType: 'bearer',
    patterns: [
      /\boauth\b/i,
      /\bopenid\b/i,
      /\bsso\b/i,
      /\bsaml\b/i,
    ],
    baseConfidence: 0.6,
    label: 'OAuth/SSO',
  },
  {
    type: 'api_key',
    profileType: 'api_key',
    patterns: [
      /\bapi[_\s-]?key\b/i,
      /\bx-api-key\b/i,
      /\bapikey\b/i,
    ],
    baseConfidence: 0.7,
    label: 'API Key',
  },
  {
    type: 'bearer',
    profileType: 'bearer',
    patterns: [
      /\bjwt\b/i,
      /\bbearer\b/i,
      /\bauthorization\s+header\b/i,
    ],
    baseConfidence: 0.6,
    label: 'Bearer Token',
  },
  {
    type: 'cookie',
    profileType: 'cookie',
    patterns: [
      /\blogin\b/i,
      /\bsession\b/i,
      /\bcookie\b/i,
      /\bcredentials\b/i,
    ],
    baseConfidence: 0.4,
    label: 'Session/Cookie',
  },
];

// ─── Tech Fingerprint Rules ─────────────────────────────────────────────────

interface FingerprintRule {
  test: (headers: Record<string, string>, status: number) => boolean;
  authType: DetectedAuthType['type'];
  confidence: number;
  evidence: string;
}

const FINGERPRINT_RULES: FingerprintRule[] = [
  {
    test: (h, s) => (h['server']?.toLowerCase().includes('cloudflare') ?? false) && s === 403,
    authType: 'bearer',
    confidence: 0.7,
    evidence: 'Cloudflare Access detected (Server: cloudflare + 403)',
  },
  {
    test: (h) => /\bExpress\b/i.test(h['x-powered-by'] ?? ''),
    authType: 'bearer',
    confidence: 0.4,
    evidence: 'Node.js/Express detected — likely JWT/bearer auth',
  },
  {
    test: (h) => /PHPSESSID/i.test(h['set-cookie'] ?? ''),
    authType: 'cookie',
    confidence: 0.5,
    evidence: 'PHP session detected (PHPSESSID cookie) — form-based login likely',
  },
  {
    test: (h) => /csrftoken/i.test(h['set-cookie'] ?? ''),
    authType: 'cookie',
    confidence: 0.6,
    evidence: 'Django detected (csrftoken cookie) — form-based login with CSRF',
  },
];

// ─── AuthDetector ────────────────────────────────────────────────────────────

export class AuthDetector {
  /**
   * Detect auth requirements for a program's in-scope targets.
   *
   * @param targets - In-scope target URLs/domains (first 8 probed)
   * @param programName - Program name (e.g., "Wallet on Telegram")
   * @param programRules - Program rules text for keyword analysis
   * @param httpClient - HttpClient instance (scope validation enforced)
   * @returns Structured detection result
   */
  static async detect(
    targets: string[],
    programName: string,
    programRules: string[],
    httpClient: HttpClient,
  ): Promise<AuthDetectionResult> {
    // Run probing and text analysis concurrently
    const [probeResults, textAnalysis] = await Promise.all([
      AuthDetector.probeTargets(targets, httpClient),
      Promise.resolve(AuthDetector.analyzeText(programName, programRules, targets)),
    ]);

    // Extract tech fingerprints from probe results (synchronous)
    const fingerprintDetections = AuthDetector.fingerprintFromProbes(probeResults);

    // Merge all detected auth types, keeping highest confidence per type
    const allDetections = AuthDetector.mergeDetections(textAnalysis, fingerprintDetections);

    // Determine overall auth requirement
    const hasAuthWall = probeResults.some(p => p.authWall || p.redirectsToLogin);
    const hasTextSignals = textAnalysis.length > 0;
    const hasFingerprintSignals = fingerprintDetections.length > 0;
    const requiresAuth = hasAuthWall || hasTextSignals || hasFingerprintSignals;

    // Calculate overall confidence
    const maxConfidence = allDetections.length > 0
      ? Math.max(...allDetections.map(d => d.confidence))
      : 0;
    const signalCount = [hasAuthWall, hasTextSignals, hasFingerprintSignals].filter(Boolean).length;
    const confidence = Math.min(1, maxConfidence + (signalCount > 1 ? 0.15 : 0));

    // Collect program hints
    const programHints = textAnalysis.map(d => d.evidence);

    // Generate suggested profiles
    const suggestedProfiles = AuthDetector.generateSuggestedProfiles(
      allDetections, probeResults, programName,
    );

    // Generate manual steps from top detection
    const manualSteps = suggestedProfiles.length > 0
      ? suggestedProfiles[0].instructions
      : [];

    return {
      requiresAuth,
      confidence,
      probeResults,
      detectedAuthTypes: allDetections,
      suggestedProfiles,
      manualSteps,
      programHints,
    };
  }

  // ─── HTTP Probing ──────────────────────────────────────────────────────────

  /** Probe up to MAX_PROBE_TARGETS targets with GET requests */
  static async probeTargets(
    targets: string[],
    httpClient: HttpClient,
  ): Promise<TargetProbeResult[]> {
    const normalizedTargets = targets
      .slice(0, MAX_PROBE_TARGETS)
      .map(AuthDetector.normalizeTargetUrl);

    const results = await Promise.allSettled(
      normalizedTargets.map(url => AuthDetector.probeSingleTarget(url, httpClient)),
    );

    return results.map((r, i) => {
      if (r.status === 'fulfilled') return r.value;
      return {
        url: normalizedTargets[i],
        status: 0,
        authWall: false,
        redirectsToLogin: false,
        hasLoginForm: false,
        error: r.reason instanceof Error ? r.reason.message : String(r.reason),
      };
    });
  }

  /** Probe a single target URL */
  private static async probeSingleTarget(
    url: string,
    httpClient: HttpClient,
  ): Promise<TargetProbeResult> {
    try {
      const response: HttpResponse = await httpClient.request({
        url,
        method: 'GET',
        timeoutMs: PROBE_TIMEOUT_MS,
        followRedirects: false,
      });

      const result: TargetProbeResult = {
        url,
        status: response.status,
        authWall: response.status === 401 || response.status === 403,
        redirectsToLogin: false,
        hasLoginForm: false,
      };

      // Check WWW-Authenticate header
      const wwwAuth = response.headers['www-authenticate'];
      if (wwwAuth) {
        result.wwwAuthenticate = wwwAuth;
      }

      // Check for redirect to login
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers['location'] ?? '';
        const locationLower = location.toLowerCase();
        if (LOGIN_PATH_PATTERNS.some(p => locationLower.includes(p))) {
          result.redirectsToLogin = true;
          result.authWall = true;
          try {
            result.loginUrl = new URL(location, url).toString();
          } catch {
            result.loginUrl = location;
          }
        }
      }

      // Check for login form in response body
      if (response.body && response.status === 200) {
        result.hasLoginForm = LOGIN_FORM_PATTERNS.some(p => p.test(response.body));
        if (result.hasLoginForm) {
          result.authWall = true;
        }
      }

      // Tech fingerprinting from response headers
      result.techFingerprint = AuthDetector.detectTechFromHeaders(response.headers);

      return result;
    } catch (err) {
      return {
        url,
        status: 0,
        authWall: false,
        redirectsToLogin: false,
        hasLoginForm: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  // ─── Program Text Analysis ─────────────────────────────────────────────────

  /** Scan program name, rules, and scope for auth-related keywords */
  static analyzeText(
    programName: string,
    rules: string[],
    targets: string[],
  ): DetectedAuthType[] {
    const fullText = [programName, ...rules, ...targets].join(' ');
    const detected: DetectedAuthType[] = [];

    for (const group of PATTERN_GROUPS) {
      const matchedPatterns = group.patterns.filter(p => p.test(fullText));
      if (matchedPatterns.length > 0) {
        const boost = Math.min(0.3, matchedPatterns.length * 0.1);
        detected.push({
          type: group.type,
          confidence: Math.min(1, group.baseConfidence + boost),
          evidence: `Program text matches: ${matchedPatterns.map(p => p.source).join(', ')}`,
        });
      }
    }

    // Extract specific API key header name if mentioned
    const apiKeyHeaderMatch = /\b(x-[\w-]*api[\w-]*key[\w-]*)\b/i.exec(fullText);
    if (apiKeyHeaderMatch) {
      const existing = detected.find(d => d.type === 'api_key');
      if (existing) {
        existing.headerName = apiKeyHeaderMatch[1];
      }
    }

    return detected;
  }

  // ─── Fingerprinting from Probes ────────────────────────────────────────────

  /** Extract auth type detections from probe results */
  private static fingerprintFromProbes(probes: TargetProbeResult[]): DetectedAuthType[] {
    const detected: DetectedAuthType[] = [];

    for (const probe of probes) {
      if (probe.error) continue;

      // WWW-Authenticate header identifies the auth scheme directly
      if (probe.wwwAuthenticate) {
        const scheme = probe.wwwAuthenticate.split(/\s/)[0].toLowerCase();
        if (scheme === 'basic') {
          detected.push({
            type: 'basic',
            confidence: 0.9,
            evidence: `WWW-Authenticate: Basic on ${probe.url}`,
          });
        } else if (scheme === 'bearer') {
          detected.push({
            type: 'bearer',
            confidence: 0.9,
            evidence: `WWW-Authenticate: Bearer on ${probe.url}`,
          });
        }
      }

      // Login form detected in page body
      if (probe.hasLoginForm && probe.status === 200) {
        detected.push({
          type: 'cookie',
          confidence: 0.8,
          evidence: `Login form detected on ${probe.url}`,
          loginUrl: probe.url,
        });
      }

      // Redirect to login page
      if (probe.redirectsToLogin && probe.loginUrl) {
        detected.push({
          type: 'cookie',
          confidence: 0.7,
          evidence: `Redirects to login page: ${probe.loginUrl}`,
          loginUrl: probe.loginUrl,
        });
      }

      // Tech fingerprint rules
      if (probe.techFingerprint) {
        const headers: Record<string, string> = {};
        if (probe.techFingerprint === 'Cloudflare') headers['server'] = 'cloudflare';
        if (probe.techFingerprint === 'Express') headers['x-powered-by'] = 'Express';
        if (probe.techFingerprint === 'PHP') headers['set-cookie'] = 'PHPSESSID=abc';
        if (probe.techFingerprint === 'Django') headers['set-cookie'] = 'csrftoken=abc';

        for (const rule of FINGERPRINT_RULES) {
          if (rule.test(headers, probe.status)) {
            detected.push({
              type: rule.authType,
              confidence: rule.confidence,
              evidence: rule.evidence,
            });
          }
        }
      }
    }

    return detected;
  }

  // ─── Header-based tech detection ───────────────────────────────────────────

  private static detectTechFromHeaders(headers: Record<string, string>): string | undefined {
    if (/PHPSESSID/i.test(headers['set-cookie'] ?? '')) return 'PHP';
    if (/csrftoken/i.test(headers['set-cookie'] ?? '')) return 'Django';
    if (headers['server']?.toLowerCase().includes('cloudflare')) return 'Cloudflare';
    if (/Express/i.test(headers['x-powered-by'] ?? '')) return 'Express';
    if (/ASP\.NET/i.test(headers['x-powered-by'] ?? '')) return 'ASP.NET';
    return undefined;
  }

  // ─── Detection Merging ─────────────────────────────────────────────────────

  /** Merge detections from all sources, keeping highest confidence per type */
  private static mergeDetections(
    ...sources: DetectedAuthType[][]
  ): DetectedAuthType[] {
    const byType = new Map<string, DetectedAuthType>();

    for (const detections of sources) {
      for (const d of detections) {
        const existing = byType.get(d.type);
        if (!existing || existing.confidence < d.confidence) {
          byType.set(d.type, { ...d });
        } else {
          // Boost confidence when multiple sources agree
          existing.confidence = Math.min(1, existing.confidence + 0.1);
          existing.evidence += '; ' + d.evidence;
          // Preserve loginUrl/headerName from any source
          if (d.loginUrl && !existing.loginUrl) existing.loginUrl = d.loginUrl;
          if (d.headerName && !existing.headerName) existing.headerName = d.headerName;
        }
      }
    }

    return [...byType.values()].sort((a, b) => b.confidence - a.confidence);
  }

  // ─── Profile Generation ────────────────────────────────────────────────────

  /** Generate suggested auth profiles from detections */
  private static generateSuggestedProfiles(
    detections: DetectedAuthType[],
    probes: TargetProbeResult[],
    programName: string,
  ): SuggestedAuthProfile[] {
    const profiles: SuggestedAuthProfile[] = [];
    const firstValidProbe = probes.find(p => !p.error);
    const baseUrl = firstValidProbe?.url;

    for (const detection of detections) {
      const profile = AuthDetector.buildProfileForType(detection, baseUrl, programName);
      if (profile) {
        profiles.push(profile);
      }
    }

    return profiles;
  }

  /** Build a suggested profile with instructions for a specific auth type */
  private static buildProfileForType(
    detection: DetectedAuthType,
    baseUrl: string | undefined,
    programName: string,
  ): SuggestedAuthProfile | null {
    switch (detection.type) {
      case 'telegram_webapp':
        return {
          label: `${programName} \u2014 Telegram User`,
          authType: 'custom_header',
          url: baseUrl,
          headerName: 'wallet-authorization',
          instructions: [
            '1. Open Telegram Desktop (or web.telegram.org)',
            '2. Open the target bot (e.g., @wallet)',
            '3. Open Browser DevTools (F12) \u2192 Network tab',
            '4. Launch the Mini App inside Telegram',
            '5. Filter Network tab to "Fetch/XHR" requests only',
            '6. Interact with the app (tap anything to trigger API calls)',
            '7. Look for requests to /v2api/ or /api/ paths',
            '8. Copy the auth header (e.g., "wallet-authorization" JWT)',
            '9. Also copy "x-wallet-device-serial" if present',
            '10. Paste values below (token expires in ~10 min \u2014 refresh if hunt runs long)',
          ],
          automationLevel: 'manual',
        };

      case 'bearer':
      case 'oauth':
        return {
          label: `${programName} \u2014 Bearer Token`,
          authType: 'bearer',
          url: baseUrl,
          instructions: [
            '1. Log in to the target application in your browser',
            '2. Open DevTools (F12) \u2192 Network tab',
            '3. Perform any action that triggers an API request',
            '4. Find the request and look for the Authorization header',
            '5. Copy the token value (without the "Bearer " prefix)',
            '6. Paste it below',
          ],
          automationLevel: 'partial',
        };

      case 'cookie':
        return {
          label: `${programName} \u2014 Login Session`,
          authType: 'cookie',
          // Only embed the URL in the profile + instructions when we actually
          // detected a login page. Falling through to `baseUrl` (the first
          // in-scope probe URL) leads users to a dead end when the first
          // in-scope asset is a CDN or API endpoint with no login form --
          // see the 2026-04-23 Superhuman hunt where detection pointed at
          // codacontent.io. When unsure, leave `url` undefined and make the
          // wizard prompt for it explicitly.
          url: detection.loginUrl,
          instructions: detection.loginUrl
            ? [
                `1. Navigate to the login page: ${detection.loginUrl}`,
                '2. Enter your test account credentials below',
                '3. Huntress will perform the login and capture session cookies',
                '4. Use the "Test Auth" button to verify the session works',
              ]
            : [
                '1. Enter the login page URL below -- Huntress could not auto-detect one',
                '2. Enter your test account credentials',
                '3. Huntress will perform the login and capture session cookies',
                '4. Use the "Test Auth" button to verify the session works',
              ],
          automationLevel: 'full',
        };

      case 'api_key':
        return {
          label: `${programName} \u2014 API Key`,
          authType: 'api_key',
          headerName: detection.headerName ?? 'X-API-Key',
          url: baseUrl,
          instructions: [
            '1. Log in to the target\u2019s developer portal or dashboard',
            '2. Navigate to API settings or API keys section',
            '3. Generate a new API key (or copy your existing one)',
            `4. Note the header name (default: ${detection.headerName ?? 'X-API-Key'})`,
            '5. Paste the API key below',
          ],
          automationLevel: 'full',
        };

      case 'basic':
        return {
          label: `${programName} \u2014 Basic Auth`,
          authType: 'custom_header',
          url: baseUrl,
          headerName: 'Authorization',
          instructions: [
            '1. Obtain your username and password for the target',
            '2. The Authorization header will be built automatically',
            '3. Enter your credentials below',
          ],
          automationLevel: 'full',
        };

      default:
        return null;
    }
  }

  // ─── URL Normalization ─────────────────────────────────────────────────────

  /** Normalize a target string to a URL suitable for probing */
  static normalizeTargetUrl(target: string): string {
    const trimmed = target.trim();
    if (/^https?:\/\//i.test(trimmed)) return trimmed;
    if (trimmed.startsWith('*.')) return `https://${trimmed.slice(2)}`;
    return `https://${trimmed}`;
  }
}

export default AuthDetector;
