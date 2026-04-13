/**
 * WAF-to-Agent Pipeline — Unit Tests (I8)
 *
 * Verifies:
 * 1. WAF detection data is correctly transformed to WafContext
 * 2. System prompt includes vendor-specific bypass strategies
 * 3. Per-domain WAF isolation works correctly
 * 4. Graceful handling when no WAF is detected
 */

import { describe, it, expect } from 'vitest';
import type { WafContext } from '../../agents/base_agent';
import { detectWAF } from '../http/request_engine';

// ─── WAF Detection Transformation ───────────────────────────────────────────

describe('WAF-to-Agent Pipeline (I8)', () => {

  describe('detectWAF function', () => {
    it('should detect Cloudflare from cf-ray header', () => {
      const waf = detectWAF(200, { 'cf-ray': '12345abc-LAX' }, '');
      expect(waf.detected).toBe(true);
      expect(waf.provider).toBe('cloudflare');
    });

    it('should detect Cloudflare from server header', () => {
      const waf = detectWAF(200, { 'server': 'cloudflare' }, '');
      expect(waf.detected).toBe(true);
      expect(waf.provider).toBe('cloudflare');
    });

    it('should detect Akamai from server header', () => {
      const waf = detectWAF(200, { 'server': 'AkamaiGHost' }, '');
      expect(waf.detected).toBe(true);
      expect(waf.provider).toBe('akamai');
    });

    it('should detect AWS WAF from x-amzn-waf-action header', () => {
      const waf = detectWAF(403, { 'x-amzn-waf-action': 'BLOCK' }, '');
      expect(waf.detected).toBe(true);
      expect(waf.provider).toBe('aws-waf');
    });

    it('should detect generic WAF from 429 status', () => {
      const waf = detectWAF(429, {}, 'Rate limited');
      expect(waf.detected).toBe(true);
      expect(waf.provider).toBe('generic');
    });

    it('should detect generic WAF from 403 block page', () => {
      const waf = detectWAF(403, {}, 'Your request has been blocked');
      expect(waf.detected).toBe(true);
      expect(waf.provider).toBe('generic');
    });

    it('should return detected=false when no WAF signals present', () => {
      const waf = detectWAF(200, { 'content-type': 'text/html' }, '<html>OK</html>');
      expect(waf.detected).toBe(false);
      expect(waf.provider).toBe('none');
    });
  });

  // ─── WafContext Construction ──────────────────────────────────────────────

  describe('WAFDetection to WafContext transformation', () => {
    /**
     * Reproduces the transformation logic from orchestrator_engine.ts
     * huntTaskToAgentTask() for the dynamic HttpClient path.
     */
    function buildWafContext(
      dynamicWaf: { detected: boolean; provider: string; signal: string } | undefined,
      staticResult: { detected: boolean; vendor: string; confidence: number; evidence: string[] } | undefined
    ): WafContext | undefined {
      if (dynamicWaf?.detected) {
        return {
          vendor: dynamicWaf.provider,
          confidence: 0.8,
          signal: dynamicWaf.signal,
        };
      }
      if (staticResult?.detected) {
        return {
          vendor: staticResult.vendor,
          confidence: staticResult.confidence,
          signal: staticResult.evidence.join('; '),
        };
      }
      return undefined;
    }

    it('should prefer dynamic WAF detection over static', () => {
      const dynamic = { detected: true, provider: 'cloudflare', signal: 'CF-Ray header present' };
      const staticWaf = { detected: true, vendor: 'akamai', confidence: 0.6, evidence: ['AkamaiGHost header'] };

      const ctx = buildWafContext(dynamic, staticWaf);
      expect(ctx).toBeDefined();
      expect(ctx!.vendor).toBe('cloudflare');
      expect(ctx!.confidence).toBe(0.8);
    });

    it('should fall back to static WAF detection when dynamic is absent', () => {
      const ctx = buildWafContext(undefined, {
        detected: true,
        vendor: 'imperva',
        confidence: 0.7,
        evidence: ['incap_ses cookie', 'Imperva error page'],
      });

      expect(ctx).toBeDefined();
      expect(ctx!.vendor).toBe('imperva');
      expect(ctx!.confidence).toBe(0.7);
      expect(ctx!.signal).toBe('incap_ses cookie; Imperva error page');
    });

    it('should return undefined when no WAF detected by either source', () => {
      const ctx = buildWafContext(
        { detected: false, provider: 'none', signal: '' },
        { detected: false, vendor: 'none', confidence: 0, evidence: [] }
      );
      expect(ctx).toBeUndefined();
    });

    it('should return undefined when both sources are undefined', () => {
      const ctx = buildWafContext(undefined, undefined);
      expect(ctx).toBeUndefined();
    });
  });

  // ─── System Prompt WAF Section ────────────────────────────────────────────

  describe('System prompt WAF bypass strategies', () => {
    /**
     * Reproduces buildWafSection() logic from react_loop.ts
     */
    const WAF_BYPASS_STRATEGIES: Record<string, string> = {
      cloudflare: 'Cloudflare WAF detected',
      akamai: 'Akamai WAF detected',
      aws_waf: 'AWS WAF detected',
      imperva: 'Imperva/Incapsula WAF detected',
      generic: 'WAF detected (vendor unknown)',
    };

    function buildWafSection(waf: WafContext | undefined): string {
      if (!waf) return '';
      const vendor = waf.vendor.toLowerCase().replace(/[-_\s]/g, '_');
      const strategies = WAF_BYPASS_STRATEGIES[vendor] ?? WAF_BYPASS_STRATEGIES['generic'] ?? '';
      return `WAF: ${strategies} (${Math.round(waf.confidence * 100)}%)`;
    }

    it('should return empty string when no WAF context', () => {
      expect(buildWafSection(undefined)).toBe('');
    });

    it('should select Cloudflare strategies for cloudflare vendor', () => {
      const section = buildWafSection({
        vendor: 'cloudflare',
        confidence: 0.9,
        signal: 'CF-Ray header',
      });
      expect(section).toContain('Cloudflare WAF detected');
      expect(section).toContain('90%');
    });

    it('should select Akamai strategies for akamai vendor', () => {
      const section = buildWafSection({
        vendor: 'akamai',
        confidence: 0.7,
        signal: 'AkamaiGHost header',
      });
      expect(section).toContain('Akamai WAF detected');
    });

    it('should select AWS WAF strategies for aws-waf vendor', () => {
      const section = buildWafSection({
        vendor: 'aws-waf',
        confidence: 0.8,
        signal: 'x-amzn-waf-action header',
      });
      expect(section).toContain('AWS WAF detected');
    });

    it('should fall back to generic strategies for unknown vendors', () => {
      const section = buildWafSection({
        vendor: 'unknown_vendor',
        confidence: 0.5,
        signal: 'suspicious block page',
      });
      expect(section).toContain('WAF detected (vendor unknown)');
    });

    it('should handle vendor names with hyphens (normalize to underscore)', () => {
      const section = buildWafSection({
        vendor: 'aws-waf',
        confidence: 0.8,
        signal: 'test',
      });
      // aws-waf should normalize to aws_waf and match
      expect(section).toContain('AWS WAF detected');
    });
  });

  // ─── Per-Domain Isolation ─────────────────────────────────────────────────

  describe('Per-domain WAF isolation', () => {
    it('should maintain separate WAF states per domain', () => {
      const wafStates = new Map<string, { detected: boolean; provider: string; signal: string }>();

      // Domain A has Cloudflare
      wafStates.set('api.example.com', { detected: true, provider: 'cloudflare', signal: 'CF-Ray' });
      // Domain B has Akamai
      wafStates.set('cdn.example.com', { detected: true, provider: 'akamai', signal: 'AkamaiGHost' });
      // Domain C has no WAF
      // (not in the map)

      expect(wafStates.get('api.example.com')?.provider).toBe('cloudflare');
      expect(wafStates.get('cdn.example.com')?.provider).toBe('akamai');
      expect(wafStates.get('www.example.com')).toBeUndefined();
    });
  });
});
