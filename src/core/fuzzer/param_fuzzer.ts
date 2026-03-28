/**
 * Parameter Fuzzer (Phase 20D)
 *
 * Systematic parameter testing engine. Takes an endpoint + parameter,
 * applies vuln-specific payloads from PayloadDatabase, sends via HttpClient,
 * and analyzes responses for confirmed hits.
 *
 * This is the core speed advantage over LLM-per-request: a single fuzz()
 * call tests 50+ payloads in seconds with zero LLM inference cost.
 */

import type { HttpClient, HttpRequestOptions, HttpResponse } from '../http/request_engine';
import type { AuthenticatedSession } from '../auth/session_manager';
import { getPayloads } from './payload_db';
import type { VulnType, Payload } from './payload_db';
import { ResponseAnalyzer } from './response_analyzer';
import type { AnalysisResult } from './response_analyzer';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface FuzzConfig {
  url: string;
  method: string;
  parameterName: string;
  parameterLocation: 'query' | 'body' | 'header' | 'cookie' | 'path';
  vulnType: VulnType;
  contentType?: 'form' | 'json' | 'xml' | 'multipart';
  maxPayloads?: number;
  httpClient: HttpClient;
  authContext?: AuthenticatedSession;
}

export interface FuzzResult {
  hits: AnalysisResult[];
  totalPayloadsTested: number;
  totalRequestsMade: number;
  durationMs: number;
  errors: string[];
}

// ─── Parameter Fuzzer ───────────────────────────────────────────────────────

export class ParamFuzzer {
  private analyzer: ResponseAnalyzer;

  constructor() {
    this.analyzer = new ResponseAnalyzer();
  }

  async fuzz(config: FuzzConfig): Promise<FuzzResult> {
    const startTime = Date.now();
    const hits: AnalysisResult[] = [];
    const errors: string[] = [];
    let totalPayloadsTested = 0;
    let totalRequestsMade = 0;

    const payloads = getPayloads(config.vulnType);
    const maxPayloads = config.maxPayloads ?? 50;
    const payloadsToTest = payloads.slice(0, maxPayloads);

    // Step 1: Get baseline response
    let baseline: HttpResponse;
    try {
      baseline = await this.sendRequest(config, 'baseline_safe_value');
      totalRequestsMade++;
    } catch (error) {
      errors.push(`Baseline request failed: ${error instanceof Error ? error.message : String(error)}`);
      return { hits, totalPayloadsTested: 0, totalRequestsMade: 0, durationMs: Date.now() - startTime, errors };
    }

    // Step 2: Test each payload
    for (const payload of payloadsToTest) {
      totalPayloadsTested++;

      // Test raw payload
      try {
        const response = await this.sendRequest(config, payload.raw);
        totalRequestsMade++;

        const analysis = this.analyzer.analyze(config.vulnType, baseline, response, payload);

        if (analysis.confidence > 0.7) {
          hits.push(analysis);
          // Early termination on high-confidence hit
          if (analysis.confidence > 0.9) break;
        }
      } catch (error) {
        errors.push(`Payload error (${payload.description}): ${error instanceof Error ? error.message : String(error)}`);
      }

      // Test WAF bypass variants if the raw payload didn't hit
      if (hits.length === 0 && payload.wafBypass.length > 0) {
        for (const bypassPayload of payload.wafBypass) {
          try {
            const response = await this.sendRequest(config, bypassPayload);
            totalRequestsMade++;

            const bypassAnalysisPayload: Payload = { ...payload, raw: bypassPayload };
            const analysis = this.analyzer.analyze(config.vulnType, baseline, response, bypassAnalysisPayload);

            if (analysis.confidence > 0.7) {
              analysis.evidence += ' (WAF bypass variant)';
              hits.push(analysis);
              if (analysis.confidence > 0.9) break;
            }
          } catch {
            // Skip failed bypass attempts
          }
        }
      }

      // Early termination after confirmed high-confidence hit
      if (hits.some(h => h.confidence > 0.9)) break;
    }

    return {
      hits,
      totalPayloadsTested,
      totalRequestsMade,
      durationMs: Date.now() - startTime,
      errors,
    };
  }

  private async sendRequest(config: FuzzConfig, payloadValue: string): Promise<HttpResponse> {
    const options = this.buildRequest(config, payloadValue);
    return config.httpClient.request(options);
  }

  private buildRequest(config: FuzzConfig, payloadValue: string): HttpRequestOptions {
    const method = config.method.toUpperCase() as HttpRequestOptions['method'];
    const headers: Record<string, string> = {};

    // Apply auth context
    if (config.authContext) {
      Object.assign(headers, config.authContext.headers);
      if (config.authContext.cookies.length > 0) {
        headers['Cookie'] = config.authContext.cookies.map(c => `${c.name}=${c.value}`).join('; ');
      }
      if (config.authContext.csrfToken) {
        headers['X-CSRF-Token'] = config.authContext.csrfToken;
      }
    }

    switch (config.parameterLocation) {
      case 'query': {
        const url = new URL(config.url);
        url.searchParams.set(config.parameterName, payloadValue);
        return { url: url.toString(), method, headers };
      }

      case 'body': {
        const contentType = config.contentType ?? 'form';
        let body: string;

        if (contentType === 'json') {
          headers['Content-Type'] = 'application/json';
          body = JSON.stringify({ [config.parameterName]: payloadValue });
        } else if (contentType === 'xml') {
          headers['Content-Type'] = 'application/xml';
          body = `<root><${config.parameterName}>${payloadValue}</${config.parameterName}></root>`;
        } else {
          headers['Content-Type'] = 'application/x-www-form-urlencoded';
          const params = new URLSearchParams();
          params.set(config.parameterName, payloadValue);
          body = params.toString();
        }

        return { url: config.url, method, headers, body };
      }

      case 'header': {
        headers[config.parameterName] = payloadValue;
        return { url: config.url, method, headers };
      }

      case 'cookie': {
        const existing = headers['Cookie'] ?? '';
        headers['Cookie'] = existing
          ? `${existing}; ${config.parameterName}=${payloadValue}`
          : `${config.parameterName}=${payloadValue}`;
        return { url: config.url, method, headers };
      }

      case 'path': {
        const url = config.url.replace(`{${config.parameterName}}`, encodeURIComponent(payloadValue));
        return { url, method, headers };
      }

      default:
        return { url: config.url, method, headers };
    }
  }
}

export default ParamFuzzer;
