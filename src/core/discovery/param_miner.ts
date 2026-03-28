/**
 * Parameter Miner (Phase 20B)
 *
 * Discovers hidden parameters by brute-forcing common names against
 * an endpoint and checking for behavioral changes in the response.
 */

import type { HttpClient } from '../http/request_engine';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ParamMineResult {
  reflectedParams: Array<{ name: string; location: 'query' | 'header' | 'body' }>;
  behaviorChangingParams: Array<{ name: string; responseChange: 'status' | 'length' | 'content' }>;
}

// ─── Common Parameter Wordlist ──────────────────────────────────────────────

export const COMMON_PARAMS: string[] = [
  'id', 'user_id', 'uid', 'account', 'username', 'email', 'password', 'token', 'auth', 'session',
  'admin', 'debug', 'test', 'dev', 'page', 'limit', 'offset', 'sort', 'order', 'filter', 'search', 'q',
  'callback', 'redirect', 'redirect_uri', 'return_url', 'next', 'url', 'file', 'path', 'filename',
  'template', 'view', 'action', 'cmd', 'command', 'exec', 'query', 'format', 'type', 'category',
  'role', 'permission', 'access', 'level', 'status', 'state', 'mode', 'lang', 'locale', 'ref',
  'source', 'target', 'destination', 'from', 'to', 'key', 'secret', 'api_key', 'access_token',
  'client_id', 'client_secret', 'grant_type', 'scope', 'response_type', 'code', 'nonce',
  'include', 'exclude', 'fields', 'expand', 'embed', 'select', 'columns', 'where', 'having',
  'group', 'group_by', 'order_by', 'sort_by', 'direction', 'asc', 'desc', 'count', 'max', 'min',
  'start', 'end', 'begin', 'size', 'per_page', 'page_size', 'cursor', 'after', 'before',
  'name', 'title', 'description', 'content', 'body', 'message', 'comment', 'text', 'data',
  'value', 'param', 'input', 'output', 'result', 'response', 'request', 'payload',
  'config', 'setting', 'option', 'preference', 'feature', 'flag', 'enabled', 'disabled',
  'version', 'v', 'api', 'endpoint', 'method', 'operation', 'handler',
  'user', 'account_id', 'org', 'organization', 'team', 'project', 'workspace',
  'file_id', 'upload', 'download', 'attachment', 'media', 'image', 'document',
  'price', 'amount', 'quantity', 'total', 'discount', 'coupon', 'promo',
  'domain', 'host', 'origin', 'referer', 'referrer', 'site', 'channel',
  'timestamp', 'date', 'time', 'created', 'updated', 'modified', 'expires',
  'hash', 'checksum', 'signature', 'hmac', 'digest', 'verify',
  'xml', 'json', 'csv', 'html', 'plain', 'raw', 'encoded', 'base64',
  'proxy', 'forward', 'x-forwarded-for', 'x-forwarded-host', 'x-real-ip',
  'webhook', 'notify', 'notification', 'subscribe', 'unsubscribe',
  'internal', 'external', 'private', 'public', 'hidden', 'visible', 'active', 'inactive',
];

// ─── ParamMiner ─────────────────────────────────────────────────────────────

export class ParamMiner {
  private httpClient: HttpClient;

  constructor(httpClient: HttpClient) {
    this.httpClient = httpClient;
  }

  async mine(url: string, method: string, wordlist?: string[]): Promise<ParamMineResult> {
    const params = wordlist ?? COMMON_PARAMS;
    const reflectedParams: ParamMineResult['reflectedParams'] = [];
    const behaviorChangingParams: ParamMineResult['behaviorChangingParams'] = [];

    // Get baseline response
    const baseline = await this.httpClient.request({
      url,
      method: method as 'GET' | 'POST',
      timeoutMs: 10000,
    });

    const baselineLength = baseline.body.length;
    const canaryValue = 'hntrs_' + Math.random().toString(36).substring(2, 10);

    // Test parameters in batches of 10 for speed
    const batchSize = 10;
    for (let i = 0; i < params.length; i += batchSize) {
      const batch = params.slice(i, i + batchSize);

      for (const paramName of batch) {
        try {
          const testUrl = new URL(url);
          testUrl.searchParams.set(paramName, canaryValue);

          const response = await this.httpClient.request({
            url: testUrl.toString(),
            method: method as 'GET' | 'POST',
            timeoutMs: 10000,
          });

          // Check if canary is reflected in response
          if (response.body.includes(canaryValue)) {
            reflectedParams.push({ name: paramName, location: 'query' });
          }

          // Check for behavioral changes
          if (response.status !== baseline.status) {
            behaviorChangingParams.push({ name: paramName, responseChange: 'status' });
          } else if (Math.abs(response.body.length - baselineLength) > 50) {
            behaviorChangingParams.push({ name: paramName, responseChange: 'length' });
          }
        } catch {
          // Skip failed requests
        }
      }
    }

    return { reflectedParams, behaviorChangingParams };
  }
}

export default ParamMiner;
