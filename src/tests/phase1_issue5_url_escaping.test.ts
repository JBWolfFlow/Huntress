/**
 * Issue #5 — URL escaping bug in extractTargetFromCommand
 *
 * During Hunt #11 monitoring we observed this scope-validator WARN:
 *   "Target wallettg.com" did not match any in-scope pattern"
 * — note the trailing literal quote. The agent ran `curl "https://wallettg.com"`
 * and the regex `/https?:\/\/([^\/\s:]+)/` captured `wallettg.com"` because
 * quote characters weren't excluded from the hostname class.
 *
 * These tests pin the fix: stray quote / bracket / trailing punctuation
 * must not end up in the extracted target.
 */

import { describe, it, expect } from 'vitest';
import { extractTargetFromCommand } from '../core/engine/react_loop';

describe('extractTargetFromCommand — URL char-class excludes quotes (Issue #5)', () => {
  it('extracts host from double-quoted URL (the Hunt #11 regression)', () => {
    expect(extractTargetFromCommand('curl -s "https://wallettg.com"'))
      .toBe('wallettg.com');
    expect(extractTargetFromCommand('curl -s "https://pay.wallet.tg"'))
      .toBe('pay.wallet.tg');
  });

  it('extracts host from single-quoted URL', () => {
    expect(extractTargetFromCommand("curl -s 'https://target.com/path'"))
      .toBe('target.com');
  });

  it('extracts host from URL with path + query (no quotes)', () => {
    expect(extractTargetFromCommand('curl https://target.com/api/v1?id=1'))
      .toBe('target.com');
  });

  it('extracts host from URL embedded in parentheses (e.g. shell substitution logs)', () => {
    expect(extractTargetFromCommand('echo $(curl -s (https://target.com))'))
      .toBe('target.com');
  });

  it('handles -u flag with quoted URL (nuclei/sqlmap/ffuf pattern)', () => {
    expect(extractTargetFromCommand('nuclei -u "https://target.com" -t cves/'))
      .toBe('target.com');
  });

  it('strips trailing punctuation (period, comma, semicolon)', () => {
    expect(extractTargetFromCommand('curl https://target.com.'))
      .toBe('target.com');
    expect(extractTargetFromCommand('visit https://target.com; then ...'))
      .toBe('target.com');
  });

  it('falls back to explicit target field when command has no URL', () => {
    expect(extractTargetFromCommand('subfinder -d target.com', 'target.com'))
      .toBe('target.com');
  });

  it('sanitizes the fallback target too (strips protocol + port)', () => {
    expect(extractTargetFromCommand('subfinder -d TARGET', 'https://target.com:8080'))
      .toBe('target.com');
  });

  it('returns null when nothing is extractable', () => {
    expect(extractTargetFromCommand('ls -la')).toBeNull();
    expect(extractTargetFromCommand('ls -la', 'N/A')).toBeNull();
    expect(extractTargetFromCommand('ls -la', '   ')).toBeNull();
  });

  it('extracts IP address without surrounding punctuation', () => {
    expect(extractTargetFromCommand('nmap -sV 10.0.0.1 -p 80'))
      .toBe('10.0.0.1');
    expect(extractTargetFromCommand('ping "10.0.0.1"'))
      .toBe('10.0.0.1');
  });
});
