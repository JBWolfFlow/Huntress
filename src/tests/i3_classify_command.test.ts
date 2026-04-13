/**
 * I3 — classifyCommand (Auto-approval categories)
 *
 * Verifies deterministic classification so unattended hunts aren't blocked
 * at the 60-second approval timeout but mutations still require manual OK.
 */

import { describe, it, expect } from 'vitest';
import { classifyCommand } from '../core/engine/safety_policies';

describe('classifyCommand — passive_recon', () => {
  it('classifies pure DNS/WHOIS tools as passive', () => {
    expect(classifyCommand('whois example.com')).toBe('passive_recon');
    expect(classifyCommand('dig example.com A')).toBe('passive_recon');
    expect(classifyCommand('nslookup example.com')).toBe('passive_recon');
    expect(classifyCommand('host example.com')).toBe('passive_recon');
  });

  it('classifies subdomain enumeration as passive', () => {
    expect(classifyCommand('subfinder -d example.com')).toBe('passive_recon');
    expect(classifyCommand('assetfinder example.com')).toBe('passive_recon');
    expect(classifyCommand('httpx -l targets.txt')).toBe('passive_recon');
    expect(classifyCommand('wafw00f https://example.com')).toBe('passive_recon');
    expect(classifyCommand('whatweb example.com')).toBe('passive_recon');
  });

  it('classifies curl GET without injection payloads as passive', () => {
    expect(classifyCommand('curl https://example.com')).toBe('passive_recon');
    expect(classifyCommand('curl -X GET https://example.com/api/users')).toBe('passive_recon');
    expect(classifyCommand('curl -H "X-Forwarded-For: 1.2.3.4" https://example.com')).toBe('passive_recon');
  });

  it('classifies wget as passive', () => {
    expect(classifyCommand('wget https://example.com/file.txt')).toBe('passive_recon');
  });
});

describe('classifyCommand — injection_passive', () => {
  it('flags SSTI payloads in curl GETs', () => {
    expect(classifyCommand('curl "https://example.com/?q={{7*7}}"')).toBe('injection_passive');
  });

  it('flags SQLi probes in curl GETs', () => {
    expect(classifyCommand("curl \"https://example.com/api?id=1' OR 1=1--\"")).toBe('injection_passive');
    expect(classifyCommand('curl "https://example.com/?id=1 UNION SELECT null,null"')).toBe('injection_passive');
  });

  it('flags XSS payloads in curl GETs', () => {
    expect(classifyCommand('curl "https://example.com/?q=<script>alert(1)</script>"')).toBe('injection_passive');
  });

  it('flags path traversal in curl GETs', () => {
    expect(classifyCommand('curl "https://example.com/file?path=..%2f..%2fetc%2fpasswd"')).toBe('injection_passive');
  });

  it('flags prototype pollution markers in curl GETs', () => {
    expect(classifyCommand('curl "https://example.com/?__proto__[admin]=true"')).toBe('injection_passive');
  });
});

describe('classifyCommand — safe_active_recon', () => {
  it('classifies content discovery tools', () => {
    expect(classifyCommand('gobuster dir -u https://example.com -w wordlist.txt')).toBe('safe_active_recon');
    expect(classifyCommand('ffuf -u https://example.com/FUZZ -w list.txt')).toBe('safe_active_recon');
    expect(classifyCommand('dirb https://example.com')).toBe('safe_active_recon');
    expect(classifyCommand('feroxbuster --url https://example.com')).toBe('safe_active_recon');
  });

  it('classifies nmap without SYN scan', () => {
    expect(classifyCommand('nmap -sV example.com')).toBe('safe_active_recon');
    expect(classifyCommand('nmap -p 80,443 example.com')).toBe('safe_active_recon');
  });

  it('escalates nmap with SYN scan to manual_only', () => {
    expect(classifyCommand('nmap -sS example.com')).toBe('manual_only');
  });

  it('classifies nuclei with default templates', () => {
    expect(classifyCommand('nuclei -u https://example.com')).toBe('safe_active_recon');
  });

  it('escalates nuclei with custom templates to manual_only', () => {
    expect(classifyCommand('nuclei -t ./my-template.yaml -u https://example.com')).toBe('manual_only');
  });
});

describe('classifyCommand — manual_only', () => {
  it('requires manual approval for mutations', () => {
    expect(classifyCommand('curl -X POST https://example.com/api/users -d "{}"')).toBe('manual_only');
    expect(classifyCommand('curl -X PUT https://example.com/api/users/1')).toBe('manual_only');
    expect(classifyCommand('curl -X DELETE https://example.com/api/users/1')).toBe('manual_only');
    expect(classifyCommand('curl --request PATCH https://example.com/api/users/1')).toBe('manual_only');
  });

  it('requires manual approval for exploit tools', () => {
    expect(classifyCommand('sqlmap -u https://example.com/?id=1')).toBe('manual_only');
    expect(classifyCommand('hydra -l admin -P list.txt example.com')).toBe('manual_only');
    expect(classifyCommand('nikto -h https://example.com')).toBe('manual_only');
  });

  it('requires manual approval for unknown tools', () => {
    expect(classifyCommand('some-random-tool --do-stuff')).toBe('manual_only');
    expect(classifyCommand('bash custom_exploit.sh')).toBe('manual_only');
  });

  it('requires manual approval for empty/blank commands', () => {
    expect(classifyCommand('')).toBe('manual_only');
    expect(classifyCommand('   ')).toBe('manual_only');
  });
});
