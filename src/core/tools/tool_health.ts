/**
 * Tool Health Checker — Verifies availability of external security tools
 *
 * Checks whether required security binaries (nuclei, subfinder, etc.) are
 * installed and reachable on the system PATH. Uses Tauri IPC when running
 * inside the desktop app, falls back to Node.js child_process in test/dev.
 */

import { executeCommand } from '../tauri_bridge';

// ─── Types ──────────────────────────────────────────────────────────────────

export interface SecurityTool {
  name: string;
  binary: string;
  checkCommand: string;
  installCommand: string;
  installMethod: string;
  category: string;
  description: string;
}

type ToolCategory = 'recon' | 'scanning' | 'fuzzing' | 'exploitation' | 'utility';

// ─── Tool Registry ──────────────────────────────────────────────────────────

export const SECURITY_TOOLS: SecurityTool[] = [
  {
    name: 'Nuclei',
    binary: 'nuclei',
    checkCommand: 'which nuclei',
    installCommand: 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
    installMethod: 'go install',
    category: 'scanning' satisfies ToolCategory,
    description: 'Template-based vulnerability scanner with community-driven templates',
  },
  {
    name: 'Subfinder',
    binary: 'subfinder',
    checkCommand: 'which subfinder',
    installCommand: 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
    installMethod: 'go install',
    category: 'recon' satisfies ToolCategory,
    description: 'Passive subdomain discovery using multiple sources',
  },
  {
    name: 'httpx',
    binary: 'httpx',
    checkCommand: 'which httpx',
    installCommand: 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
    installMethod: 'go install',
    category: 'recon' satisfies ToolCategory,
    description: 'HTTP probing and technology fingerprinting',
  },
  {
    name: 'Dalfox',
    binary: 'dalfox',
    checkCommand: 'which dalfox',
    installCommand: 'go install github.com/hahwul/dalfox/v2@latest',
    installMethod: 'go install',
    category: 'exploitation' satisfies ToolCategory,
    description: 'XSS parameter analysis and scanning',
  },
  {
    name: 'Katana',
    binary: 'katana',
    checkCommand: 'which katana',
    installCommand: 'go install github.com/projectdiscovery/katana/cmd/katana@latest',
    installMethod: 'go install',
    category: 'recon' satisfies ToolCategory,
    description: 'Web crawling and spidering framework',
  },
  {
    name: 'ffuf',
    binary: 'ffuf',
    checkCommand: 'which ffuf',
    installCommand: 'go install github.com/ffuf/ffuf/v2@latest',
    installMethod: 'go install',
    category: 'fuzzing' satisfies ToolCategory,
    description: 'Fast web fuzzer for directory and parameter discovery',
  },
  {
    name: 'Nmap',
    binary: 'nmap',
    checkCommand: 'which nmap',
    installCommand: 'sudo apt install -y nmap',
    installMethod: 'apt',
    category: 'scanning' satisfies ToolCategory,
    description: 'Network port scanner and service detection',
  },
  {
    name: 'gau',
    binary: 'gau',
    checkCommand: 'which gau',
    installCommand: 'go install github.com/lc/gau/v2/cmd/gau@latest',
    installMethod: 'go install',
    category: 'recon' satisfies ToolCategory,
    description: 'Fetch known URLs from AlienVault, Wayback Machine, and Common Crawl',
  },
  {
    name: 'waybackurls',
    binary: 'waybackurls',
    checkCommand: 'which waybackurls',
    installCommand: 'go install github.com/tomnomnom/waybackurls@latest',
    installMethod: 'go install',
    category: 'recon' satisfies ToolCategory,
    description: 'Fetch URLs from the Wayback Machine for a given domain',
  },
  {
    name: 'Arjun',
    binary: 'arjun',
    checkCommand: 'which arjun',
    installCommand: 'pip3 install arjun',
    installMethod: 'pip',
    category: 'fuzzing' satisfies ToolCategory,
    description: 'HTTP parameter discovery suite',
  },
  {
    name: 'kxss',
    binary: 'kxss',
    checkCommand: 'which kxss',
    installCommand: 'go install github.com/Emoe/kxss@latest',
    installMethod: 'go install',
    category: 'exploitation' satisfies ToolCategory,
    description: 'Reflected parameter detection for XSS',
  },
  {
    name: 'interactsh-client',
    binary: 'interactsh-client',
    checkCommand: 'which interactsh-client',
    installCommand: 'go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest',
    installMethod: 'go install',
    category: 'utility' satisfies ToolCategory,
    description: 'Out-of-band interaction gathering for blind vulnerability detection',
  },
  {
    name: 'sqlmap',
    binary: 'sqlmap',
    checkCommand: 'which sqlmap',
    installCommand: 'sudo apt install -y sqlmap',
    installMethod: 'apt',
    category: 'exploitation' satisfies ToolCategory,
    description: 'Automatic SQL injection detection and exploitation',
  },
  {
    name: 'Naabu',
    binary: 'naabu',
    checkCommand: 'which naabu',
    installCommand: 'go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest',
    installMethod: 'go install',
    category: 'scanning' satisfies ToolCategory,
    description: 'Fast port scanner with SYN/CONNECT scan support',
  },
  {
    name: 'dnsx',
    binary: 'dnsx',
    checkCommand: 'which dnsx',
    installCommand: 'go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest',
    installMethod: 'go install',
    category: 'recon' satisfies ToolCategory,
    description: 'Fast DNS toolkit for resolution, wildcard filtering, and brute-forcing',
  },
  {
    name: 'GoSpider',
    binary: 'gospider',
    checkCommand: 'which gospider',
    installCommand: 'go install github.com/jaeles-project/gospider@latest',
    installMethod: 'go install',
    category: 'recon' satisfies ToolCategory,
    description: 'Fast web spider for link and endpoint discovery',
  },
  {
    name: 'Feroxbuster',
    binary: 'feroxbuster',
    checkCommand: 'which feroxbuster',
    installCommand: 'sudo apt install -y feroxbuster',
    installMethod: 'apt',
    category: 'fuzzing' satisfies ToolCategory,
    description: 'Recursive content discovery via forced browsing',
  },
  {
    name: 'WhatWeb',
    binary: 'whatweb',
    checkCommand: 'which whatweb',
    installCommand: 'sudo apt install -y whatweb',
    installMethod: 'apt',
    category: 'recon' satisfies ToolCategory,
    description: 'Web technology fingerprinting and identification',
  },
  {
    name: 'wafw00f',
    binary: 'wafw00f',
    checkCommand: 'which wafw00f',
    installCommand: 'pip3 install wafw00f',
    installMethod: 'pip',
    category: 'recon' satisfies ToolCategory,
    description: 'Web Application Firewall detection and fingerprinting',
  },
  {
    name: 'testssl.sh',
    binary: 'testssl',
    checkCommand: 'which testssl',
    installCommand: 'sudo apt install -y testssl.sh',
    installMethod: 'apt',
    category: 'utility' satisfies ToolCategory,
    description: 'TLS/SSL cipher and vulnerability testing',
  },
];

// ─── Health Check ───────────────────────────────────────────────────────────

/**
 * Check availability of all registered security tools.
 *
 * For each tool, runs `which <binary>` via Tauri IPC (or Node.js fallback).
 * Returns a Map where keys are tool names and values indicate whether the
 * binary was found on the system PATH.
 */
export async function checkToolHealth(): Promise<Map<string, boolean>> {
  const results = new Map<string, boolean>();

  const checks = SECURITY_TOOLS.map(async (tool) => {
    try {
      const result = await executeCommand('which', [tool.binary]);
      results.set(tool.name, result.success && result.exitCode === 0);
    } catch {
      // Command execution failed entirely — tool is not available
      results.set(tool.name, false);
    }
  });

  await Promise.all(checks);
  return results;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Return the names of all tools that are currently available on the system.
 */
export function getAvailableToolsSummary(availability: Map<string, boolean>): string[] {
  const available: string[] = [];
  for (const [name, isAvailable] of availability) {
    if (isAvailable) {
      available.push(name);
    }
  }
  return available;
}

/**
 * Return the install command for a specific tool by name.
 * Returns an empty string if the tool is not found in the registry.
 */
export function getInstallInstructions(toolName: string): string {
  const tool = SECURITY_TOOLS.find(
    (t) => t.name.toLowerCase() === toolName.toLowerCase()
      || t.binary.toLowerCase() === toolName.toLowerCase(),
  );
  return tool?.installCommand ?? '';
}
