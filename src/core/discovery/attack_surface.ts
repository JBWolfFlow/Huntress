/**
 * Attack Surface Map Builder (Phase 20B)
 *
 * Combines crawl results + JS analysis into a unified attack surface
 * and auto-generates suggested agent tasks ranked by priority.
 */

import type { CrawlResult, DiscoveredEndpoint, DiscoveredForm } from './crawler';
import type { JSAnalysisResult } from './js_analyzer';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AttackSurface {
  endpoints: DiscoveredEndpoint[];
  forms: DiscoveredForm[];
  technologies: string[];
  secrets: JSAnalysisResult['secrets'];
  suggestedTasks: SuggestedTask[];
}

export interface SuggestedTask {
  agentType: string;
  target: string;
  description: string;
  priority: number;
  parameters: Record<string, unknown>;
}

// ─── Task Generation ────────────────────────────────────────────────────────

function generateTasks(
  endpoints: DiscoveredEndpoint[],
  forms: DiscoveredForm[],
  secrets: JSAnalysisResult['secrets'],
  technologies: string[],
): SuggestedTask[] {
  const tasks: SuggestedTask[] = [];

  // Secrets found → immediate high-severity findings
  for (const secret of secrets) {
    tasks.push({
      agentType: 'recon',
      target: secret.file,
      description: `Validate exposed ${secret.type} found in ${secret.file}`,
      priority: 10,
      parameters: { secretType: secret.type, secretValue: secret.value },
    });
  }

  for (const form of forms) {
    const hasTextInputs = form.inputs.some(i =>
      ['text', 'search', 'email', 'url', 'password', 'textarea', 'hidden'].includes(i.type)
    );

    if (hasTextInputs) {
      // Forms with text inputs → XSS + SQLi
      tasks.push({
        agentType: 'xss_hunter',
        target: form.action,
        description: `Test XSS in form at ${form.pageUrl} (params: ${form.inputs.map(i => i.name).join(', ')})`,
        priority: 7,
        parameters: { formAction: form.action, formMethod: form.method, inputs: form.inputs },
      });

      tasks.push({
        agentType: 'sqli_hunter',
        target: form.action,
        description: `Test SQLi in form at ${form.pageUrl}`,
        priority: 7,
        parameters: { formAction: form.action, formMethod: form.method, inputs: form.inputs },
      });
    }
  }

  for (const ep of endpoints) {
    const urlLower = ep.url.toLowerCase();
    const paramNames = ep.parameters.map(p => p.toLowerCase());

    // ID parameters → IDOR
    if (paramNames.some(p => /^(id|user_?id|uid|account_?id|org_?id)$/.test(p))) {
      tasks.push({
        agentType: 'idor_hunter',
        target: ep.url,
        description: `Test IDOR on ${ep.url} with ID params: ${ep.parameters.join(', ')}`,
        priority: 8,
        parameters: { endpoint: ep.url, method: ep.method, idParams: ep.parameters.filter(p => /id/i.test(p)) },
      });
    }

    // Redirect/callback parameters → Open Redirect + SSRF
    if (paramNames.some(p => /^(redirect|redirect_uri|return_?url|next|url|callback|continue|goto|dest|destination|forward|rurl)$/.test(p))) {
      tasks.push({
        agentType: 'ssrf_hunter',
        target: ep.url,
        description: `Test SSRF via redirect param on ${ep.url}`,
        priority: 8,
        parameters: { endpoint: ep.url, redirectParams: ep.parameters.filter(p => /redirect|url|callback|next|dest|forward/i.test(p)) },
      });

      tasks.push({
        agentType: 'open_redirect',
        target: ep.url,
        description: `Test open redirect on ${ep.url}`,
        priority: 6,
        parameters: { endpoint: ep.url },
      });
    }

    // File/path parameters → Path Traversal
    if (paramNames.some(p => /^(file|filename|path|filepath|document|template|page|include|dir|folder)$/.test(p))) {
      tasks.push({
        agentType: 'path_traversal_hunter',
        target: ep.url,
        description: `Test path traversal on ${ep.url}`,
        priority: 8,
        parameters: { endpoint: ep.url, fileParams: ep.parameters.filter(p => /file|path|template|include|dir/i.test(p)) },
      });
    }

    // Command/exec parameters → Command Injection
    if (paramNames.some(p => /^(cmd|command|exec|run|ping|host|ip|domain)$/.test(p))) {
      tasks.push({
        agentType: 'command_injection_hunter',
        target: ep.url,
        description: `Test command injection on ${ep.url}`,
        priority: 9,
        parameters: { endpoint: ep.url },
      });
    }

    // XML content type → XXE
    if (ep.contentType?.includes('xml')) {
      tasks.push({
        agentType: 'xxe_hunter',
        target: ep.url,
        description: `Test XXE on XML endpoint ${ep.url}`,
        priority: 8,
        parameters: { endpoint: ep.url },
      });
    }

    // Template/name parameters → SSTI
    if (paramNames.some(p => /^(template|name|message|greeting|title|subject|preview)$/.test(p))) {
      tasks.push({
        agentType: 'ssti_hunter',
        target: ep.url,
        description: `Test SSTI on ${ep.url}`,
        priority: 7,
        parameters: { endpoint: ep.url },
      });
    }

    // Admin/debug/internal endpoints → all hunters (high priority)
    if (/admin|debug|internal|config|test|staging|dev|manage|dashboard|console/i.test(urlLower)) {
      tasks.push({
        agentType: 'recon',
        target: ep.url,
        description: `Deep recon on sensitive endpoint: ${ep.url}`,
        priority: 9,
        parameters: { endpoint: ep.url, sensitive: true },
      });
    }

    // GraphQL endpoints
    if (/graphql/i.test(urlLower)) {
      tasks.push({
        agentType: 'graphql_hunter',
        target: ep.url,
        description: `Test GraphQL endpoint at ${ep.url}`,
        priority: 8,
        parameters: { endpoint: ep.url },
      });
    }

    // OAuth endpoints
    if (/oauth|authorize|token|callback/i.test(urlLower)) {
      tasks.push({
        agentType: 'oauth_hunter',
        target: ep.url,
        description: `Test OAuth flow at ${ep.url}`,
        priority: 7,
        parameters: { endpoint: ep.url },
      });
    }
  }

  // Sort by priority descending
  tasks.sort((a, b) => b.priority - a.priority);

  // Deduplicate by agentType + target
  const seen = new Set<string>();
  return tasks.filter(t => {
    const key = `${t.agentType}:${t.target}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ─── Builder ────────────────────────────────────────────────────────────────

export function buildAttackSurface(
  crawlResult: CrawlResult,
  jsAnalysis: JSAnalysisResult,
): AttackSurface {
  // Merge JS-discovered endpoints with crawled endpoints
  const allEndpoints = [...crawlResult.endpoints];
  for (const jsEp of jsAnalysis.endpoints) {
    const exists = allEndpoints.some(e => e.url === jsEp.url);
    if (!exists) {
      allEndpoints.push({
        url: jsEp.url,
        method: jsEp.method ?? 'GET',
        source: 'javascript',
        parameters: [],
      });
    }
  }

  const suggestedTasks = generateTasks(
    allEndpoints,
    crawlResult.forms,
    jsAnalysis.secrets,
    crawlResult.technologies,
  );

  return {
    endpoints: allEndpoints,
    forms: crawlResult.forms,
    technologies: crawlResult.technologies,
    secrets: jsAnalysis.secrets,
    suggestedTasks,
  };
}
