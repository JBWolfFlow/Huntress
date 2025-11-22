/**
 * Report Templates
 * 
 * Professional templates for vulnerability reports
 */

export const REPORT_TEMPLATES = {
  open_redirect: `
# Open Redirect Vulnerability

## Summary
An open redirect vulnerability was discovered that allows attackers to redirect users to arbitrary external domains.

## Vulnerability Details
**URL:** {{url}}
**Parameter:** {{parameter}}
**Severity:** {{severity}}

## Steps to Reproduce
{{steps}}

## Proof of Concept
{{poc}}

## Impact
This vulnerability can be exploited for phishing attacks by making malicious URLs appear to originate from a trusted domain.

## Remediation
- Implement whitelist-based redirect validation
- Use relative URLs for internal redirects
- Validate and sanitize all redirect parameters
  `,

  xss: `
# Cross-Site Scripting (XSS) Vulnerability

## Summary
A {{xss_type}} XSS vulnerability was identified that allows execution of arbitrary JavaScript in the context of the application.

## Vulnerability Details
**URL:** {{url}}
**Parameter:** {{parameter}}
**Payload:** {{payload}}
**Severity:** {{severity}}

## Steps to Reproduce
{{steps}}

## Proof of Concept
{{poc}}

## Impact
- Session hijacking
- Credential theft
- Defacement
- Malware distribution

## Remediation
- Implement proper output encoding
- Use Content Security Policy (CSP)
- Sanitize user input
- Use framework-provided XSS protection
  `,

  sql_injection: `
# SQL Injection Vulnerability

## Summary
A SQL injection vulnerability was discovered that allows unauthorized database access and manipulation.

## Vulnerability Details
**URL:** {{url}}
**Parameter:** {{parameter}}
**Database:** {{database_type}}
**Severity:** CRITICAL

## Steps to Reproduce
{{steps}}

## Proof of Concept
{{poc}}

## Impact
- Unauthorized data access
- Data modification or deletion
- Authentication bypass
- Potential remote code execution

## Remediation
- Use parameterized queries/prepared statements
- Implement input validation
- Apply principle of least privilege
- Use ORM frameworks
  `,

  idor: `
# Insecure Direct Object Reference (IDOR)

## Summary
An IDOR vulnerability allows unauthorized access to other users' resources by manipulating object identifiers.

## Vulnerability Details
**Endpoint:** {{endpoint}}
**Method:** {{method}}
**Vulnerable Parameter:** {{parameter}}
**Severity:** {{severity}}

## Steps to Reproduce
{{steps}}

## Proof of Concept
{{poc}}

## Impact
- Unauthorized data access
- Privacy violations
- Potential account takeover
- Data breach

## Remediation
- Implement proper authorization checks
- Use indirect reference maps
- Validate user permissions on every request
- Implement access control lists (ACLs)
  `,

  ssrf: `
# Server-Side Request Forgery (SSRF)

## Summary
An SSRF vulnerability allows attackers to make the server perform requests to arbitrary destinations.

## Vulnerability Details
**URL:** {{url}}
**Parameter:** {{parameter}}
**Severity:** {{severity}}

## Steps to Reproduce
{{steps}}

## Proof of Concept
{{poc}}

## Impact
- Internal network scanning
- Access to internal services
- Cloud metadata access
- Potential remote code execution

## Remediation
- Implement URL whitelist
- Disable unnecessary protocols
- Use network segmentation
- Validate and sanitize URLs
  `,
};

export function fillTemplate(template: string, data: Record<string, string>): string {
  let filled = template;
  
  for (const [key, value] of Object.entries(data)) {
    const placeholder = `{{${key}}}`;
    filled = filled.replace(new RegExp(placeholder, 'g'), value);
  }
  
  return filled.trim();
}

export default REPORT_TEMPLATES;