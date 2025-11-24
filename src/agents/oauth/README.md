# OAuth Hunter Module

A comprehensive OAuth vulnerability detection system for the Huntress bug bounty automation platform.

## Overview

The OAuth Hunter is a modular, multi-phase vulnerability scanner designed to discover and exploit OAuth misconfigurations. It averages **$4,800 per bounty** (vs $2,900 for redirect vulnerabilities), making it the highest-priority agent in Huntress.

## Architecture

```
oauth/
├── index.ts              # Main orchestrator
├── discovery.ts          # Phase 1: Endpoint discovery
├── redirect_validator.ts # Phase 2: redirect_uri testing
├── state_validator.ts    # Phase 3: State parameter testing
└── README.md            # This file
```

## Features

### Phase 1: Discovery Engine
- **Well-known endpoints**: Checks `.well-known/openid-configuration`
- **Common paths**: Tests standard OAuth URL patterns
- **Wayback Machine**: Historical endpoint discovery
- **Nuclei integration**: Automated template-based scanning
- **JavaScript analysis**: Extracts OAuth URLs from JS files

### Phase 2: redirect_uri Validation
- **Open redirect detection**: Tests for arbitrary redirect_uri values
- **Token theft**: Validates if tokens can be stolen via malicious redirects
- **XSS testing**: Checks for XSS via redirect_uri parameter
- **Path traversal**: Tests for path-based validation bypasses

### Phase 3: State Parameter Testing
- **Missing state**: Detects if state parameter is optional
- **Predictable state**: Analyzes state token entropy
- **State fixation**: Tests for state fixation attacks
- **State reuse**: Validates one-time use enforcement

## Usage

### Basic Usage

```typescript
import { OAuthHunter } from './agents/oauth';

const hunter = new OAuthHunter({
  target: 'api.example.com',
  clientId: 'your_client_id',
  redirectUri: 'https://your-app.com/callback',
  collaboratorUrl: 'https://your-collaborator.com',
});

const result = await hunter.hunt();

console.log(`Found ${result.vulnerabilities.length} vulnerabilities`);
console.log(`Critical: ${result.summary.critical}`);
console.log(`High: ${result.summary.high}`);
```

### Advanced Configuration

```typescript
const hunter = new OAuthHunter({
  target: 'api.example.com',
  clientId: 'optional_client_id',
  redirectUri: 'https://your-app.com/callback',
  collaboratorUrl: 'https://burp-collaborator.net/xyz',
  timeout: 30000,           // Request timeout in ms
  maxEndpoints: 1000,       // Max endpoints to discover
  useWayback: true,         // Enable Wayback Machine
  useNuclei: true,          // Enable Nuclei scanning
});
```

### Generate Reports

```typescript
const result = await hunter.hunt();

for (const vuln of result.vulnerabilities) {
  const report = hunter.generateReport(vuln);
  console.log(report);
}
```

## Output Format

### OAuthHuntResult

```typescript
{
  target: "api.example.com",
  endpointsFound: 5,
  vulnerabilities: [
    {
      id: "oauth_1234567890_abc123",
      type: "oauth_open_redirect",
      severity: "high",
      endpoint: "https://api.example.com/oauth/authorize",
      description: "OAuth authorization endpoint allows arbitrary redirect_uri values",
      evidence: "Request: https://...\nResponse Location: https://evil.com",
      impact: "Attacker can steal authorization codes...",
      remediation: "Implement strict redirect_uri validation...",
      discoveredAt: "2025-01-22T02:30:00.000Z",
      payload: "https://evil.com"
    }
  ],
  summary: {
    critical: 0,
    high: 1,
    medium: 0,
    low: 0
  },
  duration: 45000
}
```

## Prerequisites

### Required Tools

1. **Node.js packages** (already installed):
   ```bash
   npm install axios openid-client
   ```

2. **Security tools**:
   ```bash
   # Install waybackurls
   go install github.com/tomnomnom/waybackurls@latest
   
   # Install nuclei
   go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
   nuclei -update-templates
   ```

3. **Collaborator service** (optional but recommended):
   - Burp Suite Professional (built-in Collaborator)
   - OR Interactsh: https://app.interactsh.com

### Environment Variables

```bash
# .env file
OAUTH_DISCOVERY_ENABLED=true
OAUTH_MAX_ENDPOINTS=1000
OAUTH_TIMEOUT_MS=30000

# Security tools
WAYBACKURLS_PATH=waybackurls
NUCLEI_PATH=nuclei
NUCLEI_TEMPLATES_PATH=~/nuclei-templates

# Collaborator (optional)
COLLABORATOR_URL=https://your-collaborator.com
```

## Testing

### Unit Tests

```bash
npm test src/agents/oauth/
```

### Integration Tests

```bash
# Test against a known vulnerable OAuth implementation
npm run test:oauth -- --target vulnerable-oauth-app.com
```

## Attack Vectors

### 1. redirect_uri Manipulation (High Priority)
- **Bounty Range**: $2,000 - $10,000
- **Acceptance Rate**: 75%
- **Common Payloads**:
  - `https://evil.com`
  - `https://target.com@evil.com`
  - `https://target.com%2f%2fevil.com`

### 2. State Parameter Issues (High Priority)
- **Bounty Range**: $1,500 - $8,000
- **Acceptance Rate**: 70%
- **Tests**:
  - Missing state validation
  - Predictable state tokens
  - State fixation

### 3. Token Theft (Critical Priority)
- **Bounty Range**: $5,000 - $25,000
- **Acceptance Rate**: 85%
- **Requires**: Collaborator URL

## Performance

- **Discovery Phase**: 10-30 seconds
- **Validation Phase**: 30-60 seconds per endpoint
- **Total Runtime**: 1-5 minutes (depending on endpoints found)

## Roadmap

### Phase 4: PKCE Bypass (Coming Soon)
- Missing code_challenge validation
- Weak code_verifier generation
- Downgrade to non-PKCE flow

### Phase 5: Scope Escalation (Coming Soon)
- Requesting elevated scopes
- Scope confusion attacks
- Missing scope validation

### Phase 6: Token Validation (Coming Soon)
- JWT signature validation
- Token expiration testing
- Token reuse detection

## References

- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OAuth 2.0 Threat Model (RFC 6819)](https://datatracker.ietf.org/doc/html/rfc6819)
- [OWASP OAuth Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- [HackerOne OAuth Reports](https://hackerone.com/hacktivity?querystring=oauth)

## Contributing

When adding new attack vectors:

1. Add test method to appropriate validator
2. Update vulnerability types in interfaces
3. Add documentation to this README
4. Include test cases
5. Update PIPELINE.md with bounty data

## License

Part of the Huntress bug bounty automation platform.