/**
 * OAuth State Parameter Validator
 * 
 * Phase 3: Tests state parameter for CSRF vulnerabilities:
 * - Missing state validation
 * - Predictable state tokens
 * - State fixation attacks
 * - State reuse vulnerabilities
 */

import axios from 'axios';
import { OAuthEndpoint } from './discovery';

export interface StateVulnerability {
  type: 'missing_state' | 'predictable_state' | 'state_fixation' | 'state_reuse';
  severity: 'low' | 'medium' | 'high' | 'critical';
  endpoint: string;
  description: string;
  evidence: string;
  impact: string;
  remediation: string;
}

export interface StateTestConfig {
  endpoint: OAuthEndpoint;
  clientId?: string;
  redirectUri?: string;
  timeout: number;
}

export class StateValidator {
  private config: StateTestConfig;
  private vulnerabilities: StateVulnerability[] = [];

  constructor(config: StateTestConfig) {
    this.config = config;
  }

  /**
   * Main validation orchestrator
   */
  async validate(): Promise<StateVulnerability[]> {
    console.log(`[State Validator] Testing ${this.config.endpoint.url}`);

    await Promise.allSettled([
      this.testMissingState(),
      this.testPredictableState(),
      this.testStateFixation(),
      this.testStateReuse(),
    ]);

    console.log(`[State Validator] Found ${this.vulnerabilities.length} vulnerabilities`);
    return this.vulnerabilities;
  }

  /**
   * Test if state parameter is required
   */
  private async testMissingState(): Promise<void> {
    try {
      // Build URL without state parameter
      const url = this.buildAuthUrl();
      url.searchParams.delete('state');

      const response = await axios.get(url.toString(), {
        timeout: this.config.timeout,
        maxRedirects: 0,
        validateStatus: () => true,
      });

      // If request succeeds without state, it's vulnerable
      if (response.status >= 200 && response.status < 400) {
        this.vulnerabilities.push({
          type: 'missing_state',
          severity: 'high',
          endpoint: this.config.endpoint.url,
          description: 'OAuth endpoint does not require state parameter',
          evidence: `Request without state parameter succeeded:\n${url.toString()}\nStatus: ${response.status}`,
          impact: 'Application is vulnerable to CSRF attacks. Attacker can trick users into authorizing malicious applications.',
          remediation: 'Make state parameter mandatory and validate it on callback',
        });
      }
    } catch (error) {
      // Test failed, continue
    }
  }

  /**
   * Test if state tokens are predictable
   */
  private async testPredictableState(): Promise<void> {
    const states: string[] = [];
    const numTests = 5;

    // Collect multiple state values
    for (let i = 0; i < numTests; i++) {
      try {
        const url = this.buildAuthUrl();
        const response = await axios.get(url.toString(), {
          timeout: this.config.timeout,
          maxRedirects: 0,
          validateStatus: () => true,
        });

        // Extract state from response or redirect
        const location = response.headers['location'];
        if (location) {
          const stateMatch = location.match(/state=([^&]+)/);
          if (stateMatch) {
            states.push(stateMatch[1]);
          }
        }

        // Also check if state is echoed in response body
        if (typeof response.data === 'string') {
          const bodyStateMatch = response.data.match(/state["\s:=]+([a-zA-Z0-9_-]+)/);
          if (bodyStateMatch) {
            states.push(bodyStateMatch[1]);
          }
        }
      } catch (error) {
        // Continue
      }
    }

    // Analyze state tokens for predictability
    if (states.length >= 3) {
      const analysis = this.analyzeStatePredictability(states);
      
      if (analysis.isPredictable) {
        this.vulnerabilities.push({
          type: 'predictable_state',
          severity: 'high',
          endpoint: this.config.endpoint.url,
          description: 'OAuth state tokens are predictable',
          evidence: `Collected states:\n${states.join('\n')}\n\nPattern: ${analysis.pattern}`,
          impact: 'Attacker can predict state values and bypass CSRF protection',
          remediation: 'Use cryptographically secure random values for state parameter (minimum 128 bits)',
        });
      }
    }
  }

  /**
   * Test for state fixation vulnerability
   */
  private async testStateFixation(): Promise<void> {
    const fixedState = 'attacker_controlled_state_12345';

    try {
      // First request with attacker's state
      const url1 = this.buildAuthUrl(fixedState);
      const response1 = await axios.get(url1.toString(), {
        timeout: this.config.timeout,
        maxRedirects: 0,
        validateStatus: () => true,
      });

      // Second request with same state
      const url2 = this.buildAuthUrl(fixedState);
      const response2 = await axios.get(url2.toString(), {
        timeout: this.config.timeout,
        maxRedirects: 0,
        validateStatus: () => true,
      });

      // If both requests succeed with same state, vulnerable to fixation
      if (response1.status < 400 && response2.status < 400) {
        const location1 = response1.headers['location'];
        const location2 = response2.headers['location'];

        if (location1 && location2 && 
            location1.includes(fixedState) && location2.includes(fixedState)) {
          this.vulnerabilities.push({
            type: 'state_fixation',
            severity: 'high',
            endpoint: this.config.endpoint.url,
            description: 'OAuth endpoint vulnerable to state fixation',
            evidence: `Fixed state "${fixedState}" accepted in multiple requests:\nRequest 1: ${url1.toString()}\nRequest 2: ${url2.toString()}`,
            impact: 'Attacker can fix the state parameter and perform CSRF attacks',
            remediation: 'Generate unique state values per session and validate them server-side',
          });
        }
      }
    } catch (error) {
      // Test failed, continue
    }
  }

  /**
   * Test for state reuse vulnerability
   */
  private async testStateReuse(): Promise<void> {
    const testState = 'test_state_' + Date.now();

    try {
      // Simulate complete OAuth flow
      const url = this.buildAuthUrl(testState);
      
      // First authorization request
      const response1 = await axios.get(url.toString(), {
        timeout: this.config.timeout,
        maxRedirects: 0,
        validateStatus: () => true,
      });

      // Try to reuse the same state in another request
      const response2 = await axios.get(url.toString(), {
        timeout: this.config.timeout,
        maxRedirects: 0,
        validateStatus: () => true,
      });

      // If state can be reused, it's vulnerable
      if (response1.status < 400 && response2.status < 400) {
        this.vulnerabilities.push({
          type: 'state_reuse',
          severity: 'medium',
          endpoint: this.config.endpoint.url,
          description: 'OAuth state parameter can be reused',
          evidence: `State "${testState}" accepted in multiple requests:\nRequest 1: ${response1.status}\nRequest 2: ${response2.status}`,
          impact: 'State tokens can be reused, reducing CSRF protection effectiveness',
          remediation: 'Implement one-time use state tokens that are invalidated after first use',
        });
      }
    } catch (error) {
      // Test failed, continue
    }
  }

  /**
   * Build authorization URL
   */
  private buildAuthUrl(state?: string): URL {
    const url = new URL(this.config.endpoint.url);
    url.searchParams.set('response_type', 'code');
    
    if (this.config.clientId) {
      url.searchParams.set('client_id', this.config.clientId);
    }
    
    if (this.config.redirectUri) {
      url.searchParams.set('redirect_uri', this.config.redirectUri);
    }
    
    if (state) {
      url.searchParams.set('state', state);
    } else {
      url.searchParams.set('state', 'test_state_' + Date.now());
    }
    
    url.searchParams.set('scope', 'openid profile email');
    
    return url;
  }

  /**
   * Analyze state tokens for predictability
   */
  private analyzeStatePredictability(states: string[]): { isPredictable: boolean; pattern: string } {
    // Check for sequential patterns
    const isSequential = states.every((state, i) => {
      if (i === 0) return true;
      const prev = parseInt(states[i - 1], 10);
      const curr = parseInt(state, 10);
      return !isNaN(prev) && !isNaN(curr) && curr === prev + 1;
    });

    if (isSequential) {
      return { isPredictable: true, pattern: 'Sequential numbers' };
    }

    // Check for timestamp-based patterns
    const timestamps = states.map(s => parseInt(s, 10)).filter(n => !isNaN(n));
    if (timestamps.length === states.length) {
      const now = Date.now();
      const allRecent = timestamps.every(ts => Math.abs(now - ts) < 3600000); // Within 1 hour
      if (allRecent) {
        return { isPredictable: true, pattern: 'Timestamp-based' };
      }
    }

    // Check for short length (< 16 characters)
    const avgLength = states.reduce((sum, s) => sum + s.length, 0) / states.length;
    if (avgLength < 16) {
      return { isPredictable: true, pattern: 'Insufficient entropy (too short)' };
    }

    // Check for repeated patterns
    const uniqueStates = new Set(states);
    if (uniqueStates.size < states.length) {
      return { isPredictable: true, pattern: 'Repeated values' };
    }

    // Check for common prefixes/suffixes
    const commonPrefix = this.findCommonPrefix(states);
    if (commonPrefix.length > states[0].length * 0.5) {
      return { isPredictable: true, pattern: `Common prefix: ${commonPrefix}` };
    }

    return { isPredictable: false, pattern: 'No obvious pattern detected' };
  }

  /**
   * Find common prefix in strings
   */
  private findCommonPrefix(strings: string[]): string {
    if (strings.length === 0) return '';
    
    let prefix = strings[0];
    for (let i = 1; i < strings.length; i++) {
      while (strings[i].indexOf(prefix) !== 0) {
        prefix = prefix.substring(0, prefix.length - 1);
        if (prefix === '') return '';
      }
    }
    return prefix;
  }
}

export default StateValidator;