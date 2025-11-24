/**
 * Guidelines Context
 * 
 * Provides program guidelines to all components and AI agents
 * Ensures agents understand scope, rules, and bounty ranges
 */

import React, { createContext, useContext, useState, ReactNode } from 'react';
import type { ProgramGuidelines } from '../components/GuidelinesImporter';

interface GuidelinesContextType {
  guidelines: ProgramGuidelines | null;
  setGuidelines: (guidelines: ProgramGuidelines | null) => void;
  getGuidelinesPrompt: () => string;
  isInScope: (target: string) => boolean;
  getBountyRange: () => { min: number; max: number } | null;
  hasGuidelines: () => boolean;
  requireGuidelines: () => void;
}

const GuidelinesContext = createContext<GuidelinesContextType | undefined>(undefined);

export const GuidelinesProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [guidelines, setGuidelines] = useState<ProgramGuidelines | null>(null);

  /**
   * Generate a prompt string for AI agents with program guidelines
   */
  const getGuidelinesPrompt = (): string => {
    if (!guidelines) {
      return 'No program guidelines loaded. Proceed with caution and follow general bug bounty best practices.';
    }

    return `
# Program Guidelines: ${guidelines.programName}

## Scope
### In-Scope Targets (${guidelines.scope.inScope.length}):
${guidelines.scope.inScope.map(t => `- ${t}`).join('\n')}

### Out-of-Scope Targets (${guidelines.scope.outOfScope.length}):
${guidelines.scope.outOfScope.map(t => `- ${t} (DO NOT TEST)`).join('\n')}

## Program Rules
${guidelines.rules.map((r, i) => `${i + 1}. ${r}`).join('\n')}

## Bounty Range
- Minimum: $${guidelines.bountyRange.min.toLocaleString()}
- Maximum: $${guidelines.bountyRange.max.toLocaleString()}

${guidelines.severity.critical ? `### Severity Payouts
- Critical: ${guidelines.severity.critical}
- High: ${guidelines.severity.high || 'Not specified'}
- Medium: ${guidelines.severity.medium || 'Not specified'}
- Low: ${guidelines.severity.low || 'Not specified'}` : ''}

## Important Reminders
1. ONLY test in-scope targets
2. Follow all program rules strictly
3. Stop immediately if you encounter out-of-scope assets
4. Document all findings with clear proof-of-concept
5. Respect rate limits and avoid DoS conditions

Program URL: ${guidelines.url}
Imported: ${new Date(guidelines.importedAt).toLocaleString()}
    `.trim();
  };

  /**
   * Check if a target is in scope
   */
  const isInScope = (target: string): boolean => {
    if (!guidelines) return false;

    // Check exact matches
    if (guidelines.scope.inScope.includes(target)) return true;

    // Check wildcard matches
    for (const scopeTarget of guidelines.scope.inScope) {
      if (scopeTarget.startsWith('*.')) {
        const domain = scopeTarget.substring(2);
        if (target.endsWith(domain) || target === domain) {
          return true;
        }
      }
    }

    // Check if it's explicitly out of scope
    for (const outOfScope of guidelines.scope.outOfScope) {
      if (target === outOfScope || target.includes(outOfScope)) {
        return false;
      }
    }

    return false;
  };

  /**
   * Get bounty range for the program
   */
  const getBountyRange = (): { min: number; max: number } | null => {
    if (!guidelines) return null;
    return guidelines.bountyRange;
  };

  /**
   * Check if guidelines are loaded
   */
  const hasGuidelines = (): boolean => {
    return guidelines !== null;
  };

  /**
   * Require guidelines to be loaded (throws error if not)
   * CRITICAL: Use this before OAuth testing to prevent policy violations
   */
  const requireGuidelines = (): void => {
    if (!guidelines) {
      throw new Error(
        'CRITICAL: Program guidelines must be imported before testing. ' +
        'This prevents policy violations like "no automated scanning" or ' +
        '"no testing on *.shopify.com". Use the Import Guidelines button to load program rules.'
      );
    }
  };

  return (
    <GuidelinesContext.Provider
      value={{
        guidelines,
        setGuidelines,
        getGuidelinesPrompt,
        isInScope,
        getBountyRange,
        hasGuidelines,
        requireGuidelines,
      }}
    >
      {children}
    </GuidelinesContext.Provider>
  );
};

/**
 * Hook to use guidelines context
 */
export const useGuidelines = (): GuidelinesContextType => {
  const context = useContext(GuidelinesContext);
  if (!context) {
    throw new Error('useGuidelines must be used within a GuidelinesProvider');
  }
  return context;
};

export default GuidelinesContext;