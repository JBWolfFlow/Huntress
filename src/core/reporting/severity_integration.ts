/**
 * Severity Predictor Integration with Guidelines Context
 * 
 * Bridges the SeverityPredictor with program-specific guidelines
 * to provide accurate, program-aware severity and bounty predictions
 */

import { SeverityPredictor, type ProgramBountyRanges } from './severity_predictor';
import type { ProgramGuidelines } from '../../components/GuidelinesImporter';

/**
 * Create a SeverityPredictor instance configured with program guidelines
 */
export function createProgramAwarePredictor(
  qdrant: any,
  guidelines: ProgramGuidelines | null
): SeverityPredictor {
  const predictor = new SeverityPredictor(qdrant);

  if (guidelines) {
    // Extract bounty ranges from guidelines
    const bountyRanges = extractBountyRanges(guidelines);
    
    if (bountyRanges) {
      predictor.setProgramBountyRanges(bountyRanges, guidelines.programName);
    }
  }

  return predictor;
}

/**
 * Extract bounty ranges from program guidelines
 */
export function extractBountyRanges(
  guidelines: ProgramGuidelines
): ProgramBountyRanges | null {
  const ranges: ProgramBountyRanges = {};

  // Parse severity payouts if available
  if (guidelines.severity) {
    if (guidelines.severity.critical) {
      ranges.critical = parseBountyRange(guidelines.severity.critical);
    }
    if (guidelines.severity.high) {
      ranges.high = parseBountyRange(guidelines.severity.high);
    }
    if (guidelines.severity.medium) {
      ranges.medium = parseBountyRange(guidelines.severity.medium);
    }
    if (guidelines.severity.low) {
      ranges.low = parseBountyRange(guidelines.severity.low);
    }
  }

  // If no severity-specific ranges, use program min/max
  if (Object.keys(ranges).length === 0 && guidelines.bountyRange) {
    const { min, max } = guidelines.bountyRange;
    
    // Distribute across severity levels
    ranges.critical = { min: Math.floor(max * 0.6), max };
    ranges.high = { min: Math.floor(max * 0.3), max: Math.floor(max * 0.6) };
    ranges.medium = { min: Math.floor(max * 0.1), max: Math.floor(max * 0.3) };
    ranges.low = { min, max: Math.floor(max * 0.1) };
  }

  return Object.keys(ranges).length > 0 ? ranges : null;
}

/**
 * Parse bounty range from string (e.g., "$1,000 - $5,000" or "$2,500")
 */
function parseBountyRange(rangeStr: string): { min: number; max: number } | undefined {
  if (!rangeStr) return undefined;

  // Remove currency symbols and commas
  const cleaned = rangeStr.replace(/[$,]/g, '');

  // Check for range format (e.g., "1000 - 5000" or "1000-5000")
  const rangeMatch = cleaned.match(/(\d+)\s*-\s*(\d+)/);
  if (rangeMatch) {
    return {
      min: parseInt(rangeMatch[1], 10),
      max: parseInt(rangeMatch[2], 10),
    };
  }

  // Check for single value (e.g., "2500")
  const singleMatch = cleaned.match(/(\d+)/);
  if (singleMatch) {
    const value = parseInt(singleMatch[1], 10);
    return {
      min: Math.floor(value * 0.8),
      max: Math.floor(value * 1.2),
    };
  }

  return undefined;
}

/**
 * Format bounty range for display
 */
export function formatBountyRange(range: { min: number; max: number }): string {
  return `$${range.min.toLocaleString()} - $${range.max.toLocaleString()}`;
}

/**
 * Get severity color for UI display
 */
export function getSeverityColor(severity: 'critical' | 'high' | 'medium' | 'low'): string {
  const colors = {
    critical: '#dc2626', // red-600
    high: '#ea580c',    // orange-600
    medium: '#ca8a04',  // yellow-600
    low: '#16a34a',     // green-600
  };
  return colors[severity];
}

/**
 * Get severity badge class for Tailwind
 */
export function getSeverityBadgeClass(severity: 'critical' | 'high' | 'medium' | 'low'): string {
  const classes = {
    critical: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
    high: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
    medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
    low: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
  };
  return classes[severity];
}

/**
 * Calculate confidence badge class
 */
export function getConfidenceBadgeClass(confidence: number): string {
  if (confidence >= 80) {
    return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200';
  } else if (confidence >= 60) {
    return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200';
  } else {
    return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200';
  }
}

export default {
  createProgramAwarePredictor,
  extractBountyRanges,
  formatBountyRange,
  getSeverityColor,
  getSeverityBadgeClass,
  getConfidenceBadgeClass,
};