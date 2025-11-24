/**
 * Reporting Module
 *
 * Exports HackerOne API client, PoC generator, report templates, and severity predictor
 */

export {
  HackerOneAPI,
  type H1ApiConfig,
  type H1Report,
  type Attachment,
  type SubmissionResult,
  type ReportStatus,
} from './h1_api';
export {
  PoCGenerator,
  type ProgramGuidelines,
  type ReportGenerationOptions
} from './poc_generator';
export { REPORT_TEMPLATES, fillTemplate } from './templates';
export {
  SeverityPredictor,
  type SeverityPrediction,
  type BountyRange,
  type AcceptedReport,
  type ProgramBountyRanges,
  type VulnerabilityFeatures,
} from './severity_predictor';
export {
  createProgramAwarePredictor,
  extractBountyRanges,
  formatBountyRange,
  getSeverityColor,
  getSeverityBadgeClass,
  getConfidenceBadgeClass,
} from './severity_integration';