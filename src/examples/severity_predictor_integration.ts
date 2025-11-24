/**
 * Severity Predictor Integration Example
 * 
 * Demonstrates how to use the SeverityPredictor with:
 * - Duplicate detection
 * - Program guidelines
 * - Historical learning
 * - Report generation
 */

import { QdrantClient } from '../core/memory/qdrant_client';
import { FindingSummarizer } from '../core/memory/summarizer';
import { DuplicateChecker, type Vulnerability } from '../utils/duplicate_checker';
import {
  SeverityPredictor,
  type AcceptedReport,
  type SeverityPrediction,
} from '../core/reporting/severity_predictor';
import {
  createProgramAwarePredictor,
  formatBountyRange,
  getSeverityColor,
} from '../core/reporting/severity_integration';
import type { ProgramGuidelines } from '../components/GuidelinesImporter';

/**
 * Example 1: Basic Severity Prediction
 */
export async function example1_basicPrediction() {
  console.log('\n=== Example 1: Basic Severity Prediction ===\n');

  // Initialize Qdrant client
  const qdrant = new QdrantClient({
    url: 'http://localhost:6333',
    collectionName: 'huntress_findings',
  });

  // Create predictor
  const predictor = new SeverityPredictor(qdrant);

  // Example vulnerability
  const vulnerability: Vulnerability = {
    id: 'vuln-001',
    type: 'oauth_misconfiguration',
    severity: 'medium', // Initial guess
    title: 'OAuth State Parameter Missing - CSRF Vulnerability',
    description: 'The OAuth authorization flow does not implement state parameter validation, allowing CSRF attacks',
    url: 'https://api.example.com/oauth/authorize',
    target: 'api.example.com',
    impact: 'Attacker can force victim to authorize malicious application, leading to account takeover',
    steps: [
      'Navigate to /oauth/authorize endpoint',
      'Remove state parameter from request',
      'Complete authorization flow',
      'Observe successful authorization without state validation',
    ],
    timestamp: Date.now(),
  };

  // Predict severity
  const prediction = await predictor.predictSeverity(vulnerability);

  console.log('Vulnerability:', vulnerability.title);
  console.log('Predicted Severity:', prediction.severity);
  console.log('Confidence:', `${prediction.confidence}%`);
  console.log('Suggested Bounty:', formatBountyRange(prediction.suggestedBounty));
  console.log('\nReasoning:');
  prediction.reasoning.forEach((reason, i) => {
    console.log(`  ${i + 1}. ${reason}`);
  });
  console.log('\nHistorical Data:');
  console.log(`  Similar Reports: ${prediction.historicalData.similarReports}`);
  console.log(`  Average Bounty: $${prediction.historicalData.averageBounty.toLocaleString()}`);
  console.log(`  Acceptance Rate: ${(prediction.historicalData.acceptanceRate * 100).toFixed(1)}%`);
}

/**
 * Example 2: Program-Aware Prediction with Guidelines
 */
export async function example2_programAwarePrediction() {
  console.log('\n=== Example 2: Program-Aware Prediction ===\n');

  const qdrant = new QdrantClient({
    url: 'http://localhost:6333',
    collectionName: 'huntress_findings',
  });

  // Example program guidelines
  const guidelines: ProgramGuidelines = {
    programHandle: 'example-corp',
    programName: 'Example Corp Bug Bounty',
    url: 'https://hackerone.com/example-corp',
    scope: {
      inScope: ['*.example.com', 'api.example.com'],
      outOfScope: ['test.example.com'],
    },
    rules: [
      'Do not perform DoS attacks',
      'Do not access user data',
      'Report findings within 24 hours',
    ],
    bountyRange: {
      min: 500,
      max: 25000,
    },
    severity: {
      critical: '$10,000 - $25,000',
      high: '$3,000 - $10,000',
      medium: '$1,000 - $3,000',
      low: '$500 - $1,000',
    },
    importedAt: new Date(),
  };

  // Create program-aware predictor
  const predictor = createProgramAwarePredictor(qdrant, guidelines);

  const vulnerability: Vulnerability = {
    id: 'vuln-002',
    type: 'sql_injection',
    severity: 'high',
    title: 'SQL Injection in User Search',
    description: 'User search endpoint vulnerable to SQL injection via search parameter',
    url: 'https://api.example.com/users/search',
    target: 'api.example.com',
    impact: 'Complete database compromise, access to all user data including passwords',
    steps: [
      'Send GET request to /users/search?q=test',
      'Inject SQL payload: ?q=test\' OR 1=1--',
      'Observe all users returned',
      'Extract sensitive data using UNION injection',
    ],
    timestamp: Date.now(),
  };

  const prediction = await predictor.predictSeverity(vulnerability);

  console.log('Program:', guidelines.programName);
  console.log('Vulnerability:', vulnerability.title);
  console.log('Predicted Severity:', prediction.severity);
  console.log('Confidence:', `${prediction.confidence}%`);
  console.log('Suggested Bounty:', formatBountyRange(prediction.suggestedBounty));
  console.log('Color:', getSeverityColor(prediction.severity));
}

/**
 * Example 3: Learning from Accepted Reports
 */
export async function example3_learningFromReports() {
  console.log('\n=== Example 3: Learning from Accepted Reports ===\n');

  const qdrant = new QdrantClient({
    url: 'http://localhost:6333',
    collectionName: 'huntress_findings',
  });

  const predictor = new SeverityPredictor(qdrant);

  // Simulate accepted reports for training
  const acceptedReports: AcceptedReport[] = [
    {
      id: 'report-001',
      type: 'oauth_misconfiguration',
      severity: 'high',
      bountyAmount: 5000,
      program: 'example-corp',
      acceptedAt: Date.now() - 86400000 * 30, // 30 days ago
      description: 'OAuth redirect_uri validation bypass',
      impact: 'Account takeover via malicious redirect',
      cvssScore: 8.1,
    },
    {
      id: 'report-002',
      type: 'oauth_misconfiguration',
      severity: 'high',
      bountyAmount: 4500,
      program: 'example-corp',
      acceptedAt: Date.now() - 86400000 * 20, // 20 days ago
      description: 'Missing PKCE enforcement',
      impact: 'Authorization code interception',
      cvssScore: 7.8,
    },
    {
      id: 'report-003',
      type: 'oauth_misconfiguration',
      severity: 'critical',
      bountyAmount: 12000,
      program: 'another-corp',
      acceptedAt: Date.now() - 86400000 * 10, // 10 days ago
      description: 'OAuth state parameter bypass with account takeover',
      impact: 'Full account takeover of any user',
      cvssScore: 9.3,
    },
  ];

  // Train the model with accepted reports
  console.log('Training model with accepted reports...\n');
  for (const report of acceptedReports) {
    await predictor.updateModel(report);
    console.log(`✓ Learned from: ${report.type} - $${report.bountyAmount.toLocaleString()}`);
  }

  // Now predict on a new similar vulnerability
  const newVulnerability: Vulnerability = {
    id: 'vuln-003',
    type: 'oauth_misconfiguration',
    severity: 'medium',
    title: 'OAuth Scope Escalation',
    description: 'Application allows requesting elevated scopes without proper validation',
    url: 'https://api.example.com/oauth/authorize',
    target: 'api.example.com',
    impact: 'Privilege escalation to admin scopes',
    steps: [
      'Request authorization with user scope',
      'Modify scope parameter to admin',
      'Complete authorization',
      'Observe admin access granted',
    ],
    timestamp: Date.now(),
  };

  console.log('\nPredicting severity for new vulnerability...\n');
  const prediction = await predictor.predictSeverity(newVulnerability);

  console.log('Vulnerability:', newVulnerability.title);
  console.log('Predicted Severity:', prediction.severity);
  console.log('Confidence:', `${prediction.confidence}%`);
  console.log('Suggested Bounty:', formatBountyRange(prediction.suggestedBounty));
  console.log('\nHistorical Data (from training):');
  console.log(`  Similar Reports: ${prediction.historicalData.similarReports}`);
  console.log(`  Average Bounty: $${prediction.historicalData.averageBounty.toLocaleString()}`);
}

/**
 * Example 4: Complete Pipeline with Duplicate Detection
 */
export async function example4_completePipeline() {
  console.log('\n=== Example 4: Complete Pipeline ===\n');

  const qdrant = new QdrantClient({
    url: 'http://localhost:6333',
    collectionName: 'huntress_findings',
  });

  const summarizer = new FindingSummarizer(
    process.env.ANTHROPIC_API_KEY || 'dummy-key'
  );
  const duplicateChecker = new DuplicateChecker(
    qdrant,
    summarizer,
    0.85,
    process.env.H1_API_KEY,
    process.env.GITHUB_TOKEN
  );

  const predictor = new SeverityPredictor(qdrant);

  const vulnerability: Vulnerability = {
    id: 'vuln-004',
    type: 'idor',
    severity: 'medium',
    title: 'IDOR in User Profile API',
    description: 'User profile endpoint allows accessing other users\' data by changing user ID',
    url: 'https://api.example.com/users/{id}/profile',
    target: 'api.example.com',
    impact: 'Unauthorized access to user PII including email, phone, address',
    steps: [
      'Login as user A (ID: 123)',
      'Request /users/123/profile',
      'Change ID to 456',
      'Observe user B\'s profile data returned',
    ],
    timestamp: Date.now(),
    proof: {
      screenshots: ['screenshot1.png', 'screenshot2.png'],
      logs: ['request.log', 'response.log'],
    },
  };

  // Step 1: Check for duplicates
  console.log('Step 1: Checking for duplicates...\n');
  const duplicateScore = await duplicateChecker.getDuplicateScore(vulnerability);
  
  console.log('Duplicate Score:', `${duplicateScore.overall}%`);
  console.log('Recommendation:', duplicateScore.recommendation.toUpperCase());
  
  if (duplicateScore.recommendation === 'skip') {
    console.log('\n⚠️ High duplicate probability - skipping submission');
    return;
  }

  // Step 2: Predict severity and bounty
  console.log('\nStep 2: Predicting severity and bounty...\n');
  const prediction = await predictor.predictSeverity(vulnerability);
  
  console.log('Predicted Severity:', prediction.severity);
  console.log('Confidence:', `${prediction.confidence}%`);
  console.log('Suggested Bounty:', formatBountyRange(prediction.suggestedBounty));

  // Step 3: Generate report (simplified)
  console.log('\nStep 3: Generating report...\n');
  const report = {
    title: vulnerability.title,
    severity: prediction.severity,
    suggestedBounty: prediction.suggestedBounty,
    description: vulnerability.description,
    impact: vulnerability.impact,
    steps: vulnerability.steps,
    duplicateCheck: {
      score: duplicateScore.overall,
      recommendation: duplicateScore.recommendation,
    },
    confidence: prediction.confidence,
  };

  console.log('Report ready for submission:');
  console.log(JSON.stringify(report, null, 2));

  // Step 4: If accepted, learn from it
  if (prediction.confidence >= 70) {
    console.log('\n✓ High confidence - ready for submission');
  } else {
    console.log('\n⚠️ Low confidence - manual review recommended');
  }
}

/**
 * Example 5: Batch Processing Multiple Vulnerabilities
 */
export async function example5_batchProcessing() {
  console.log('\n=== Example 5: Batch Processing ===\n');

  const qdrant = new QdrantClient({
    url: 'http://localhost:6333',
    collectionName: 'huntress_findings',
  });

  const predictor = new SeverityPredictor(qdrant);

  const vulnerabilities: Vulnerability[] = [
    {
      id: 'vuln-005',
      type: 'xss',
      severity: 'medium',
      title: 'Reflected XSS in Search',
      description: 'Search parameter reflects user input without sanitization',
      url: 'https://example.com/search',
      target: 'example.com',
      impact: 'Session hijacking, credential theft',
      steps: ['Navigate to /search?q=<script>alert(1)</script>', 'Observe XSS execution'],
      timestamp: Date.now(),
    },
    {
      id: 'vuln-006',
      type: 'rce',
      severity: 'critical',
      title: 'Remote Code Execution via File Upload',
      description: 'File upload allows executing arbitrary code',
      url: 'https://example.com/upload',
      target: 'example.com',
      impact: 'Complete server compromise',
      steps: ['Upload PHP shell', 'Access uploaded file', 'Execute commands'],
      timestamp: Date.now(),
    },
    {
      id: 'vuln-007',
      type: 'csrf',
      severity: 'medium',
      title: 'CSRF in Password Change',
      description: 'Password change endpoint lacks CSRF protection',
      url: 'https://example.com/account/password',
      target: 'example.com',
      impact: 'Account takeover via CSRF',
      steps: ['Create CSRF PoC', 'Victim visits page', 'Password changed'],
      timestamp: Date.now(),
    },
  ];

  console.log(`Processing ${vulnerabilities.length} vulnerabilities...\n`);

  const results: Array<{ vuln: Vulnerability; prediction: SeverityPrediction }> = [];

  for (const vuln of vulnerabilities) {
    const prediction = await predictor.predictSeverity(vuln);
    results.push({ vuln, prediction });
  }

  // Sort by suggested bounty (max)
  results.sort((a, b) => b.prediction.suggestedBounty.max - a.prediction.suggestedBounty.max);

  console.log('Results (sorted by bounty potential):\n');
  results.forEach((result, i) => {
    console.log(`${i + 1}. ${result.vuln.title}`);
    console.log(`   Severity: ${result.prediction.severity} (${result.prediction.confidence}% confidence)`);
    console.log(`   Bounty: ${formatBountyRange(result.prediction.suggestedBounty)}`);
    console.log('');
  });
}

/**
 * Run all examples
 */
export async function runAllExamples() {
  try {
    await example1_basicPrediction();
    await example2_programAwarePrediction();
    await example3_learningFromReports();
    await example4_completePipeline();
    await example5_batchProcessing();
    
    console.log('\n✓ All examples completed successfully!\n');
  } catch (error) {
    console.error('Error running examples:', error);
  }
}

// Run examples if executed directly
if (require.main === module) {
  runAllExamples();
}