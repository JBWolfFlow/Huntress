/**
 * Duplicate Detection Integration Example
 * 
 * Shows how to integrate the duplicate detection system into the reporting workflow.
 * This is CRITICAL for Phase 4 - prevents 80% of wasted submissions.
 */

import { DuplicateChecker, type Vulnerability, type DuplicateScore } from '../utils/duplicate_checker';
import { QdrantClient } from '../core/memory/qdrant_client';
import { FindingSummarizer } from '../core/memory/summarizer';
import { HackerOneAPI, type H1Report } from '../core/reporting/h1_api';

/**
 * Example 1: Basic Duplicate Check Before Submission
 */
export async function checkBeforeSubmission(vuln: Vulnerability): Promise<boolean> {
  // Initialize components
  const qdrant = new QdrantClient({
    url: process.env.QDRANT_URL || 'http://localhost:6333',
    collectionName: 'huntress_findings',
  });

  const summarizer = new FindingSummarizer(
    process.env.ANTHROPIC_API_KEY || '',
    'claude-3-5-sonnet-20241022'
  );

  const duplicateChecker = new DuplicateChecker(
    qdrant,
    summarizer,
    0.85,
    process.env.HACKERONE_API_KEY,
    process.env.GITHUB_TOKEN
  );

  // Check for duplicates
  console.log('🔍 Checking for duplicates...');
  const score = await duplicateChecker.getDuplicateScore(vuln);

  // Display results
  console.log('\n📊 Duplicate Detection Results:');
  console.log(`Overall Score: ${score.overall}/100`);
  console.log(`HackerOne Match: ${(score.h1Match * 100).toFixed(1)}%`);
  console.log(`GitHub Match: ${(score.githubMatch * 100).toFixed(1)}%`);
  console.log(`Internal Match: ${(score.internalMatch * 100).toFixed(1)}%`);
  console.log(`Recommendation: ${score.recommendation.toUpperCase()}`);

  if (score.matches.length > 0) {
    console.log('\n🔗 Similar Reports Found:');
    score.matches.forEach((match, i) => {
      console.log(`  ${i + 1}. [${match.source}] ${match.title}`);
      console.log(`     Similarity: ${(match.similarity * 100).toFixed(1)}%`);
      console.log(`     URL: ${match.url}`);
    });
  }

  console.log('\n💡 Reasoning:');
  score.reasoning.forEach(reason => console.log(`  - ${reason}`));

  // Return whether to proceed
  return score.recommendation === 'submit';
}

/**
 * Example 2: Complete Reporting Workflow with Duplicate Detection
 */
export async function completeReportingWorkflow(vuln: Vulnerability): Promise<void> {
  console.log('🚀 Starting Complete Reporting Workflow\n');

  // Step 1: Initialize duplicate checker
  const qdrant = new QdrantClient({
    url: process.env.QDRANT_URL || 'http://localhost:6333',
    collectionName: 'huntress_findings',
  });

  const summarizer = new FindingSummarizer(
    process.env.ANTHROPIC_API_KEY || '',
  );

  const duplicateChecker = new DuplicateChecker(
    qdrant,
    summarizer,
    0.85,
    process.env.HACKERONE_API_KEY,
    process.env.GITHUB_TOKEN
  );

  // Step 2: Check for duplicates
  console.log('📋 Step 1: Duplicate Detection');
  const score = await duplicateChecker.getDuplicateScore(vuln);
  
  console.log(`   Overall Score: ${score.overall}/100`);
  console.log(`   Recommendation: ${score.recommendation}\n`);

  // Step 3: Handle based on recommendation
  if (score.recommendation === 'skip') {
    console.log('❌ SKIPPING: High duplicate probability detected');
    console.log('   This finding is too similar to existing reports.');
    console.log('   Submitting would likely result in rejection.\n');
    return;
  }

  if (score.recommendation === 'review') {
    console.log('⚠️  MANUAL REVIEW REQUIRED');
    console.log('   Potential duplicate detected. Please review:');
    score.matches.forEach((match, i) => {
      console.log(`   ${i + 1}. ${match.title} (${(match.similarity * 100).toFixed(1)}% similar)`);
    });
    console.log('\n   Proceed with caution or modify your report to differentiate it.\n');
    
    // In a real implementation, you would show a UI modal here
    // For now, we'll just return
    return;
  }

  // Step 4: Proceed with submission
  console.log('✅ Step 2: Proceeding with Submission');
  console.log('   No significant duplicates found - safe to submit\n');

  // Step 5: Generate report
  console.log('📝 Step 3: Generating Report');
  const report: H1Report = {
    title: vuln.title,
    vulnerability_information: formatVulnerabilityInfo(vuln, score),
    severity_rating: vuln.severity,
    weakness_id: getWeaknessId(vuln.type),
    asset_identifier: vuln.target,
  };
  console.log(`   Title: ${report.title}`);
  console.log(`   Severity: ${report.severity_rating}\n`);

  // Step 6: Submit to HackerOne
  console.log('🚀 Step 4: Submitting to HackerOne');
  const h1Api = new HackerOneAPI({
    apiKey: process.env.HACKERONE_API_KEY || '',
    username: process.env.HACKERONE_USERNAME || '',
  });

  try {
    // Uncomment when H1 API is implemented
    // const response = await h1Api.submitReport('example-program', report);
    // console.log(`   ✅ Report submitted successfully!`);
    // console.log(`   Report ID: ${response.id}\n`);
    
    console.log('   ✅ Report ready for submission (API not yet implemented)\n');
  } catch (error) {
    console.error('   ❌ Submission failed:', error);
    return;
  }

  // Step 7: Store in database for future duplicate detection
  console.log('💾 Step 5: Storing in Database');
  const finding = {
    id: vuln.id,
    type: vuln.type,
    severity: vuln.severity,
    url: vuln.url,
    description: vuln.description,
    evidence: vuln.proof ? JSON.stringify(vuln.proof) : vuln.impact,
    timestamp: vuln.timestamp,
  };

  await duplicateChecker.store(finding);
  console.log('   ✅ Finding stored for future duplicate detection\n');

  console.log('🎉 Workflow Complete!\n');
}

/**
 * Example 3: Batch Duplicate Check for Multiple Findings
 */
export async function batchDuplicateCheck(vulnerabilities: Vulnerability[]): Promise<void> {
  console.log(`🔍 Checking ${vulnerabilities.length} findings for duplicates...\n`);

  const qdrant = new QdrantClient({
    url: process.env.QDRANT_URL || 'http://localhost:6333',
    collectionName: 'huntress_findings',
  });

  const summarizer = new FindingSummarizer(
    process.env.ANTHROPIC_API_KEY || '',
  );

  const duplicateChecker = new DuplicateChecker(
    qdrant,
    summarizer,
    0.85,
    process.env.HACKERONE_API_KEY,
    process.env.GITHUB_TOKEN
  );

  const results: { vuln: Vulnerability; score: DuplicateScore }[] = [];

  for (const vuln of vulnerabilities) {
    const score = await duplicateChecker.getDuplicateScore(vuln);
    results.push({ vuln, score });
  }

  // Categorize results
  const toSubmit = results.filter(r => r.score.recommendation === 'submit');
  const toReview = results.filter(r => r.score.recommendation === 'review');
  const toSkip = results.filter(r => r.score.recommendation === 'skip');

  console.log('📊 Batch Results:');
  console.log(`   ✅ Safe to Submit: ${toSubmit.length}`);
  console.log(`   ⚠️  Needs Review: ${toReview.length}`);
  console.log(`   ❌ Skip (Duplicates): ${toSkip.length}\n`);

  if (toSubmit.length > 0) {
    console.log('✅ Safe to Submit:');
    toSubmit.forEach(({ vuln, score }) => {
      console.log(`   - ${vuln.title} (Score: ${score.overall}/100)`);
    });
    console.log();
  }

  if (toReview.length > 0) {
    console.log('⚠️  Needs Manual Review:');
    toReview.forEach(({ vuln, score }) => {
      console.log(`   - ${vuln.title} (Score: ${score.overall}/100)`);
      console.log(`     Reason: ${score.reasoning[0]}`);
    });
    console.log();
  }

  if (toSkip.length > 0) {
    console.log('❌ Skip (Likely Duplicates):');
    toSkip.forEach(({ vuln, score }) => {
      console.log(`   - ${vuln.title} (Score: ${score.overall}/100)`);
      if (score.matches.length > 0) {
        console.log(`     Similar to: ${score.matches[0].title}`);
      }
    });
    console.log();
  }

  console.log(`💡 Time Saved: ~${toSkip.length * 2} hours (assuming 2 hours per duplicate)\n`);
}

/**
 * Helper: Format vulnerability information with duplicate check results
 */
function formatVulnerabilityInfo(vuln: Vulnerability, score: DuplicateScore): string {
  let info = `# ${vuln.title}\n\n`;
  info += `## Description\n${vuln.description}\n\n`;
  info += `## Impact\n${vuln.impact}\n\n`;
  info += `## Steps to Reproduce\n`;
  vuln.steps.forEach((step, i) => {
    info += `${i + 1}. ${step}\n`;
  });
  info += `\n## Duplicate Check\n`;
  info += `This vulnerability has been checked against known reports:\n`;
  info += `- Overall Duplicate Score: ${score.overall}/100\n`;
  info += `- HackerOne Match: ${(score.h1Match * 100).toFixed(1)}%\n`;
  info += `- GitHub Match: ${(score.githubMatch * 100).toFixed(1)}%\n`;
  info += `- Internal Match: ${(score.internalMatch * 100).toFixed(1)}%\n`;
  info += `\nRecommendation: ${score.recommendation.toUpperCase()}\n`;
  
  return info;
}

/**
 * Helper: Get CWE weakness ID from vulnerability type
 */
function getWeaknessId(type: string): number {
  const weaknessMap: Record<string, number> = {
    'oauth': 346,           // CWE-346: Origin Validation Error
    'open_redirect': 601,   // CWE-601: URL Redirection to Untrusted Site
    'ssrf': 918,           // CWE-918: Server-Side Request Forgery
    'xss': 79,             // CWE-79: Cross-site Scripting
    'sql_injection': 89,   // CWE-89: SQL Injection
    'idor': 639,           // CWE-639: Authorization Bypass
    'csrf': 352,           // CWE-352: Cross-Site Request Forgery
  };

  return weaknessMap[type.toLowerCase()] || 1035; // CWE-1035: Generic
}

/**
 * Example Usage
 */
export async function runExamples(): Promise<void> {
  // Example vulnerability
  const exampleVuln: Vulnerability = {
    id: 'vuln-001',
    type: 'oauth',
    severity: 'high',
    title: 'OAuth Redirect URI Validation Bypass',
    description: 'The OAuth implementation does not properly validate redirect_uri parameters, allowing an attacker to redirect users to malicious sites.',
    url: 'https://example.com/oauth/authorize',
    target: 'example.com',
    impact: 'An attacker can steal OAuth tokens by redirecting users to a malicious site.',
    steps: [
      'Navigate to https://example.com/oauth/authorize',
      'Modify the redirect_uri parameter to https://evil.com',
      'Complete the OAuth flow',
      'Observe that the authorization code is sent to evil.com',
    ],
    timestamp: Date.now(),
    proof: {
      screenshots: ['screenshot1.png', 'screenshot2.png'],
      logs: ['request.log', 'response.log'],
    },
  };

  console.log('═══════════════════════════════════════════════════════════');
  console.log('  DUPLICATE DETECTION SYSTEM - INTEGRATION EXAMPLES');
  console.log('═══════════════════════════════════════════════════════════\n');

  // Example 1: Basic check
  console.log('Example 1: Basic Duplicate Check\n');
  const shouldSubmit = await checkBeforeSubmission(exampleVuln);
  console.log(`\nResult: ${shouldSubmit ? 'PROCEED' : 'DO NOT SUBMIT'}\n`);
  console.log('───────────────────────────────────────────────────────────\n');

  // Example 2: Complete workflow
  console.log('Example 2: Complete Reporting Workflow\n');
  await completeReportingWorkflow(exampleVuln);
  console.log('───────────────────────────────────────────────────────────\n');

  // Example 3: Batch check
  console.log('Example 3: Batch Duplicate Check\n');
  const batchVulns = [exampleVuln, { ...exampleVuln, id: 'vuln-002' }];
  await batchDuplicateCheck(batchVulns);
  console.log('───────────────────────────────────────────────────────────\n');

  console.log('✅ All examples completed!\n');
}

// Run examples if executed directly
if (require.main === module) {
  runExamples().catch(console.error);
}