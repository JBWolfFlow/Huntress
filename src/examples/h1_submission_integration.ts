/**
 * HackerOne One-Click Submission Integration Example
 * 
 * Complete workflow demonstrating:
 * - Report generation with PoCGenerator
 * - Duplicate detection
 * - Severity prediction
 * - Attachment upload
 * - One-click submission to HackerOne
 * - Status tracking
 */

import { QdrantClient } from '../core/memory/qdrant_client';
import { FindingSummarizer } from '../core/memory/summarizer';
import { PoCGenerator, type ProgramGuidelines } from '../core/reporting/poc_generator';
import { HackerOneAPI, type H1Report, type Attachment } from '../core/reporting/h1_api';
import type { Vulnerability } from '../utils/duplicate_checker';
import * as path from 'path';

/**
 * Example 1: Basic One-Click Submission
 */
export async function basicSubmission(vuln: Vulnerability, programHandle: string): Promise<void> {
  console.log('🚀 Example 1: Basic One-Click Submission\n');

  // 1. Initialize components
  const qdrant = new QdrantClient({
    url: process.env.QDRANT_URL || 'http://localhost:6333',
    collectionName: 'huntress_findings',
  });

  const summarizer = new FindingSummarizer(
    process.env.ANTHROPIC_API_KEY || ''
  );

  const generator = new PoCGenerator(
    qdrant,
    summarizer,
    process.env.HACKERONE_API_TOKEN,
    process.env.GITHUB_TOKEN
  );

  const h1Api = new HackerOneAPI({
    username: process.env.HACKERONE_API_USERNAME || '',
    apiToken: process.env.HACKERONE_API_TOKEN || '',
  });

  try {
    // 2. Generate report (includes duplicate check and severity prediction)
    console.log('📝 Generating report...');
    const report = await generator.generateReport(vuln);
    
    console.log(`\n✓ Report generated:`);
    console.log(`   Title: ${report.title}`);
    console.log(`   Severity: ${report.severity}`);
    console.log(`   Bounty: $${report.suggestedBounty.min} - $${report.suggestedBounty.max}`);
    
    if (report.duplicateCheck) {
      console.log(`   Duplicate Score: ${report.duplicateCheck.overall}/100`);
      console.log(`   Recommendation: ${report.duplicateCheck.recommendation}`);
    }

    // 3. Prepare attachments
    const attachments: Attachment[] = [];
    
    if (report.proof.video) {
      attachments.push({
        type: 'video',
        path: report.proof.video,
      });
    }
    
    if (report.proof.screenshots) {
      report.proof.screenshots.forEach(screenshot => {
        attachments.push({
          type: 'screenshot',
          path: screenshot,
        });
      });
    }
    
    if (report.proof.logs) {
      report.proof.logs.forEach(log => {
        attachments.push({
          type: 'log',
          path: log,
        });
      });
    }

    // 4. Submit to HackerOne
    console.log(`\n🚀 Submitting to ${programHandle}...`);
    const result = await h1Api.submitReport({
      programHandle,
      report,
      attachments,
    });

    if (result.success) {
      console.log(`\n✅ SUCCESS!`);
      console.log(`   Report ID: ${result.reportId}`);
      console.log(`   Report URL: ${result.reportUrl}`);
      console.log(`   Status: ${result.status}`);
      console.log(`   Attachments: ${result.attachmentIds?.length || 0} uploaded`);
    } else {
      console.error(`\n❌ FAILED: ${result.error}`);
    }
  } catch (error: any) {
    console.error(`\n❌ Error: ${error.message}`);
  }
}

/**
 * Example 2: Submission with Program Guidelines
 */
export async function submissionWithGuidelines(
  vuln: Vulnerability,
  programHandle: string,
  guidelines: ProgramGuidelines
): Promise<void> {
  console.log('🚀 Example 2: Submission with Program Guidelines\n');

  const qdrant = new QdrantClient({
    url: process.env.QDRANT_URL || 'http://localhost:6333',
    collectionName: 'huntress_findings',
  });

  const summarizer = new FindingSummarizer(
    process.env.ANTHROPIC_API_KEY || ''
  );

  const generator = new PoCGenerator(
    qdrant,
    summarizer,
    process.env.HACKERONE_API_TOKEN,
    process.env.GITHUB_TOKEN
  );

  const h1Api = new HackerOneAPI({
    username: process.env.HACKERONE_API_USERNAME || '',
    apiToken: process.env.HACKERONE_API_TOKEN || '',
  });

  try {
    // Set program-specific guidelines
    generator.setProgramGuidelines(guidelines);
    
    console.log(`📋 Using guidelines for: ${guidelines.programName}`);
    if (guidelines.bountyRanges) {
      console.log(`   Bounty ranges configured`);
    }

    // Generate report with program context
    console.log('\n📝 Generating report...');
    const report = await generator.generateReport(vuln, {
      programGuidelines: guidelines,
    });

    console.log(`\n✓ Report generated with program-specific context`);
    console.log(`   Severity: ${report.severity}`);
    console.log(`   Suggested Bounty: $${report.suggestedBounty.min} - $${report.suggestedBounty.max}`);

    // Submit
    console.log(`\n🚀 Submitting to ${programHandle}...`);
    const result = await h1Api.submitReport({
      programHandle,
      report,
    });

    if (result.success) {
      console.log(`\n✅ Report submitted: ${result.reportUrl}`);
    }
  } catch (error: any) {
    console.error(`\n❌ Error: ${error.message}`);
  }
}

/**
 * Example 3: Batch Submission with Status Tracking
 */
export async function batchSubmission(
  vulnerabilities: Vulnerability[],
  programHandle: string
): Promise<void> {
  console.log(`🚀 Example 3: Batch Submission (${vulnerabilities.length} findings)\n`);

  const qdrant = new QdrantClient({
    url: process.env.QDRANT_URL || 'http://localhost:6333',
    collectionName: 'huntress_findings',
  });

  const summarizer = new FindingSummarizer(
    process.env.ANTHROPIC_API_KEY || ''
  );

  const generator = new PoCGenerator(
    qdrant,
    summarizer,
    process.env.HACKERONE_API_TOKEN,
    process.env.GITHUB_TOKEN
  );

  const h1Api = new HackerOneAPI({
    username: process.env.HACKERONE_API_USERNAME || '',
    apiToken: process.env.HACKERONE_API_TOKEN || '',
  });

  const results: Array<{
    vuln: Vulnerability;
    success: boolean;
    reportId?: string;
    error?: string;
  }> = [];

  for (let i = 0; i < vulnerabilities.length; i++) {
    const vuln = vulnerabilities[i];
    console.log(`\n[${i + 1}/${vulnerabilities.length}] Processing: ${vuln.title}`);

    try {
      // Generate report
      const report = await generator.generateReport(vuln);
      
      // Check duplicate recommendation
      if (report.duplicateCheck?.recommendation === 'skip') {
        console.log(`   ⏭️  Skipped (duplicate detected)`);
        results.push({
          vuln,
          success: false,
          error: 'Duplicate detected',
        });
        continue;
      }

      // Submit
      const result = await h1Api.submitReport({
        programHandle,
        report,
      });

      if (result.success) {
        console.log(`   ✅ Submitted: ${result.reportId}`);
        results.push({
          vuln,
          success: true,
          reportId: result.reportId,
        });
      } else {
        console.log(`   ❌ Failed: ${result.error}`);
        results.push({
          vuln,
          success: false,
          error: result.error,
        });
      }

      // Rate limiting - wait 2 seconds between submissions
      if (i < vulnerabilities.length - 1) {
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    } catch (error: any) {
      console.log(`   ❌ Error: ${error.message}`);
      results.push({
        vuln,
        success: false,
        error: error.message,
      });
    }
  }

  // Summary
  const successful = results.filter(r => r.success).length;
  const failed = results.filter(r => !r.success).length;

  console.log(`\n📊 Batch Submission Summary:`);
  console.log(`   ✅ Successful: ${successful}`);
  console.log(`   ❌ Failed: ${failed}`);
  console.log(`   📈 Success Rate: ${((successful / results.length) * 100).toFixed(1)}%`);

  if (successful > 0) {
    console.log(`\n✅ Successfully Submitted:`);
    results
      .filter(r => r.success)
      .forEach(r => {
        console.log(`   - ${r.vuln.title} (${r.reportId})`);
      });
  }

  if (failed > 0) {
    console.log(`\n❌ Failed Submissions:`);
    results
      .filter(r => !r.success)
      .forEach(r => {
        console.log(`   - ${r.vuln.title}: ${r.error}`);
      });
  }
}

/**
 * Example 4: Complete Workflow with Status Tracking
 */
export async function completeWorkflowWithTracking(
  vuln: Vulnerability,
  programHandle: string
): Promise<void> {
  console.log('🚀 Example 4: Complete Workflow with Status Tracking\n');

  const qdrant = new QdrantClient({
    url: process.env.QDRANT_URL || 'http://localhost:6333',
    collectionName: 'huntress_findings',
  });

  const summarizer = new FindingSummarizer(
    process.env.ANTHROPIC_API_KEY || ''
  );

  const generator = new PoCGenerator(
    qdrant,
    summarizer,
    process.env.HACKERONE_API_TOKEN,
    process.env.GITHUB_TOKEN
  );

  const h1Api = new HackerOneAPI({
    username: process.env.HACKERONE_API_USERNAME || '',
    apiToken: process.env.HACKERONE_API_TOKEN || '',
  });

  try {
    // Step 1: Generate report
    console.log('📝 Step 1: Generating report...');
    const report = await generator.generateReport(vuln);
    console.log(`   ✓ Report generated`);

    // Step 2: Review duplicate check
    if (report.duplicateCheck) {
      console.log(`\n🔍 Step 2: Duplicate Check`);
      console.log(`   Score: ${report.duplicateCheck.overall}/100`);
      console.log(`   Recommendation: ${report.duplicateCheck.recommendation}`);
      
      if (report.duplicateCheck.recommendation === 'skip') {
        console.log(`\n❌ Stopping: High duplicate probability`);
        return;
      }
    }

    // Step 3: Review severity prediction
    console.log(`\n📊 Step 3: Severity Assessment`);
    console.log(`   Severity: ${report.severity}`);
    console.log(`   Bounty: $${report.suggestedBounty.min} - $${report.suggestedBounty.max}`);
    if (report.cvssScore) {
      console.log(`   CVSS: ${report.cvssScore}`);
    }

    // Step 4: Submit
    console.log(`\n🚀 Step 4: Submitting to HackerOne...`);
    const result = await h1Api.submitReport({
      programHandle,
      report,
    });

    if (!result.success) {
      console.error(`\n❌ Submission failed: ${result.error}`);
      return;
    }

    console.log(`\n✅ Step 5: Report Submitted!`);
    console.log(`   Report ID: ${result.reportId}`);
    console.log(`   URL: ${result.reportUrl}`);

    // Step 6: Track status
    console.log(`\n📡 Step 6: Tracking Status...`);
    const reportId = result.reportId!;
    
    // Check status immediately
    let status = await h1Api.getReportStatus(reportId);
    console.log(`   Initial Status: ${status.state}`);

    // Check again after 30 seconds (in real usage, you'd poll periodically)
    console.log(`\n   Waiting 30 seconds before checking again...`);
    await new Promise(resolve => setTimeout(resolve, 30000));
    
    status = await h1Api.getReportStatus(reportId);
    console.log(`   Updated Status: ${status.state}`);
    
    if (status.triageAt) {
      console.log(`   ✓ Triaged at: ${status.triageAt}`);
    }

    console.log(`\n🎉 Workflow Complete!`);
  } catch (error: any) {
    console.error(`\n❌ Error: ${error.message}`);
  }
}

/**
 * Example 5: Test API Connection
 */
export async function testConnection(): Promise<void> {
  console.log('🔌 Example 5: Testing HackerOne API Connection\n');

  const h1Api = new HackerOneAPI({
    username: process.env.HACKERONE_API_USERNAME || '',
    apiToken: process.env.HACKERONE_API_TOKEN || '',
  });

  try {
    const connected = await h1Api.testConnection();
    
    if (connected) {
      console.log('✅ Connection successful!');
      
      const userInfo = await h1Api.getUserInfo();
      console.log(`\nUser Information:`);
      console.log(`   Username: ${userInfo.attributes.username}`);
      console.log(`   Name: ${userInfo.attributes.name}`);
      console.log(`   Reputation: ${userInfo.attributes.reputation}`);
    } else {
      console.log('❌ Connection failed');
    }
  } catch (error: any) {
    console.error(`❌ Error: ${error.message}`);
  }
}

/**
 * Run all examples
 */
export async function runAllExamples(): Promise<void> {
  // Example vulnerability
  const exampleVuln: Vulnerability = {
    id: 'vuln-oauth-001',
    type: 'oauth_misconfiguration',
    severity: 'high',
    title: 'OAuth Redirect URI Validation Bypass in Authorization Flow',
    description: 'The OAuth 2.0 implementation does not properly validate the redirect_uri parameter during the authorization flow. An attacker can manipulate this parameter to redirect users to a malicious site, potentially stealing authorization codes and access tokens.',
    url: 'https://api.example.com/oauth/authorize',
    target: 'api.example.com',
    impact: 'An attacker can steal OAuth tokens by redirecting users to a malicious site during the authorization flow. This could lead to account takeover, unauthorized access to user data, and potential privilege escalation.',
    steps: [
      'Navigate to https://api.example.com/oauth/authorize?client_id=CLIENT_ID&redirect_uri=https://example.com/callback',
      'Modify the redirect_uri parameter to https://evil.com/steal',
      'Complete the OAuth authorization flow',
      'Observe that the authorization code is sent to evil.com instead of the legitimate callback URL',
      'Use the stolen authorization code to obtain an access token',
    ],
    timestamp: Date.now(),
    proof: {
      video: path.join(process.cwd(), 'recordings', 'oauth-bypass.mp4'),
      screenshots: [
        path.join(process.cwd(), 'recordings', 'oauth-step1.png'),
        path.join(process.cwd(), 'recordings', 'oauth-step2.png'),
      ],
      logs: [
        path.join(process.cwd(), 'recordings', 'oauth-session.cast'),
      ],
    },
  };

  // Example program guidelines
  const exampleGuidelines: ProgramGuidelines = {
    programHandle: 'example-corp',
    programName: 'Example Corp Bug Bounty',
    bountyRanges: {
      critical: { min: 10000, max: 50000 },
      high: { min: 5000, max: 15000 },
      medium: { min: 1000, max: 5000 },
      low: { min: 100, max: 1000 },
    },
  };

  console.log('═══════════════════════════════════════════════════════════');
  console.log('  HACKERONE ONE-CLICK SUBMISSION - INTEGRATION EXAMPLES');
  console.log('═══════════════════════════════════════════════════════════\n');

  // Example 1: Test connection
  await testConnection();
  console.log('\n───────────────────────────────────────────────────────────\n');

  // Example 2: Basic submission (commented out to avoid actual submission)
  // await basicSubmission(exampleVuln, 'example-corp');
  console.log('Example 2: Basic Submission (commented out - uncomment to test)');
  console.log('───────────────────────────────────────────────────────────\n');

  // Example 3: Submission with guidelines (commented out)
  // await submissionWithGuidelines(exampleVuln, 'example-corp', exampleGuidelines);
  console.log('Example 3: Submission with Guidelines (commented out - uncomment to test)');
  console.log('───────────────────────────────────────────────────────────\n');

  console.log('✅ Examples ready to run!');
  console.log('\nTo test actual submissions:');
  console.log('1. Configure your .env file with HackerOne credentials');
  console.log('2. Uncomment the example functions above');
  console.log('3. Run: ts-node src/examples/h1_submission_integration.ts\n');
}

// Run examples if executed directly
if (require.main === module) {
  runAllExamples().catch(console.error);
}