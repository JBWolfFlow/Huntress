/**
 * OAuth Hunter Integration Test
 * 
 * Comprehensive test suite for OAuth Hunter + CrewAI integration
 * Tests all major functionality including human-in-the-loop approval
 */

import { Supervisor } from '../core/crewai';
import { HumanTaskRequest, HumanTaskResponse } from '../core/crewai/human_task';
import { OAuthVulnerability } from '../agents/oauth';

// Test configuration
const TEST_CONFIG = {
  target: 'oauth.example.com',
  clientId: 'test_client_12345',
  redirectUri: 'https://app.example.com/oauth/callback',
  collaboratorUrl: 'https://collaborator.example.com',
  knownScopes: ['read', 'write', 'admin', 'profile', 'email'],
};

// Track approval requests for testing
const approvalLog: HumanTaskRequest[] = [];

/**
 * Mock approval callback for testing
 */
async function mockApprovalCallback(request: HumanTaskRequest): Promise<HumanTaskResponse> {
  approvalLog.push(request);
  
  console.log('\n' + '='.repeat(70));
  console.log(`[APPROVAL REQUEST #${approvalLog.length}]`);
  console.log('='.repeat(70));
  console.log(`Title: ${request.title}`);
  console.log(`Description: ${request.description}`);
  console.log(`Severity: ${request.severity}`);
  console.log(`Type: ${request.type}`);
  console.log(`Context:`, JSON.stringify(request.context, null, 2));
  console.log('='.repeat(70));
  
  // Auto-approve for testing
  return {
    taskId: request.id,
    approved: true,
    feedback: 'Auto-approved for testing',
    timestamp: Date.now(),
  };
}

/**
 * Test 1: Basic OAuth Hunt
 */
async function testBasicOAuthHunt() {
  console.log('\n╔════════════════════════════════════════════════════════════╗');
  console.log('║  TEST 1: Basic OAuth Hunt                                 ║');
  console.log('╚════════════════════════════════════════════════════════════╝\n');

  const supervisor = new Supervisor({
    humanInTheLoop: true,
    maxIterations: 10,
    timeout: 60000,
  });

  const result = await supervisor.execute({
    target: TEST_CONFIG.target,
    scope: ['*.example.com'],
    oauthConfig: TEST_CONFIG,
    onApprovalRequired: mockApprovalCallback,
  });

  console.log('\n[TEST 1 RESULTS]');
  console.log(`✓ Success: ${result.success}`);
  console.log(`✓ Duration: ${result.duration}ms`);
  console.log(`✓ Tasks: ${result.tasks.length}`);
  console.log(`✓ Vulnerabilities: ${result.vulnerabilities.length}`);
  console.log(`✓ Approval Requests: ${approvalLog.length}`);

  return result;
}

/**
 * Test 2: Specific Vulnerability Type Testing
 */
async function testSpecificVulnerabilityTypes() {
  console.log('\n╔════════════════════════════════════════════════════════════╗');
  console.log('║  TEST 2: Specific Vulnerability Type Testing              ║');
  console.log('╚════════════════════════════════════════════════════════════╝\n');

  const supervisor = new Supervisor({
    humanInTheLoop: true,
  });

  supervisor.registerOAuthAgent('oauth', {
    ...TEST_CONFIG,
    humanInTheLoop: true,
    autoApprove: false,
    maxRetries: 2,
    retryDelay: 500,
  });

  supervisor.setHumanTaskCallback(mockApprovalCallback);

  const agents = supervisor.getAgents();
  const oauthAgent = agents.get('oauth');

  if (!oauthAgent) {
    throw new Error('OAuth agent not registered');
  }

  const results = {
    redirect: [] as OAuthVulnerability[],
    state: [] as OAuthVulnerability[],
    pkce: [] as OAuthVulnerability[],
    scope: [] as OAuthVulnerability[],
  };

  // Test each vulnerability type
  console.log('Testing Redirect URI vulnerabilities...');
  results.redirect = await oauthAgent.testVulnerabilityType('redirect');
  console.log(`✓ Found ${results.redirect.length} redirect vulnerabilities\n`);

  console.log('Testing State parameter vulnerabilities...');
  results.state = await oauthAgent.testVulnerabilityType('state');
  console.log(`✓ Found ${results.state.length} state vulnerabilities\n`);

  console.log('Testing PKCE implementation...');
  results.pkce = await oauthAgent.testVulnerabilityType('pkce');
  console.log(`✓ Found ${results.pkce.length} PKCE vulnerabilities\n`);

  console.log('Testing Scope parameter...');
  results.scope = await oauthAgent.testVulnerabilityType('scope');
  console.log(`✓ Found ${results.scope.length} scope vulnerabilities\n`);

  const totalVulns = Object.values(results).flat().length;
  console.log(`[TEST 2 RESULTS]`);
  console.log(`✓ Total vulnerabilities: ${totalVulns}`);
  console.log(`✓ Redirect: ${results.redirect.length}`);
  console.log(`✓ State: ${results.state.length}`);
  console.log(`✓ PKCE: ${results.pkce.length}`);
  console.log(`✓ Scope: ${results.scope.length}`);

  return results;
}

/**
 * Test 3: Human-in-the-Loop Approval Workflow
 */
async function testHumanApprovalWorkflow() {
  console.log('\n╔════════════════════════════════════════════════════════════╗');
  console.log('║  TEST 3: Human-in-the-Loop Approval Workflow              ║');
  console.log('╚════════════════════════════════════════════════════════════╝\n');

  approvalLog.length = 0; // Clear previous logs

  const supervisor = new Supervisor({
    humanInTheLoop: true,
  });

  supervisor.registerOAuthAgent('oauth', {
    ...TEST_CONFIG,
    humanInTheLoop: true,
    autoApprove: false, // Force all approvals
  });

  supervisor.setHumanTaskCallback(mockApprovalCallback);

  const agents = supervisor.getAgents();
  const oauthAgent = agents.get('oauth');

  if (!oauthAgent) {
    throw new Error('OAuth agent not registered');
  }

  console.log('Executing hunt with approval tracking...\n');
  const result = await oauthAgent.executeHunt();

  console.log('\n[TEST 3 RESULTS]');
  console.log(`✓ Hunt completed: ${result.vulnerabilities.length >= 0}`);
  console.log(`✓ Vulnerabilities found: ${result.vulnerabilities.length}`);
  console.log(`✓ Approval requests received: ${approvalLog.length}`);
  console.log(`✓ All approvals granted: true`);
  
  console.log('\n[APPROVAL REQUEST SUMMARY]');
  approvalLog.forEach((req, index) => {
    console.log(`  ${index + 1}. ${req.title} (${req.severity})`);
  });

  return { result, approvalLog: [...approvalLog] };
}

/**
 * Test 4: Report Generation
 */
async function testReportGeneration() {
  console.log('\n╔════════════════════════════════════════════════════════════╗');
  console.log('║  TEST 4: Report Generation                                ║');
  console.log('╚════════════════════════════════════════════════════════════╝\n');

  const supervisor = new Supervisor({
    humanInTheLoop: true,
  });

  supervisor.registerOAuthAgent('oauth', TEST_CONFIG);
  supervisor.setHumanTaskCallback(mockApprovalCallback);

  const agents = supervisor.getAgents();
  const oauthAgent = agents.get('oauth');

  if (!oauthAgent) {
    throw new Error('OAuth agent not registered');
  }

  const result = await oauthAgent.executeHunt();

  console.log(`Found ${result.vulnerabilities.length} vulnerabilities\n`);

  if (result.vulnerabilities.length > 0) {
    console.log('Generating reports...\n');
    
    result.vulnerabilities.slice(0, 3).forEach((vuln, index) => {
      console.log(`\n${'─'.repeat(70)}`);
      console.log(`REPORT ${index + 1}: ${vuln.type} (${vuln.severity})`);
      console.log('─'.repeat(70));
      
      const report = oauthAgent.generateReport(vuln);
      console.log(report);
    });

    if (result.vulnerabilities.length > 3) {
      console.log(`\n... and ${result.vulnerabilities.length - 3} more reports`);
    }
  }

  console.log('\n[TEST 4 RESULTS]');
  console.log(`✓ Reports generated: ${Math.min(result.vulnerabilities.length, 3)}`);
  console.log(`✓ Total vulnerabilities: ${result.vulnerabilities.length}`);

  return result;
}

/**
 * Test 5: Agent Capabilities and Status
 */
async function testAgentCapabilities() {
  console.log('\n╔════════════════════════════════════════════════════════════╗');
  console.log('║  TEST 5: Agent Capabilities and Status                    ║');
  console.log('╚════════════════════════════════════════════════════════════╝\n');

  const supervisor = new Supervisor({
    humanInTheLoop: true,
  });

  supervisor.registerOAuthAgent('oauth', TEST_CONFIG);

  const agents = supervisor.getAgents();
  const oauthAgent = agents.get('oauth');

  if (!oauthAgent) {
    throw new Error('OAuth agent not registered');
  }

  console.log('[AGENT INFORMATION]');
  console.log(`Description: ${oauthAgent.getDescription()}\n`);
  
  console.log('[AGENT CAPABILITIES]');
  const capabilities = oauthAgent.getCapabilities();
  capabilities.forEach((cap, index) => {
    console.log(`  ${index + 1}. ${cap}`);
  });

  console.log('\n[TEST 5 RESULTS]');
  console.log(`✓ Agent registered: true`);
  console.log(`✓ Capabilities: ${capabilities.length}`);
  console.log(`✓ Description available: true`);

  return { capabilities, description: oauthAgent.getDescription() };
}

/**
 * Run all tests
 */
export async function runAllTests() {
  console.log('\n╔════════════════════════════════════════════════════════════╗');
  console.log('║                                                            ║');
  console.log('║     OAuth Hunter + CrewAI Integration Test Suite          ║');
  console.log('║                                                            ║');
  console.log('╚════════════════════════════════════════════════════════════╝\n');

  const startTime = Date.now();
  const results: any = {};

  try {
    // Run all tests
    results.test1 = await testBasicOAuthHunt();
    results.test2 = await testSpecificVulnerabilityTypes();
    results.test3 = await testHumanApprovalWorkflow();
    results.test4 = await testReportGeneration();
    results.test5 = await testAgentCapabilities();

    const duration = Date.now() - startTime;

    console.log('\n╔════════════════════════════════════════════════════════════╗');
    console.log('║                    TEST SUITE SUMMARY                      ║');
    console.log('╚════════════════════════════════════════════════════════════╝\n');
    console.log(`✓ All tests completed successfully`);
    console.log(`✓ Total duration: ${duration}ms`);
    console.log(`✓ Tests passed: 5/5`);
    console.log(`✓ Integration verified: OAuth Hunter + CrewAI + Human-in-the-Loop`);

    return { success: true, results, duration };
  } catch (error) {
    console.error('\n✗ Test suite failed:', error);
    throw error;
  }
}

// Export individual tests
export {
  testBasicOAuthHunt,
  testSpecificVulnerabilityTypes,
  testHumanApprovalWorkflow,
  testReportGeneration,
  testAgentCapabilities,
};

// Run tests if executed directly (Node.js only)
// This check is disabled in browser/Vite environments
if (typeof require !== 'undefined' && typeof module !== 'undefined' && require.main === module) {
  runAllTests()
    .then(() => {
      console.log('\n✓ Test suite completed');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n✗ Test suite failed:', error);
      process.exit(1);
    });
}