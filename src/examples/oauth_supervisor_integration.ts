/**
 * OAuth Hunter + CrewAI Supervisor Integration Example
 * 
 * Demonstrates how to use the OAuth Hunter through the CrewAI supervisor
 * with human-in-the-loop approval for risky operations.
 */

import { Supervisor, ExecutionConfig } from '../core/crewai';
import { HumanTaskRequest, HumanTaskResponse } from '../core/crewai/human_task';
import { OAuthVulnerability } from '../agents/oauth';

/**
 * Example 1: Basic OAuth Hunt with Human Approval
 */
export async function basicOAuthHunt() {
  console.log('=== Example 1: Basic OAuth Hunt ===\n');

  // Create supervisor with human-in-the-loop enabled
  const supervisor = new Supervisor({
    humanInTheLoop: true,
    maxIterations: 10,
    timeout: 3600000, // 1 hour
  });

  // Define approval callback (in real app, this would show a modal)
  const onApprovalRequired = async (request: HumanTaskRequest): Promise<HumanTaskResponse> => {
    console.log(`\n[APPROVAL REQUIRED]`);
    console.log(`Title: ${request.title}`);
    console.log(`Description: ${request.description}`);
    console.log(`Severity: ${request.severity}`);
    console.log(`Context:`, JSON.stringify(request.context, null, 2));

    // In a real application, this would show a modal and wait for user input
    // For this example, we'll auto-approve
    return {
      taskId: request.id,
      approved: true,
      timestamp: Date.now(),
    };
  };

  // Execute OAuth hunt
  const config: ExecutionConfig = {
    target: 'api.example.com',
    scope: ['*.example.com', 'api.example.com'],
    oauthConfig: {
      target: 'api.example.com',
      clientId: 'example_client_id',
      redirectUri: 'https://example.com/callback',
      collaboratorUrl: 'https://collaborator.example.com',
      knownScopes: ['read', 'write', 'admin'],
    },
    onApprovalRequired,
  };

  try {
    const result = await supervisor.execute(config);

    console.log('\n=== Hunt Results ===');
    console.log(`Success: ${result.success}`);
    console.log(`Duration: ${result.duration}ms`);
    console.log(`Tasks: ${result.tasks.length}`);
    console.log(`Vulnerabilities: ${result.vulnerabilities.length}`);

    if (result.vulnerabilities.length > 0) {
      console.log('\n=== Vulnerabilities Found ===');
      result.vulnerabilities.forEach((vuln: OAuthVulnerability, index: number) => {
        console.log(`\n${index + 1}. ${vuln.type} (${vuln.severity})`);
        console.log(`   Endpoint: ${vuln.endpoint}`);
        console.log(`   Description: ${vuln.description}`);
      });
    }

    return result;
  } catch (error) {
    console.error('Hunt failed:', error);
    throw error;
  }
}

/**
 * Example 2: OAuth Hunt with Custom Approval Logic
 */
export async function customApprovalLogic() {
  console.log('\n=== Example 2: Custom Approval Logic ===\n');

  const supervisor = new Supervisor({
    humanInTheLoop: true,
  });

  // Custom approval logic: auto-approve low/medium, require human for high/critical
  const onApprovalRequired = async (request: HumanTaskRequest): Promise<HumanTaskResponse> => {
    console.log(`\n[APPROVAL REQUEST] ${request.title} (${request.severity})`);

    // Auto-approve low and medium severity
    if (request.severity === 'low' || request.severity === 'medium') {
      console.log('✓ Auto-approved (low/medium severity)');
      return {
        taskId: request.id,
        approved: true,
        timestamp: Date.now(),
      };
    }

    // Require human approval for high/critical
    console.log('⚠ Requires human approval (high/critical severity)');
    console.log(`Context:`, JSON.stringify(request.context, null, 2));

    // In real app, show modal and wait for user decision
    // For demo, we'll approve after logging
    return {
      taskId: request.id,
      approved: true,
      feedback: 'Approved after review',
      timestamp: Date.now(),
    };
  };

  const config: ExecutionConfig = {
    target: 'oauth.example.com',
    oauthConfig: {
      target: 'oauth.example.com',
      clientId: 'test_client',
      redirectUri: 'https://app.example.com/callback',
    },
    onApprovalRequired,
  };

  const result = await supervisor.execute(config);
  console.log(`\nCompleted with ${result.vulnerabilities.length} vulnerabilities`);
  return result;
}

/**
 * Example 3: OAuth Hunt with Specific Test Types
 */
export async function specificTestTypes() {
  console.log('\n=== Example 3: Specific Test Types ===\n');

  const supervisor = new Supervisor({
    humanInTheLoop: true,
  });

  // Register OAuth agent manually for more control
  supervisor.registerOAuthAgent('oauth', {
    target: 'auth.example.com',
    clientId: 'client_123',
    redirectUri: 'https://app.example.com/oauth/callback',
    humanInTheLoop: true,
    autoApprove: false, // Require approval for all operations
    maxRetries: 3,
    retryDelay: 1000,
  });

  // Set approval callback
  supervisor.setHumanTaskCallback(async (request) => {
    console.log(`\n[${request.type.toUpperCase()}] ${request.title}`);
    return {
      taskId: request.id,
      approved: true,
      timestamp: Date.now(),
    };
  });

  // Get the registered agent
  const agents = supervisor.getAgents();
  const oauthAgent = agents.get('oauth');

  if (oauthAgent) {
    console.log('Testing specific vulnerability types...\n');

    // Test redirect URI vulnerabilities
    console.log('1. Testing redirect URI vulnerabilities...');
    const redirectVulns = await oauthAgent.testVulnerabilityType('redirect');
    console.log(`   Found ${redirectVulns.length} redirect vulnerabilities`);

    // Test state parameter vulnerabilities
    console.log('2. Testing state parameter vulnerabilities...');
    const stateVulns = await oauthAgent.testVulnerabilityType('state');
    console.log(`   Found ${stateVulns.length} state vulnerabilities`);

    // Test PKCE implementation
    console.log('3. Testing PKCE implementation...');
    const pkceVulns = await oauthAgent.testVulnerabilityType('pkce');
    console.log(`   Found ${pkceVulns.length} PKCE vulnerabilities`);

    // Test scope parameter
    console.log('4. Testing scope parameter...');
    const scopeVulns = await oauthAgent.testVulnerabilityType('scope');
    console.log(`   Found ${scopeVulns.length} scope vulnerabilities`);

    const allVulns = [...redirectVulns, ...stateVulns, ...pkceVulns, ...scopeVulns];
    console.log(`\nTotal vulnerabilities found: ${allVulns.length}`);

    return allVulns;
  }

  throw new Error('OAuth agent not registered');
}

/**
 * Example 4: Error Handling and Retry Logic
 */
export async function errorHandlingExample() {
  console.log('\n=== Example 4: Error Handling ===\n');

  const supervisor = new Supervisor({
    humanInTheLoop: true,
  });

  const config: ExecutionConfig = {
    target: 'unreachable.example.com',
    oauthConfig: {
      target: 'unreachable.example.com',
      maxRetries: 3,
      retryDelay: 1000,
    },
    onApprovalRequired: async (request) => ({
      taskId: request.id,
      approved: true,
      timestamp: Date.now(),
    }),
  };

  try {
    const result = await supervisor.execute(config);

    if (!result.success) {
      console.log('Hunt failed as expected');
      console.log(`Error: ${result.error}`);
      console.log(`Tasks attempted: ${result.tasks.length}`);
      
      result.tasks.forEach((task, index) => {
        console.log(`\nTask ${index + 1}:`);
        console.log(`  Type: ${task.type}`);
        console.log(`  Status: ${task.status}`);
        if (task.error) {
          console.log(`  Error: ${task.error}`);
        }
      });
    }

    return result;
  } catch (error) {
    console.error('Caught error:', error);
    throw error;
  }
}

/**
 * Example 5: Generate Reports for Findings
 */
export async function generateReports() {
  console.log('\n=== Example 5: Generate Reports ===\n');

  const supervisor = new Supervisor({
    humanInTheLoop: true,
  });

  supervisor.registerOAuthAgent('oauth', {
    target: 'api.example.com',
    clientId: 'test_client',
    redirectUri: 'https://app.example.com/callback',
  });

  supervisor.setHumanTaskCallback(async (request) => ({
    taskId: request.id,
    approved: true,
    timestamp: Date.now(),
  }));

  const agents = supervisor.getAgents();
  const oauthAgent = agents.get('oauth');

  if (oauthAgent) {
    // Execute hunt
    const result = await oauthAgent.executeHunt();

    // Generate reports for each vulnerability
    if (result.vulnerabilities.length > 0) {
      console.log(`Generating reports for ${result.vulnerabilities.length} vulnerabilities...\n`);

      result.vulnerabilities.forEach((vuln, index) => {
        console.log(`\n${'='.repeat(60)}`);
        console.log(`Report ${index + 1}/${result.vulnerabilities.length}`);
        console.log('='.repeat(60));
        
        const report = oauthAgent.generateReport(vuln);
        console.log(report);
      });
    } else {
      console.log('No vulnerabilities found to report');
    }

    return result;
  }

  throw new Error('OAuth agent not registered');
}

/**
 * Run all examples
 */
export async function runAllExamples() {
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║  OAuth Hunter + CrewAI Supervisor Integration Examples    ║');
  console.log('╚════════════════════════════════════════════════════════════╝\n');

  try {
    // Example 1: Basic hunt
    await basicOAuthHunt();
    
    // Example 2: Custom approval logic
    await customApprovalLogic();
    
    // Example 3: Specific test types
    await specificTestTypes();
    
    // Example 4: Error handling
    await errorHandlingExample();
    
    // Example 5: Generate reports
    await generateReports();

    console.log('\n✓ All examples completed successfully');
  } catch (error) {
    console.error('\n✗ Example failed:', error);
    throw error;
  }
}

// Export all examples
export default {
  basicOAuthHunt,
  customApprovalLogic,
  specificTestTypes,
  errorHandlingExample,
  generateReports,
  runAllExamples,
};