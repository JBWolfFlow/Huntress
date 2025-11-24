# OAuth Hunter + CrewAI Supervisor Integration

This document describes the integration between the OAuth Hunter and the CrewAI Supervisor system, enabling human-in-the-loop approval and strategic coordination for OAuth vulnerability testing.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    CrewAI Supervisor                        │
│  - Coordinates agents                                       │
│  - Manages execution flow                                   │
│  - Handles human approval requests                          │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ├──────────────────────────────────────────┐
                  │                                          │
         ┌────────▼────────┐                    ┌───────────▼──────────┐
         │  OAuth Agent    │                    │  Human Task Manager  │
         │  - Wraps OAuth  │◄───────────────────┤  - Approval requests │
         │    Hunter       │                    │  - User callbacks    │
         │  - Approval     │                    │  - Task tracking     │
         │    checks       │                    └──────────────────────┘
         └────────┬────────┘
                  │
         ┌────────▼────────┐
         │  OAuth Hunter   │
         │  - Discovery    │
         │  - Redirect     │
         │  - State        │
         │  - PKCE         │
         │  - Scope        │
         └─────────────────┘
```

## Components

### 1. OAuth Agent (`src/core/crewai/oauth_agent.ts`)

The OAuth Agent wraps the OAuth Hunter as a CrewAI-compatible agent with:

- **Human-in-the-loop approval**: Requests approval before risky operations
- **Error recovery**: Automatic retry logic with configurable attempts
- **Task tracking**: Monitors execution status and results
- **Risk assessment**: Evaluates operation risk levels

#### Key Features:

```typescript
interface OAuthAgentConfig {
  target: string;
  clientId?: string;
  redirectUri?: string;
  humanInTheLoop?: boolean;  // Enable human approval
  autoApprove?: boolean;      // Auto-approve non-critical ops
  maxRetries?: number;        // Retry failed operations
  retryDelay?: number;        // Delay between retries
}
```

### 2. Enhanced Supervisor (`src/core/crewai/supervisor.ts`)

The supervisor now supports:

- **Agent pool management**: Register and coordinate multiple agents
- **Execution orchestration**: Execute supervised testing workflows
- **Human task integration**: Route approval requests to UI
- **Result aggregation**: Collect and summarize findings

#### Key Methods:

```typescript
// Register an OAuth agent
supervisor.registerOAuthAgent('oauth', config);

// Set human approval callback
supervisor.setHumanTaskCallback(async (request) => {
  // Show approval modal
  return { approved: true, taskId: request.id };
});

// Execute supervised hunt
const result = await supervisor.execute({
  target: 'api.example.com',
  oauthConfig: { ... },
  onApprovalRequired: showApprovalModal
});
```

### 3. Human Task Manager (`src/core/crewai/human_task.ts`)

Manages human approval requests with:

- **Approval requests**: Binary approve/deny decisions
- **Input requests**: Free-form text input
- **Decision requests**: Multiple choice selections
- **Severity levels**: low, medium, high, critical

## Usage Examples

### Basic OAuth Hunt with Approval

```typescript
import { Supervisor } from './core/crewai';

const supervisor = new Supervisor({
  humanInTheLoop: true,
  maxIterations: 10,
  timeout: 3600000
});

const result = await supervisor.execute({
  target: 'api.example.com',
  scope: ['*.example.com'],
  oauthConfig: {
    target: 'api.example.com',
    clientId: 'client_id',
    redirectUri: 'https://app.example.com/callback',
    knownScopes: ['read', 'write', 'admin']
  },
  onApprovalRequired: async (request) => {
    // Show modal to user
    const approved = await showApprovalModal(request);
    return {
      taskId: request.id,
      approved,
      timestamp: Date.now()
    };
  }
});

console.log(`Found ${result.vulnerabilities.length} vulnerabilities`);
```

### Custom Approval Logic

```typescript
// Auto-approve low/medium, require human for high/critical
const onApprovalRequired = async (request) => {
  if (request.severity === 'low' || request.severity === 'medium') {
    return { taskId: request.id, approved: true };
  }
  
  // Show modal for high/critical
  return await showApprovalModal(request);
};

const result = await supervisor.execute({
  target: 'oauth.example.com',
  oauthConfig: { ... },
  onApprovalRequired
});
```

### Test Specific Vulnerability Types

```typescript
// Register agent manually for more control
supervisor.registerOAuthAgent('oauth', {
  target: 'auth.example.com',
  clientId: 'client_123',
  humanInTheLoop: true,
  autoApprove: false
});

const oauthAgent = supervisor.getAgents().get('oauth');

// Test specific types
const redirectVulns = await oauthAgent.testVulnerabilityType('redirect');
const stateVulns = await oauthAgent.testVulnerabilityType('state');
const pkceVulns = await oauthAgent.testVulnerabilityType('pkce');
const scopeVulns = await oauthAgent.testVulnerabilityType('scope');
```

### Generate Reports

```typescript
const result = await oauthAgent.executeHunt();

result.vulnerabilities.forEach(vuln => {
  const report = oauthAgent.generateReport(vuln);
  console.log(report);
});
```

## Approval Flow

1. **Hunt Initiation**: User starts OAuth hunt
2. **Initial Approval**: Supervisor requests approval to begin testing
3. **Operation Approval**: Agent requests approval for risky operations
4. **Finding Review**: High-severity findings require human review
5. **Completion**: Results returned with approval history

### Approval Request Structure

```typescript
interface HumanTaskRequest {
  id: string;
  type: 'approval' | 'input' | 'decision';
  title: string;
  description: string;
  context: any;
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: number;
}
```

### Approval Response Structure

```typescript
interface HumanTaskResponse {
  taskId: string;
  approved: boolean;
  response?: string;      // For input requests
  selectedOption?: string; // For decision requests
  feedback?: string;      // Optional user feedback
  timestamp: number;
}
```

## Risk Assessment

The OAuth Agent evaluates operation risk based on:

- **Operation type**: Discovery < Testing < Exploitation
- **Target sensitivity**: Public < Internal < Production
- **Payload impact**: Read-only < Modification < Destructive
- **Scope boundaries**: In-scope < Edge case < Out-of-scope

### Risk Levels

- **Low**: Safe operations (discovery, read-only tests)
- **Medium**: Standard testing (parameter manipulation)
- **High**: Potentially impactful (token generation, scope escalation)
- **Critical**: High-impact operations (production testing, destructive tests)

## Error Handling

The integration includes robust error handling:

```typescript
try {
  const result = await supervisor.execute(config);
  
  if (!result.success) {
    console.error('Hunt failed:', result.error);
    result.tasks.forEach(task => {
      if (task.status === 'failed') {
        console.error(`Task ${task.id} failed:`, task.error);
      }
    });
  }
} catch (error) {
  console.error('Execution error:', error);
}
```

### Retry Logic

Failed operations are automatically retried with exponential backoff:

```typescript
{
  maxRetries: 3,        // Retry up to 3 times
  retryDelay: 1000      // Start with 1s delay, increases each retry
}
```

## Integration with UI

### Approval Modal Component

The integration expects an approval modal component:

```typescript
// Example React component
function ApprovalModal({ request, onResponse }) {
  return (
    <Modal>
      <h2>{request.title}</h2>
      <p>{request.description}</p>
      <Badge severity={request.severity} />
      <pre>{JSON.stringify(request.context, null, 2)}</pre>
      <Button onClick={() => onResponse({ approved: true })}>
        Approve
      </Button>
      <Button onClick={() => onResponse({ approved: false })}>
        Deny
      </Button>
    </Modal>
  );
}
```

### Integration with Existing UI

The `ApproveDenyModal` component can be adapted:

```typescript
import { ApproveDenyModal } from './components';

const supervisor = new Supervisor({ humanInTheLoop: true });

supervisor.setHumanTaskCallback(async (request) => {
  return new Promise((resolve) => {
    showModal(
      <ApproveDenyModal
        title={request.title}
        message={request.description}
        context={request.context}
        onApprove={() => resolve({ 
          taskId: request.id, 
          approved: true,
          timestamp: Date.now()
        })}
        onDeny={() => resolve({ 
          taskId: request.id, 
          approved: false,
          timestamp: Date.now()
        })}
      />
    );
  });
});
```

## Testing

See `src/examples/oauth_supervisor_integration.ts` for comprehensive examples:

- Basic OAuth hunt with approval
- Custom approval logic
- Specific test types
- Error handling
- Report generation

Run examples:

```typescript
import examples from './examples/oauth_supervisor_integration';

// Run all examples
await examples.runAllExamples();

// Or run specific examples
await examples.basicOAuthHunt();
await examples.customApprovalLogic();
```

## Configuration

### Supervisor Configuration

```typescript
interface SupervisorConfig {
  apiKey?: string;           // Anthropic API key (optional)
  model?: string;            // AI model (optional)
  maxTokens?: number;        // Max tokens per request
  humanInTheLoop?: boolean;  // Enable human approval
  maxIterations?: number;    // Max execution iterations
  timeout?: number;          // Execution timeout (ms)
}
```

### OAuth Agent Configuration

```typescript
interface OAuthAgentConfig {
  target: string;              // Target domain
  clientId?: string;           // OAuth client ID
  redirectUri?: string;        // Redirect URI
  collaboratorUrl?: string;    // Collaborator URL for OOB
  timeout?: number;            // Request timeout
  maxEndpoints?: number;       // Max endpoints to discover
  useWayback?: boolean;        // Use Wayback Machine
  useNuclei?: boolean;         // Use Nuclei scanner
  knownScopes?: string[];      // Known valid scopes
  humanInTheLoop?: boolean;    // Enable approval
  autoApprove?: boolean;       // Auto-approve non-critical
  maxRetries?: number;         // Max retry attempts
  retryDelay?: number;         // Retry delay (ms)
}
```

## Best Practices

1. **Always enable human-in-the-loop** for production testing
2. **Use auto-approve carefully** - only for low-risk operations
3. **Set appropriate timeouts** to prevent hanging operations
4. **Review high-severity findings** before proceeding
5. **Keep approval history** for audit trails
6. **Test with known-safe targets** before production use
7. **Configure retry logic** based on target reliability
8. **Use collaborator URLs** for out-of-band detection

## Future Enhancements

- [ ] Multi-agent coordination (OAuth + other hunters)
- [ ] AI-powered risk assessment
- [ ] Automated report submission to bug bounty platforms
- [ ] Real-time progress streaming
- [ ] Approval history and audit logs
- [ ] Custom approval workflows
- [ ] Integration with CI/CD pipelines
- [ ] Distributed testing across multiple agents

## See Also

- [OAuth Hunter Architecture](./OAUTH_HUNTER_ARCHITECTURE.md)
- [OAuth Implementation Summary](./OAUTH_IMPLEMENTATION_SUMMARY.md)
- [Phase 4 & 5 Completion](./OAUTH_PHASES_4_5_COMPLETE.md)
- [Integration Examples](./src/examples/oauth_supervisor_integration.ts)