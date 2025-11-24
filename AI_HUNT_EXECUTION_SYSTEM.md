# AI-Powered Hunt Execution System with Safe Tool Access

## Overview

The AI-Powered Hunt Execution System enables autonomous vulnerability hunting using Kali Linux security tools while maintaining strict safety boundaries to prevent program violations and platform bans.

## 🎯 Objective

Enable AI agents to execute real vulnerability hunting using industry-standard tools while enforcing:
- **Safety classifications** for all tools
- **Rate limiting** to prevent abuse
- **Human approval** for active operations
- **Scope validation** to stay within authorized targets
- **Kill switch** for emergency shutdown
- **Comprehensive audit logging** for compliance

## 🛡️ Safety Architecture

### Multi-Layer Safety Gates

Every tool execution passes through multiple safety gates:

```
AI Request → Command Validation → Scope Check → Rate Limit → 
Human Approval → Kill Switch Check → Execute → Audit Log
```

### Tool Safety Classification

#### ✅ SAFE - Passive Reconnaissance (Always Allowed)
- **Tools**: subfinder, amass (passive), httpx, waybackurls, gau
- **Risk**: None (passive only)
- **Execution**: Direct execution via PTY
- **Approval**: Not required
- **Rate Limiting**: Not required

**Example:**
```bash
subfinder -d example.com
waybackurls example.com
httpx -l targets.txt
```

#### ⚠️ CONTROLLED - Light Active Tools (Requires Approval)
- **Tools**: nuclei, ffuf, feroxbuster, katana
- **Risk**: Low if throttled properly
- **Execution**: Through PTY with rate limiting
- **Approval**: Required for first command
- **Rate Limiting**: 5-10 req/s enforced

**Example:**
```bash
nuclei -u https://example.com -rl 5
ffuf -u https://example.com/FUZZ -w wordlist.txt -rate 10
feroxbuster -u https://example.com --rate-limit 10
```

#### 🔶 RESTRICTED - Medium Tools (Explicit Enable Required)
- **Tools**: sqlmap (low level), dirsearch, arjun
- **Risk**: 50% ban risk if abused
- **Execution**: Requires "Enable Medium Mode" toggle
- **Approval**: Required + policy check
- **Rate Limiting**: 2-5 req/s enforced

**Example:**
```bash
# Requires Medium Mode enabled
sqlmap -u "https://example.com/page?id=1" --level 1 --risk 1
dirsearch -u https://example.com
arjun -u https://example.com
```

#### 🚫 BLOCKED - Dangerous Tools (Hard Blocked)
- **Tools**: hydra, medusa, nmap -sS, metasploit, burp intruder
- **Risk**: Instant permanent ban
- **Execution**: Completely disabled in production
- **Reason**: Password brute-forcing, aggressive scanning

**These tools are NEVER allowed:**
```bash
hydra -l admin -P passwords.txt  # ❌ BLOCKED
medusa -h example.com            # ❌ BLOCKED
nmap -sS example.com             # ❌ BLOCKED
```

#### ⛔ FORBIDDEN - DoS Tools (Not Installed)
- **Tools**: slowloris, goldeneye, hulk, LOIC, HOIC
- **Risk**: Legal threat + instant ban
- **Action**: Delete from system, never install
- **Reason**: Denial of Service attacks

**These tools should NOT exist on the system:**
```bash
slowloris example.com  # ⛔ FORBIDDEN - DoS attack
goldeneye example.com  # ⛔ FORBIDDEN - DoS attack
```

## 📋 Implementation Components

### 1. Tool Registry (`src/core/tools/tool_registry.ts`)

Manages all security tools with metadata:

```typescript
import { ToolRegistry, ToolSafetyLevel } from './core/tools';

const registry = new ToolRegistry();

// Get tool information
const nuclei = registry.getTool('nuclei');
console.log(nuclei.safetyLevel);  // CONTROLLED
console.log(nuclei.requirements.requiresApproval);  // true

// Enable medium mode for RESTRICTED tools
registry.enableMediumMode();

// Get tools by safety level
const safeTools = registry.getToolsBySafetyLevel(ToolSafetyLevel.SAFE);
```

### 2. Command Validator (`src/core/tools/command_validator.ts`)

Validates commands before execution:

```typescript
import { CommandValidator } from './core/tools';

const validator = new CommandValidator(registry);

// Validate a command
const result = await validator.validate('nuclei -u https://example.com');

if (result.allowed) {
  console.log('Command allowed');
  console.log('Sanitized:', result.sanitizedCommand);
  console.log('Required actions:', result.requiredActions);
} else {
  console.log('Command blocked:', result.blockReason);
}
```

### 3. Tool Executor (`src/core/tools/tool_executor.ts`)

Orchestrates safe execution with all safety gates:

```typescript
import { ToolExecutor } from './core/tools';

const executor = new ToolExecutor(registry);

// Execute a command
const result = await executor.execute({
  command: 'subfinder -d example.com',
  context: {
    executionId: 'exec_123',
    agentId: 'oauth_hunter',
    target: 'example.com',
    timestamp: new Date(),
  },
});

if (result.success) {
  console.log('Output:', result.stdout);
} else {
  console.log('Failed:', result.blockReason);
}
```

### 4. AI Agent Integration (`src/core/crewai/tool_integration.ts`)

Provides AI agents with controlled tool access:

```typescript
import { createAIAgentToolInterface } from './core/crewai/tool_integration';

const toolInterface = createAIAgentToolInterface('session_123');

// AI agent executes a tool
const result = await toolInterface.executeTool(
  'oauth_hunter',
  'subfinder -d example.com',
  'example.com',
  false  // Don't skip approval
);

// Get available tools for AI context
const toolDescriptions = toolInterface.getAvailableTools();
```

### 5. Audit Logger (`src/core/tools/audit_logger.ts`)

Comprehensive logging for compliance:

```typescript
import { getGlobalAuditLogger } from './core/tools/audit_logger';

const logger = getGlobalAuditLogger();

// Logs are automatically created by the executor
// Query logs
const blockedCommands = logger.query({
  result: 'blocked',
  startDate: new Date('2024-01-01'),
});

// Get statistics
const stats = logger.getStatistics();
console.log('Total executions:', stats.totalEntries);
console.log('Blocked:', stats.blockedCommands);

// Export logs
const json = logger.exportToJSON();
const csv = logger.exportToCSV();
```

## 🔄 Hunt Execution Flow

### Complete Execution Flow

```
1. AI Agent decides to use a tool
   ↓
2. Command Validator checks:
   - Tool is registered
   - Safety level allows execution
   - No dangerous flags present
   - Tool is enabled
   ↓
3. Scope Validator checks:
   - Target is in authorized scope
   - No out-of-scope patterns match
   ↓
4. Rate Limiter checks:
   - Tokens available for this tool
   - Request rate within limits
   ↓
5. Human Approval (if required):
   - Modal shown to user
   - User approves or denies
   ↓
6. Kill Switch check:
   - Verify kill switch is not active
   ↓
7. Execute via PTY:
   - Command runs in isolated terminal
   - Output streamed back
   ↓
8. Audit Log:
   - Full execution details logged
   - Available for review and export
```

## 🚨 Safety Guarantees

### Hard Guarantees

1. **Default Deny**: If scope is empty, NOTHING is allowed
2. **Tool Classification**: All tools must be registered with safety level
3. **Rate Limiting**: CONTROLLED and RESTRICTED tools are always rate-limited
4. **Human Approval**: Active tools require explicit approval
5. **Kill Switch**: Can instantly halt ALL operations
6. **Audit Trail**: Every execution is logged permanently

### Dangerous Pattern Blocking

The system automatically blocks dangerous patterns:

```typescript
// Blocked patterns for amass
amass enum -active    // ❌ Active scanning
amass enum -brute     // ❌ Brute forcing

// Blocked patterns for sqlmap
sqlmap --os-shell     // ❌ OS command execution
sqlmap --sql-shell    // ❌ SQL shell access
sqlmap --level 5      // ❌ Aggressive testing
sqlmap --risk 3       // ❌ High risk operations

// Blocked patterns for nmap
nmap -sS              // ❌ SYN scan
nmap -sU              // ❌ UDP scan
nmap -sN              // ❌ NULL scan
```

## 📊 Usage Examples

### Example 1: Safe Passive Reconnaissance

```typescript
const toolInterface = createAIAgentToolInterface();

// Execute passive recon (no approval needed)
const subdomains = await toolInterface.executeTool(
  'recon_agent',
  'subfinder -d example.com -silent',
  'example.com',
  true  // Skip approval for SAFE tools
);

if (subdomains.success) {
  console.log('Found subdomains:', subdomains.stdout);
}
```

### Example 2: Controlled Active Scanning

```typescript
// Execute nuclei (requires approval)
const scan = await toolInterface.executeTool(
  'vuln_scanner',
  'nuclei -u https://example.com -t cves/ -rl 5',
  'example.com',
  false  // Requires human approval
);

// User sees approval modal
// If approved, scan executes with rate limiting
```

### Example 3: Medium Mode Tools

```typescript
// Enable medium mode
toolInterface.enableMediumMode();

// Now RESTRICTED tools are available
const sqlTest = await toolInterface.executeTool(
  'sql_hunter',
  'sqlmap -u "https://example.com/page?id=1" --level 1 --batch',
  'example.com',
  false
);
```

### Example 4: Handling Blocked Commands

```typescript
const result = await toolInterface.executeTool(
  'bad_agent',
  'hydra -l admin -P passwords.txt ssh://example.com',
  'example.com',
  false
);

// Result will be blocked
console.log(result.blocked);  // true
console.log(result.blockReason);  // "BLOCKED: hydra is a dangerous tool..."
```

## 🔧 Configuration

### Enable/Disable Medium Mode

```typescript
// Enable RESTRICTED tools
registry.enableMediumMode();

// Disable RESTRICTED tools
registry.disableMediumMode();

// Check status
const enabled = registry.isMediumModeEnabled();
```

### Adjust Rate Limits

Rate limits are configured per tool in the registry:

```typescript
const nuclei = registry.getTool('nuclei');
nuclei.requirements.maxRequestsPerSecond = 3;  // Reduce from 5 to 3
```

### Custom Tool Registration

```typescript
registry.registerTool({
  name: 'custom-tool',
  description: 'My custom security tool',
  safetyLevel: ToolSafetyLevel.CONTROLLED,
  requirements: {
    requiresApproval: true,
    requiresExplicitEnable: false,
    requiresScopeValidation: true,
    requiresRateLimiting: true,
    maxRequestsPerSecond: 5,
    requiresPolicyCheck: true,
  },
  commandPatterns: ['custom-tool -u', 'custom-tool --url'],
  category: 'scanning',
  riskScore: 30,
  enabled: true,
  rateLimiter: new RateLimiter({ maxRequests: 5, windowMs: 1000 }),
});
```

## 📈 Monitoring and Statistics

### Execution Statistics

```typescript
const stats = executor.getStatistics();

console.log('Total executions:', stats.totalExecutions);
console.log('Successful:', stats.successful);
console.log('Failed:', stats.failed);
console.log('Blocked:', stats.blocked);
console.log('Average execution time:', stats.averageExecutionTime, 'ms');

// By tool
for (const [tool, counts] of stats.byTool) {
  console.log(`${tool}: ${counts.success} success, ${counts.blocked} blocked`);
}

// By safety level
for (const [level, counts] of stats.bySafetyLevel) {
  console.log(`${level}: ${counts.success} success, ${counts.blocked} blocked`);
}
```

### Validation Statistics

```typescript
const validationStats = validator.getStatistics();

console.log('Total validations:', validationStats.totalValidations);
console.log('Allowed:', validationStats.allowed);
console.log('Blocked:', validationStats.blocked);
```

### Audit Log Analysis

```typescript
const logger = getGlobalAuditLogger();

// Get all blocked commands
const blocked = logger.query({ result: 'blocked' });

// Get critical events
const critical = logger.query({ severity: 'critical' });

// Get executions by agent
const agentLogs = logger.query({ agentId: 'oauth_hunter' });

// Export for analysis
const csv = logger.exportToCSV();
```

## 🚨 Emergency Procedures

### Activate Kill Switch

```typescript
// From Rust backend
await invoke('activate_kill_switch', {
  reason: 'scope_violation',
  context: 'Detected out-of-scope testing'
});

// All operations immediately halt
// No new executions allowed until reset
```

### Reset Kill Switch

```typescript
await invoke('reset_kill_switch', {
  confirmation: 'CONFIRM_RESET'
});
```

## ✅ Success Criteria

- [x] Tool registry with all Kali tools classified
- [x] Command validator blocks dangerous tools
- [x] Rate limiting enforced per tool
- [x] Human approval required for active tools
- [x] AI can execute safe passive recon
- [x] All executions logged and recorded
- [x] Kill switch stops everything instantly
- [x] Zero risk of program violations

## 🔒 Security Best Practices

1. **Always validate scope** before any operation
2. **Never skip approval** for CONTROLLED/RESTRICTED tools
3. **Monitor rate limits** to prevent abuse
4. **Review audit logs** regularly
5. **Keep Medium Mode disabled** unless explicitly needed
6. **Test in safe environment** before production
7. **Have kill switch ready** for emergencies
8. **Export logs** for compliance records

## 📚 Additional Resources

- Tool Registry: `src/core/tools/tool_registry.ts`
- Command Validator: `src/core/tools/command_validator.ts`
- Tool Executor: `src/core/tools/tool_executor.ts`
- AI Integration: `src/core/crewai/tool_integration.ts`
- Audit Logger: `src/core/tools/audit_logger.ts`
- Tests: `src/tests/tool_execution_system.test.ts`

## 🤝 Contributing

When adding new tools:

1. Classify the tool's safety level
2. Define rate limits if needed
3. Specify dangerous flags to block
4. Add to tool registry
5. Write tests for validation
6. Update documentation

## ⚠️ Important Notes

- **This system is designed for authorized bug bounty testing only**
- **Always obtain proper authorization before testing**
- **Respect program scope and rules**
- **Monitor your executions and stay within limits**
- **When in doubt, ask for human approval**

---

**Built with safety and compliance as top priorities.**