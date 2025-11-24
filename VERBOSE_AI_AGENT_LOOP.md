# Verbose AI Agent Loop with Streaming Output and Human Checkpoints

## Overview

The Huntress AI agent system now features a comprehensive verbose execution loop that provides full visibility into AI decision-making, real-time streaming output, and strategic human checkpoints for control and oversight.

## Architecture

### Core Components

1. **Supervisor** (`src/core/crewai/supervisor.ts`)
   - Enhanced with streaming callbacks
   - Checkpoint management system
   - Phase tracking (initialization → reconnaissance → active testing → exploitation → reporting)
   - Real-time AI reasoning output

2. **App.tsx** (`src/App.tsx`)
   - Streaming message handler
   - Checkpoint approval workflow
   - Real-time progress tracking UI
   - PTY integration for tool output

3. **ApproveDenyModal** (`src/components/ApproveDenyModal.tsx`)
   - Enhanced tool approval interface
   - Detailed safety information
   - Risk assessment display
   - Command validation feedback

## Features

### 1. Streaming AI Output

Every AI decision, reasoning step, and action is visible in real-time:

```
🤔 Analyzing target: paybridge.booking.com
📋 Program guidelines loaded: Booking.com
🎯 Planning reconnaissance strategy...
💭 AI Reasoning: This is a payment bridge subdomain, likely handles sensitive financial data
🔍 Recommended approach: Start with passive reconnaissance
📊 Tools to use: subfinder, httpx, waybackurls
```

**Implementation:**
- `StreamingCallback` type for real-time message delivery
- `AIReasoningType` enum for categorizing messages
- Automatic PTY streaming to terminal
- UI display with color-coded message types

### 2. Command Approval Workflow

Before executing ANY tool, the system shows a detailed approval modal:

```
⚠️ APPROVAL REQUIRED
Tool: subfinder (SAFE)
Command: subfinder -d booking.com
Target: booking.com
Risk: None (passive reconnaissance)
Reasoning: Discover subdomains to map attack surface
[Approve] [Deny]
```

**Features:**
- Tool name and safety level (SAFE/RESTRICTED/DANGEROUS)
- Exact command to be executed
- Target being tested
- Risk assessment
- AI reasoning for the action
- Validation warnings
- Optional feedback/reason input

### 3. Checkpoint System

Human checkpoints at strategic stages:

**Automatic Checkpoints:**
- After initialization (before starting hunt)
- Every 5 tool executions (configurable)
- After reconnaissance phase (before active testing)
- After finding potential vulnerability (before exploitation)
- Before submitting report

**Manual Checkpoints:**
- If AI seems stuck or looping
- On user request via emergency stop

**Checkpoint Display:**
```
⏸️ CHECKPOINT REQUIRED
Reason: Executed 5 tools
Phase: RECONNAISSANCE
Context:
  - Tools Executed: 5
  - Findings: 2
  - Target: booking.com
  - Next Action: Start active testing
[Stop Hunt] [Continue]
```

### 4. Real-Time Tool Output

All tool execution output is streamed to the terminal:

```
▶️ Executing: subfinder -d booking.com
📡 Output:
  api.booking.com
  secure.booking.com
  admin.booking.com
  ...
✅ Complete: Found 47 subdomains
```

### 5. AI Reasoning Display

The UI shows the AI's thought process in real-time:

```
💭 Analysis: Found admin.booking.com subdomain
🤔 Next step: Check for common vulnerabilities
📝 Hypothesis: Admin panel may have authentication issues
🎯 Recommended test: Check for default credentials, SQL injection
⚠️ Requesting approval to test...
```

## Hunt Phases

The system tracks and displays the current hunt phase:

1. **INITIALIZATION** - Setting up hunt, loading guidelines
2. **RECONNAISSANCE** - Passive information gathering
3. **ACTIVE_TESTING** - Active vulnerability testing
4. **EXPLOITATION** - Attempting to exploit findings
5. **REPORTING** - Generating vulnerability reports
6. **COMPLETE** - Hunt finished

## Progress Tracking

Real-time statistics displayed in the UI:

- **Current Phase** - Which stage of the hunt
- **Tools Executed** - Count of tools run
- **Findings** - Number of potential vulnerabilities
- **Status** - Active/Paused/Complete

## Message Types

AI messages are categorized and color-coded:

- 🤔 **ANALYSIS** (Blue) - Analyzing data or situation
- 📋 **PLANNING** (Purple) - Planning next steps
- 🎯 **DECISION** (Cyan) - Making a decision
- 💭 **HYPOTHESIS** (Pink) - Forming hypothesis
- 📊 **RECOMMENDATION** (Orange) - Recommending action
- ⚠️ **WARNING** (Yellow) - Warning or checkpoint
- ✅ **SUCCESS** (Green) - Successful action
- ❌ **ERROR** (Red) - Error or failure

## Configuration

### Supervisor Configuration

```typescript
const supervisor = new Supervisor({
  apiKey: 'your-anthropic-key',
  humanInTheLoop: true,
  maxIterations: 10,
  verboseMode: true,              // Enable streaming output
  checkpointInterval: 5,          // Checkpoint every N tools
  onStreaming: handleStreamingMessage,
  onCheckpoint: handleCheckpoint,
});
```

### Streaming Callback

```typescript
const handleStreamingMessage = (message: StreamingMessage) => {
  // message.type - AIReasoningType
  // message.phase - HuntPhase
  // message.message - The actual message
  // message.timestamp - When it occurred
  // message.metadata - Additional context
};
```

### Checkpoint Callback

```typescript
const handleCheckpoint = async (checkpoint: CheckpointRequest): Promise<boolean> => {
  // checkpoint.id - Unique ID
  // checkpoint.phase - Current hunt phase
  // checkpoint.reason - Why checkpoint triggered
  // checkpoint.context - Current state (tools, findings, target)
  
  // Return true to continue, false to stop
};
```

## Safety Features

### Tool Approval

Every tool execution requires approval showing:
- Command to be executed
- Tool safety level
- Target being tested
- Validation results
- Risk assessment for dangerous tools

### Checkpoint Control

Strategic checkpoints ensure:
- Human oversight at critical stages
- Ability to stop before risky operations
- Review of findings before exploitation
- Approval before report submission

### Emergency Stop

The emergency stop button:
- Activates kill switch
- Stops all running tools
- Terminates PTY sessions
- Prevents further execution

## UI Components

### Progress Stats Panel

```
┌─────────────────────────────────────────────┐
│ Phase: RECONNAISSANCE                       │
│ Tools Executed: 5                           │
│ Findings: 2                                 │
│ Status: Active                              │
└─────────────────────────────────────────────┘
```

### AI Reasoning Panel

Shows last 10 AI messages with timestamps and color-coded types.

### Terminal Output

Full PTY output with:
- Command execution
- Tool output streaming
- Success/failure indicators
- Timing information

### Approval Modal

Detailed modal showing:
- Tool information
- Command details
- Safety assessment
- Validation results
- Risk warnings
- Feedback/reason input

### Checkpoint Modal

Strategic pause showing:
- Checkpoint reason
- Current phase
- Execution context
- Next planned action
- Continue/Stop options

## Example Hunt Flow

```
1. 🤔 Analyzing target: example.com
2. 📋 Loading program guidelines...
3. 🎯 Planning reconnaissance strategy...
4. ⏸️ CHECKPOINT: Ready to begin hunt
   [User approves]
5. 📊 Recommended: Start with subfinder
6. ⚠️ APPROVAL: Execute subfinder -d example.com
   [User approves]
7. ▶️ Executing: subfinder -d example.com
8. 📡 Output: Found 23 subdomains
9. ✅ Complete: Reconnaissance phase done
10. ⏸️ CHECKPOINT: Executed 5 tools
    [User approves]
11. 💭 Hypothesis: admin.example.com may be vulnerable
12. 🎯 Recommended: Test for authentication bypass
13. ⚠️ APPROVAL: Execute nuclei -t auth-bypass
    [User approves]
14. ▶️ Executing: nuclei...
15. ✅ SUCCESS: Found vulnerability!
16. ⏸️ CHECKPOINT: Found vulnerability, proceed to exploitation?
    [User decides]
```

## Benefits

1. **Full Transparency** - See every AI decision and reasoning
2. **Human Control** - Approve/deny actions at critical points
3. **Safety** - Multiple checkpoints prevent runaway execution
4. **Learning** - Understand AI's approach to bug hunting
5. **Debugging** - Easy to identify where things go wrong
6. **Compliance** - Audit trail of all actions and approvals

## Future Enhancements

- [ ] Configurable checkpoint rules
- [ ] AI reasoning explanation on demand
- [ ] Replay/rewind hunt execution
- [ ] Export hunt transcript
- [ ] Custom message filters
- [ ] Phase-specific checkpoints
- [ ] Tool execution history
- [ ] Finding correlation display

## Testing

To test the verbose loop:

1. Start Huntress with a target
2. Observe streaming AI messages in terminal
3. Approve/deny tool executions
4. Review checkpoint information
5. Monitor progress stats
6. Check AI reasoning panel
7. Test emergency stop

## Troubleshooting

**No streaming output:**
- Check `verboseMode: true` in supervisor config
- Verify streaming callback is set
- Check PTY session is active

**Checkpoints not appearing:**
- Verify `checkpointInterval` is set
- Check checkpoint callback is registered
- Ensure hunt is in progress

**Approval modal not showing:**
- Check tool requires approval
- Verify event listener is attached
- Check modal state management

## API Reference

### StreamingMessage

```typescript
interface StreamingMessage {
  type: AIReasoningType;
  phase: HuntPhase;
  message: string;
  timestamp: number;
  metadata?: Record<string, any>;
}
```

### CheckpointRequest

```typescript
interface CheckpointRequest {
  id: string;
  phase: HuntPhase;
  reason: string;
  context: {
    toolsExecuted: number;
    findingsCount: number;
    currentTarget: string;
    nextAction?: string;
  };
  timestamp: number;
}
```

### AIReasoningType

```typescript
enum AIReasoningType {
  ANALYSIS = 'analysis',
  PLANNING = 'planning',
  DECISION = 'decision',
  HYPOTHESIS = 'hypothesis',
  RECOMMENDATION = 'recommendation',
  WARNING = 'warning',
  SUCCESS = 'success',
  ERROR = 'error',
}
```

### HuntPhase

```typescript
enum HuntPhase {
  INITIALIZATION = 'initialization',
  RECONNAISSANCE = 'reconnaissance',
  ACTIVE_TESTING = 'active_testing',
  EXPLOITATION = 'exploitation',
  REPORTING = 'reporting',
  COMPLETE = 'complete',
}
```

## Conclusion

The verbose AI agent loop provides unprecedented visibility and control over autonomous bug bounty hunting. Every decision is transparent, every action requires approval, and strategic checkpoints ensure human oversight at critical stages.

This system balances automation with safety, allowing AI to work efficiently while maintaining human control over risky operations.