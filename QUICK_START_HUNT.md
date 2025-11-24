# 🚀 Quick Start: AI-Powered Hunt

## Prerequisites

1. **Configure API Key**
   ```bash
   cd huntress
   cp config/.env.example config/.env
   # Edit config/.env and add your Anthropic API key
   ```

2. **Install Dependencies**
   ```bash
   npm install
   ```

3. **Start Application**
   ```bash
   npm run tauri dev
   ```

## Running Your First Hunt

### Step 1: Import Program Guidelines

1. Go to **"Scope"** tab
2. Click **"Import Guidelines"**
3. Paste HackerOne program URL or guidelines JSON
4. Click **"Import"**

✅ Scope automatically loaded with in-scope and out-of-scope targets

### Step 2: Configure Hunt

1. Go to **"Hunt"** tab
2. Review active agents (all enabled by default)
3. Verify scope is correct

### Step 3: Start Hunt

1. Click **"🚀 Start Hunt"**
2. Application switches to **"Results"** tab
3. Terminal shows initialization progress

### Step 4: Approve Tool Executions

When AI wants to run a tool:

1. **Approval modal appears** with:
   - Command to execute
   - Tool name and safety level
   - Target being tested
   - Validation results

2. **Review the request**:
   - Is the command safe?
   - Is the target in-scope?
   - Does it make sense?

3. **Make decision**:
   - Click **"Approve"** to allow execution
   - Click **"Deny"** to block execution
   - Add optional feedback/reason

4. **Watch terminal** for tool output

### Step 5: Monitor Progress

The terminal displays:
- ✅ Approved commands
- ❌ Denied commands
- 📊 Tool output
- 🐛 Vulnerabilities found
- ⏱️ Progress updates

### Step 6: Stop Hunt

**Graceful Stop:**
- Click **"⏸️ Stop Hunt"**

**Emergency Stop:**
- Click **"🛑 EMERGENCY STOP"** (activates kill switch)

## Example Hunt Session

```
🎯 Huntress AI Hunt Started
Creating AI tool interface...
Initializing AI supervisor...
Starting terminal session...
Analyzing target and planning attack strategy...
Hunting example.com...

[Approval Modal Appears]
Tool: subfinder
Command: subfinder -d example.com -silent
Target: example.com
Safety Level: SAFE

✅ Approved: Execute: subfinder -d example.com -silent

api.example.com
admin.example.com
dev.example.com
staging.example.com

[Approval Modal Appears]
Tool: httpx
Command: httpx -l subdomains.txt -silent
Target: example.com
Safety Level: SAFE

✅ Approved: Execute: httpx -l subdomains.txt -silent

https://api.example.com [200]
https://admin.example.com [403]
https://dev.example.com [200]
https://staging.example.com [200]

✅ Hunt completed successfully!
📊 Tasks executed: 5
🐛 Vulnerabilities found: 2
⏱️  Duration: 45.32s

🎉 Vulnerabilities:
  1. Open Redirect - Medium
  2. IDOR - High
```

## Safety Features

### Automatic Protections

- ✅ **Command Validation** - All commands validated before execution
- ✅ **Scope Validation** - Only in-scope targets tested
- ✅ **Rate Limiting** - Prevents excessive requests
- ✅ **Kill Switch** - Emergency stop for all operations
- ✅ **Audit Logging** - Complete execution history

### Human Oversight

- ✅ **Approval Required** - DANGEROUS tools always need approval
- ✅ **Real-time Monitoring** - Watch all tool executions
- ✅ **Emergency Stop** - Halt operations instantly
- ✅ **Feedback Loop** - Provide guidance to AI

## Troubleshooting

### "ANTHROPIC_API_KEY not found"

**Solution:**
```bash
# Edit config/.env
nano config/.env

# Add your API key
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
```

### "No targets in scope"

**Solution:**
1. Go to "Scope" tab
2. Import guidelines or add targets manually
3. Ensure at least one target is marked as in-scope

### Hunt won't start

**Check:**
1. ✅ API key configured in `.env`
2. ✅ Scope imported
3. ✅ Kill switch not active
4. ✅ Browser console for errors

### Approval modal not appearing

**Check:**
1. ✅ Tool requires approval (DANGEROUS/RESTRICTED)
2. ✅ Browser console for events
3. ✅ Modal not hidden behind other windows

## Tips for Effective Hunting

### 1. Use Program Guidelines

Always import program guidelines when available:
- Ensures scope compliance
- Provides bounty context
- Includes program rules
- Guides AI decision-making

### 2. Review Approvals Carefully

Before approving:
- ✅ Verify target is in-scope
- ✅ Check command is safe
- ✅ Ensure it makes sense
- ✅ Consider rate limits

### 3. Monitor Terminal Output

Watch for:
- 🚨 Errors or warnings
- 🎯 Interesting findings
- 📊 Progress indicators
- 🐛 Potential vulnerabilities

### 4. Use Emergency Stop When Needed

Activate kill switch if:
- ⚠️ Out-of-scope target detected
- ⚠️ Unexpected behavior
- ⚠️ Rate limit concerns
- ⚠️ Any safety concerns

### 5. Provide Feedback

When approving/denying:
- 💬 Add context for AI learning
- 💬 Explain reasoning
- 💬 Suggest alternatives
- 💬 Note concerns

## Advanced Usage

### Custom Scope

Instead of importing guidelines:

1. Go to "Scope" tab
2. Enter targets manually
3. Mark as in-scope or out-of-scope
4. Add notes for context

### Agent Selection

Customize which agents run:

1. Go to "Hunt" tab
2. Uncheck agents you don't want
3. Focus on specific vulnerability types

### Multiple Targets

The hunt will:
1. Start with first in-scope target
2. Complete analysis
3. Move to next target (future feature)

## What Happens During a Hunt

### 1. Initialization (5-10 seconds)
- Creates AI tool interface
- Initializes supervisor
- Loads program guidelines
- Spawns terminal session

### 2. Target Analysis (varies)
- AI analyzes target
- Plans testing strategy
- Identifies attack surface
- Prioritizes tests

### 3. Tool Execution (varies)
- AI requests tool execution
- System validates command
- Requests human approval
- Executes via PTY
- Streams output

### 4. Result Analysis (varies)
- AI analyzes tool output
- Identifies vulnerabilities
- Plans next steps
- Continues or concludes

### 5. Completion (instant)
- Displays summary
- Shows vulnerabilities
- Logs all actions
- Cleans up resources

## Next Steps

After your first hunt:

1. **Review Results**
   - Check terminal output
   - Analyze vulnerabilities
   - Verify findings

2. **Refine Approach**
   - Adjust agent selection
   - Update scope if needed
   - Provide AI feedback

3. **Submit Findings**
   - Use report generator (future)
   - Follow program guidelines
   - Include proof-of-concept

4. **Learn and Improve**
   - Review what worked
   - Note what didn't
   - Adjust strategy

## Support

For issues or questions:

1. Check [`HUNT_INTEGRATION_COMPLETE.md`](HUNT_INTEGRATION_COMPLETE.md)
2. Review [`TOOL_SAFETY_QUICK_REFERENCE.md`](TOOL_SAFETY_QUICK_REFERENCE.md)
3. Check browser console for errors
4. Review Tauri backend logs

## Safety Reminder

⚠️ **Always:**
- Verify targets are in-scope
- Review commands before approval
- Monitor tool execution
- Respect rate limits
- Follow program rules
- Use kill switch if needed

🎯 **Happy Hunting!**