# Phase 5 Emergency Rollback Procedure

Comprehensive guide for executing emergency rollbacks with step-by-step procedures, validation checks, and recovery steps.

## Table of Contents

1. [Overview](#overview)
2. [When to Rollback](#when-to-rollback)
3. [Rollback Methods](#rollback-methods)
4. [Pre-Rollback Checklist](#pre-rollback-checklist)
5. [Automated Rollback](#automated-rollback)
6. [Manual Rollback](#manual-rollback)
7. [Post-Rollback Verification](#post-rollback-verification)
8. [Rollback Scenarios](#rollback-scenarios)
9. [Recovery Procedures](#recovery-procedures)
10. [Rollback History](#rollback-history)

---

## Overview

The rollback system provides fast, reliable recovery from failed deployments or degraded performance. Target rollback time: **< 5 minutes**.

### Rollback Capabilities

- **One-Command Rollback**: Single command execution
- **Fast Recovery**: Complete rollback in under 5 minutes
- **State Preservation**: Automatic backup before rollback
- **Validation**: Post-rollback health checks
- **Audit Trail**: Complete rollback history
- **Self-Healing**: Automatic recovery attempts

### Rollback Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Rollback System                           │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Rollback Trigger                         │   │
│  │  • Performance Degradation                            │   │
│  │  • Health Check Failure                               │   │
│  │  • Manual Intervention                                │   │
│  └────────────────────┬─────────────────────────────────┘   │
│                       │                                      │
│                       ▼                                      │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           Rollback Manager                            │   │
│  │  1. Backup Current State                              │   │
│  │  2. Restore Previous Version                          │   │
│  │  3. Verify State Consistency                          │   │
│  │  4. Run Health Checks                                 │   │
│  │  5. Validate Performance                              │   │
│  └────────────────────┬─────────────────────────────────┘   │
│                       │                                      │
│                       ▼                                      │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           Post-Rollback Actions                       │   │
│  │  • Send Notifications                                 │   │
│  │  • Log to Audit Trail                                 │   │
│  │  • Update Dashboard                                   │   │
│  │  • Generate Report                                    │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## When to Rollback

### Automatic Rollback Triggers

1. **Performance Degradation**
   - Success rate drops > 15% from baseline
   - False positive rate increases > 10%
   - Execution time increases > 50%

2. **Health Check Failures**
   - 3 consecutive health check failures
   - Critical component unhealthy
   - System resource exhaustion

3. **Deployment Failures**
   - Validation fails during deployment
   - Model files corrupted
   - Configuration errors

### Manual Rollback Triggers

1. **Operational Issues**
   - Unexpected system behavior
   - User-reported problems
   - Security concerns

2. **Business Requirements**
   - Regulatory compliance
   - Emergency maintenance
   - Strategic decisions

### Decision Matrix

| Condition | Severity | Action | Timeframe |
|-----------|----------|--------|-----------|
| Success rate < 60% | Critical | Automatic rollback | Immediate |
| Success rate 60-70% | High | Alert + manual decision | 15 minutes |
| FP rate > 20% | Critical | Automatic rollback | Immediate |
| FP rate 15-20% | High | Alert + manual decision | 30 minutes |
| Health check failure | Critical | Automatic rollback | Immediate |
| Deployment validation fail | High | Block deployment | N/A |

---

## Rollback Methods

### Method 1: Automated Script (Recommended)

**Fastest and safest method**

```bash
# Execute rollback
./scripts/deploy_production.sh --rollback

# With dry-run (test without changes)
./scripts/deploy_production.sh --rollback --dry-run
```

**Advantages:**
- Fastest execution (< 5 minutes)
- Comprehensive validation
- Automatic backup
- Detailed logging

### Method 2: Programmatic Rollback

**For integration with monitoring systems**

```typescript
import { RollbackManager } from './src/core/training/rollback_manager';

const rollbackManager = new RollbackManager(
  modelManager,
  performanceMonitor,
  rollbackConfig
);

await rollbackManager.initialize();

// Execute rollback
const result = await rollbackManager.executeRollback(
  'performance_degradation',
  'Success rate dropped to 55%',
  'automatic'
);

console.log(`Rollback ${result.success ? 'succeeded' : 'failed'}`);
```

### Method 3: Manual Rollback

**For emergency situations when automation fails**

See [Manual Rollback](#manual-rollback) section below.

---

## Pre-Rollback Checklist

Before initiating rollback, verify:

### 1. Confirm Rollback Necessity

```bash
# Check current performance
cat models/metrics/metrics_latest.json

# Check health status
cat logs/health/health_latest.json

# Review recent alerts
tail -50 logs/alerts.log
```

**Questions to ask:**
- Is the issue confirmed and reproducible?
- Have other mitigation attempts failed?
- Is rollback the best solution?
- Are stakeholders informed?

### 2. Verify Backup Availability

```bash
# List available backups
ls -lt backups/deployments/

# Verify backup integrity
cat backups/deployments/pre-deploy-*/metadata.json

# Check backup size
du -sh backups/deployments/pre-deploy-*
```

### 3. Check System Resources

```bash
# Disk space
df -h

# Memory
free -h

# Running processes
ps aux | grep -E "node|python"
```

### 4. Notify Stakeholders

- Alert operations team
- Inform management
- Update status page
- Document reason

---

## Automated Rollback

### Step-by-Step Execution

#### 1. Initiate Rollback

```bash
# Navigate to project directory
cd /home/gonzo/Desktop/Huntress

# Execute rollback script
./scripts/deploy_production.sh --rollback
```

**Expected Output:**
```
================================================================================
Huntress Production Deployment
================================================================================

[INFO] Deployment ID: rollback_1706025600_abc123
[INFO] Log file: logs/deployments/rollback_1706025600_abc123.log

================================================================================
Executing Rollback
================================================================================

[WARN] Initiating emergency rollback
[INFO] Rolling back using backup: pre-deploy-1706020000_xyz789
```

#### 2. Monitor Progress

The script will execute these steps automatically:

1. **Backup Current State** (30 seconds)
   ```
   [INFO] Step: Backup Current State
   [INFO] Creating backup at: backups/pre-rollback-1706025600
   [SUCCESS] Step completed: Backup Current State (28s)
   ```

2. **Rollback Model Version** (60 seconds)
   ```
   [INFO] Step: Rollback Model Version
   [INFO] Reverting from v1.2.0 to v1.1.0
   [SUCCESS] Step completed: Rollback Model Version (58s)
   ```

3. **Restore Configuration** (15 seconds)
   ```
   [INFO] Step: Restore Configuration
   [INFO] Restored deployment.json
   [INFO] Restored model_versions.json
   [SUCCESS] Step completed: Restore Configuration (12s)
   ```

4. **Verify State Consistency** (30 seconds)
   ```
   [INFO] Step: Verify State Consistency
   [INFO] Production version: v1.1.0
   [INFO] Model files accessible
   [INFO] Configuration accessible
   [SUCCESS] Step completed: Verify State Consistency (25s)
   ```

5. **Run Health Checks** (45 seconds)
   ```
   [INFO] Step: Run Health Checks
   [INFO] Model Manager: ✓
   [INFO] Performance Monitor: ✓
   [INFO] File System: ✓
   [SUCCESS] Step completed: Run Health Checks (42s)
   ```

6. **Verify Performance** (30 seconds)
   ```
   [INFO] Step: Verify Performance
   [INFO] Success rate: 72.5%
   [INFO] FP rate: 9.8%
   [SUCCESS] Step completed: Verify Performance (28s)
   ```

#### 3. Completion

```
================================================================================
Rollback Successful
================================================================================

[SUCCESS] Rollback completed successfully
[INFO] Rolled back from v1.2.0 to v1.1.0
[INFO] Duration: 233 seconds (3.9 minutes)
[INFO] Rollback ID: rollback_1706025600_abc123
[INFO] Log file: logs/deployments/rollback_1706025600_abc123.log
```

### Rollback Validation

After automated rollback, verify:

```bash
# Check production version
jq '.production' config/model_versions.json

# Verify health
node -e "require('./src/core/training/health_checker')"

# Check performance
cat models/metrics/metrics_latest.json
```

---

## Manual Rollback

Use manual rollback only when automated rollback fails or is unavailable.

### Emergency Manual Rollback Procedure

#### Step 1: Stop All Services

```bash
# Stop Node.js processes
pkill -f "node.*huntress"

# Stop Python processes
pkill -f "python.*huntress"

# Verify stopped
ps aux | grep -E "node|python" | grep huntress
```

#### Step 2: Identify Previous Version

```bash
# List model versions
ls -lt models/

# Check version history
cat config/model_versions.json | jq '.versions[] | select(.status=="archived") | {version, createdAt}'

# Identify last known good version
PREVIOUS_VERSION="v1.1.0"
```

#### Step 3: Backup Current State

```bash
# Create backup directory
BACKUP_DIR="backups/manual-rollback-$(date +%s)"
mkdir -p "$BACKUP_DIR"

# Backup configurations
cp config/deployment.json "$BACKUP_DIR/"
cp config/model_versions.json "$BACKUP_DIR/"
cp config/production.json "$BACKUP_DIR/"

# Save metadata
cat > "$BACKUP_DIR/metadata.json" <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "reason": "Manual rollback",
  "previous_version": "$PREVIOUS_VERSION"
}
EOF
```

#### Step 4: Restore Previous Version

```bash
# Update model version configuration
jq --arg ver "$PREVIOUS_VERSION" '
  .production = $ver |
  .versions |= map(
    if .version == $ver then .status = "production"
    else . end
  )
' config/model_versions.json > config/model_versions.json.tmp
mv config/model_versions.json.tmp config/model_versions.json

# Verify change
cat config/model_versions.json | jq '.production'
```

#### Step 5: Verify Model Files

```bash
# Check model directory exists
ls -la "models/$PREVIOUS_VERSION/"

# Verify required files
test -f "models/$PREVIOUS_VERSION/adapter_model.bin" && echo "✓ Model file exists"
test -f "models/$PREVIOUS_VERSION/adapter_config.json" && echo "✓ Config exists"
test -f "models/$PREVIOUS_VERSION/model_metadata.json" && echo "✓ Metadata exists"
```

#### Step 6: Restart Services

```bash
# Start application
npm run dev &

# Wait for startup
sleep 10

# Verify running
ps aux | grep node | grep huntress
```

#### Step 7: Verify Rollback

```bash
# Check health
curl http://localhost:5173/api/health

# Check version
curl http://localhost:5173/api/version

# Monitor logs
tail -f logs/application.log
```

---

## Post-Rollback Verification

### Verification Checklist

#### 1. System Health

```bash
# Run health check
node -e "
const { HealthCheckSystem } = require('./src/core/training/health_checker');
// Execute health check
"

# Expected: All components healthy
```

#### 2. Model Version

```bash
# Verify production version
jq '.production' config/model_versions.json

# Check model status
jq '.versions[] | select(.status=="production")' config/model_versions.json
```

#### 3. Performance Metrics

```bash
# Check current metrics
cat models/metrics/metrics_latest.json

# Verify success rate > 70%
jq '.successRate' models/metrics/metrics_latest.json

# Verify FP rate < 10%
jq '.falsePositiveRate' models/metrics/metrics_latest.json
```

#### 4. Configuration Integrity

```bash
# Verify deployment config
cat config/deployment.json | jq '.'

# Check training config
cat config/training_config.json | jq '.'

# Validate production config
cat config/production.json | jq '.'
```

#### 5. Service Availability

```bash
# Check Node.js process
pgrep -f "node.*huntress"

# Check Qdrant
curl http://localhost:6333/collections

# Check dashboard
curl http://localhost:5173/
```

### Verification Tests

Run these tests to confirm rollback success:

```bash
# 1. Health check test
npm run test:health

# 2. Integration test
npm run test:integration

# 3. Performance test
npm run test:performance

# 4. End-to-end test
npm run test:e2e
```

---

## Rollback Scenarios

### Scenario 1: Performance Degradation

**Trigger:** Success rate drops from 75% to 55%

**Procedure:**
```bash
# 1. Confirm degradation
cat models/metrics/metrics_latest.json | jq '.successRate'

# 2. Execute rollback
./scripts/deploy_production.sh --rollback

# 3. Monitor recovery
watch -n 5 'cat models/metrics/metrics_latest.json | jq ".successRate"'

# 4. Verify improvement
# Expected: Success rate returns to ~75%
```

**Post-Rollback:**
- Investigate root cause of degradation
- Review training data quality
- Analyze model changes
- Plan corrective actions

### Scenario 2: Health Check Failure

**Trigger:** Qdrant connection fails

**Procedure:**
```bash
# 1. Verify failure
curl http://localhost:6333/collections
# Expected: Connection refused

# 2. Attempt service restart
docker restart qdrant
sleep 10

# 3. If restart fails, rollback
./scripts/deploy_production.sh --rollback

# 4. Verify Qdrant health
curl http://localhost:6333/collections
```

**Post-Rollback:**
- Check Qdrant logs
- Verify data integrity
- Test connection
- Restore service

### Scenario 3: Deployment Failure

**Trigger:** Model validation fails during deployment

**Procedure:**
```bash
# 1. Deployment automatically blocks
# No rollback needed - deployment never completed

# 2. Review validation errors
cat logs/deployments/deploy_*/validation_report.md

# 3. Fix issues
# - Retrain model
# - Adjust thresholds
# - Collect more data

# 4. Retry deployment
./scripts/deploy_production.sh --model-version v1.2.1
```

### Scenario 4: Corrupted Model Files

**Trigger:** Model fails to load

**Procedure:**
```bash
# 1. Verify corruption
ls -la models/v1.2.0/
md5sum models/v1.2.0/adapter_model.bin

# 2. Immediate rollback
./scripts/deploy_production.sh --rollback

# 3. Restore from backup
cp -r backups/models/v1.2.0/ models/

# 4. Verify integrity
md5sum models/v1.2.0/adapter_model.bin
```

**Post-Rollback:**
- Investigate corruption cause
- Check disk health
- Verify backup procedures
- Retrain if necessary

---

## Recovery Procedures

### Failed Rollback Recovery

If rollback itself fails:

#### 1. Assess Situation

```bash
# Check rollback logs
tail -100 logs/deployments/rollback_*/rollback.log

# Identify failure point
grep -i "error\|failed" logs/deployments/rollback_*/rollback.log

# Check system state
ps aux | grep -E "node|python"
df -h
free -h
```

#### 2. Emergency Recovery

```bash
# Stop all services
pkill -9 -f "node.*huntress"
pkill -9 -f "python.*huntress"

# Restore from oldest backup
OLDEST_BACKUP=$(ls -t backups/deployments/ | tail -1)
cp -r "backups/deployments/$OLDEST_BACKUP/"* config/

# Restart services
npm run dev
```

#### 3. Manual Intervention

If automated recovery fails, follow [Manual Rollback](#manual-rollback) procedure.

### Data Recovery

If data is lost during rollback:

```bash
# 1. Check backup availability
ls -lt backups/

# 2. Restore training data
cp backups/training_data_*.json config/training_data.json

# 3. Restore model versions
cp backups/model_versions_*.json config/model_versions.json

# 4. Verify integrity
jq '.examples | length' config/training_data.json
jq '.versions | length' config/model_versions.json
```

### System Recovery

Complete system recovery procedure:

```bash
# 1. Stop everything
./scripts/stop_all.sh

# 2. Clean temporary files
rm -rf /tmp/huntress-*
rm -rf logs/*.tmp

# 3. Restore from backup
./scripts/restore_backup.sh --backup-id latest

# 4. Verify configuration
./scripts/verify_config.sh

# 5. Start services
./scripts/start_all.sh

# 6. Run health checks
./scripts/health_check.sh
```

---

## Rollback History

### Viewing Rollback History

```bash
# List all rollbacks
ls -lt models/rollback-history/

# View specific rollback
cat models/rollback-history/rollback_*.json | jq '.'

# Summary statistics
node -e "
const { RollbackManager } = require('./src/core/training/rollback_manager');
const manager = new RollbackManager(/* ... */);
const history = manager.getRollbackHistory();
console.log('Total rollbacks:', history.totalRollbacks);
console.log('Successful:', history.successfulRollbacks);
console.log('Failed:', history.failedRollbacks);
console.log('Avg duration:', history.avgDuration, 'ms');
"
```

### Rollback Report

Generate detailed rollback report:

```typescript
import { RollbackManager } from './src/core/training/rollback_manager';

const rollback = await loadRollbackOperation('rollback_123');
const report = rollbackManager.generateReport(rollback);

console.log(report);
```

**Report includes:**
- Operation ID and timestamp
- Success/failure status
- Duration
- Reason and details
- Step-by-step execution
- Validation results
- Issues encountered

### Audit Trail

All rollbacks are logged to audit trail:

```bash
# View audit log
cat logs/rollback_audit.log

# Filter by date
grep "2025-01-23" logs/rollback_audit.log

# Filter by reason
grep "performance_degradation" logs/rollback_audit.log
```

---

## Best Practices

### Rollback Preparation

1. **Regular Backups**
   - Automated before each deployment
   - Manual backups before major changes
   - Verify backup integrity weekly

2. **Test Rollback Procedures**
   - Monthly rollback drills
   - Test in staging environment
   - Document lessons learned

3. **Maintain Documentation**
   - Keep procedures updated
   - Document special cases
   - Share knowledge with team

### During Rollback

1. **Communication**
   - Notify stakeholders immediately
   - Provide status updates
   - Document decisions

2. **Monitoring**
   - Watch metrics closely
   - Monitor system resources
   - Check for side effects

3. **Documentation**
   - Log all actions
   - Capture error messages
   - Note unusual behavior

### After Rollback

1. **Root Cause Analysis**
   - Investigate failure cause
   - Document findings
   - Implement preventive measures

2. **System Verification**
   - Run comprehensive tests
   - Monitor for 24 hours
   - Verify all functionality

3. **Process Improvement**
   - Review rollback procedure
   - Update documentation
   - Train team members

---

## Emergency Contacts

### Escalation Path

| Level | Contact | Response Time |
|-------|---------|---------------|
| L1 | Operations Team | Immediate |
| L2 | Engineering Lead | 15 minutes |
| L3 | CTO | 30 minutes |
| L4 | CEO | 1 hour |

### Communication Channels

- **Slack**: #huntress-ops
- **Email**: ops@huntress.com
- **Phone**: +1-XXX-XXX-XXXX (24/7)
- **Status Page**: status.huntress.com

---

## Appendix: Quick Reference

### One-Line Rollback

```bash
./scripts/deploy_production.sh --rollback
```

### Rollback with Dry-Run

```bash
./scripts/deploy_production.sh --rollback --dry-run
```

### Check Rollback Status

```bash
cat models/rollback-history/rollback_latest.json | jq '.success'
```

### Verify System Health

```bash
curl http://localhost:5173/api/health | jq '.overallStatus'
```

### View Recent Logs

```bash
tail -f logs/deployments/rollback_*/rollback.log
```

---

**Last Updated:** 2025-01-23  
**Version:** 1.0.0  
**Maintainer:** Huntress Development Team  
**Emergency Contact:** ops@huntress.com