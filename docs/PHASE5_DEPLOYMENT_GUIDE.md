# Phase 5.4: Production Deployment Guide

**Version:** 1.0  
**Date:** 2025-11-23  
**Status:** Production Ready  

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Pre-Deployment Checklist](#pre-deployment-checklist)
4. [Deployment Process](#deployment-process)
5. [Validation Steps](#validation-steps)
6. [Rollback Procedures](#rollback-procedures)
7. [Post-Deployment Monitoring](#post-deployment-monitoring)
8. [Troubleshooting](#troubleshooting)

---

## Overview

This guide provides step-by-step instructions for deploying Phase 5.4 components to production. Phase 5.4 implements comprehensive validation and production deployment capabilities for the HTB training loop system.

### Components Deployed

- **Validation Test Suite** - Comprehensive model validation with 20-machine test set
- **Production Readiness Checker** - Pre-deployment validation gates
- **Rollback Manager** - Emergency rollback capability (<5 minutes)
- **Health Checker** - Continuous system health monitoring
- **Deployment Automation** - Automated deployment orchestration
- **Monitoring Dashboard** - Real-time performance visualization

### Success Criteria

- ✅ Success rate ≥ 65% on test set
- ✅ False positive rate ≤ 15%
- ✅ Average execution time ≤ 2 hours
- ✅ All health checks passing
- ✅ Rollback capability verified

---

## Prerequisites

### System Requirements

**Minimum:**
- Ubuntu 20.04+ or similar Linux distribution
- Node.js 18+
- Python 3.9+
- 64GB RAM
- 500GB SSD storage
- NVIDIA GPU with 24GB+ VRAM (RTX 3090 or better)

**Recommended:**
- Ubuntu 22.04 LTS
- Node.js 20+
- Python 3.11+
- 128GB RAM
- 1TB NVMe SSD
- NVIDIA A100 (40GB/80GB) or H100

### Software Dependencies

```bash
# Node.js packages
npm install

# Python packages
pip install -r requirements.txt

# System packages
sudo apt-get install -y \
  build-essential \
  git \
  curl \
  nvidia-cuda-toolkit
```

### Configuration Files

Ensure the following configuration files are present:

- [`config/validation.json`](../config/validation.json) - Validation test configuration
- [`config/production.json`](../config/production.json) - Production deployment settings
- [`config/monitoring.json`](../config/monitoring.json) - Monitoring configuration
- [`config/deployment.json`](../config/deployment.json) - Deployment strategy
- [`.env`](../.env) - Environment variables (HTB API keys, etc.)

### Access Requirements

- HTB VIP subscription with API access
- Admin access to production environment
- SSH access to deployment servers
- Access to monitoring dashboards

---

## Pre-Deployment Checklist

### 1. Environment Verification

```bash
# Check Node.js version
node --version  # Should be 18+

# Check Python version
python3 --version  # Should be 3.9+

# Check CUDA availability
nvidia-smi

# Check disk space
df -h .  # Should have 100GB+ available

# Check memory
free -h  # Should have 32GB+ available
```

### 2. Configuration Validation

```bash
# Validate configuration files
npm run config:validate

# Check environment variables
npm run env:check
```

### 3. Dependency Check

```bash
# Verify all dependencies installed
npm run deps:check

# Run dependency audit
npm audit
```

### 4. Database Health

```bash
# Check Qdrant connection
curl http://localhost:6333/health

# Verify collections exist
npm run qdrant:check
```

### 5. Backup Current State

```bash
# Backup current production model
npm run backup:create

# Verify backup
npm run backup:verify
```

---

## Deployment Process

### Step 1: Run Validation Tests

```bash
# Run comprehensive validation suite
npm run test:validation

# Expected output:
# ✅ 20/20 machines tested
# ✅ Success rate: 67.5%
# ✅ False positive rate: 12.3%
# ✅ All quality gates passed
```

**Validation Report Location:** `test-reports/phase5-validation/`

### Step 2: Production Readiness Check

```bash
# Run readiness checker
npm run deploy:check-readiness -- --model v20251123-214500

# Expected output:
# ✅ Model Quality Gates: PASSED
# ✅ System Health: PASSED
# ✅ Configuration: PASSED
# ✅ Dependencies: PASSED
# ✅ Security Audit: PASSED
# ✅ Performance Benchmarks: PASSED
# ✅ Rollback Capability: PASSED
# 
# Overall Status: READY FOR PRODUCTION
```

**Readiness Report Location:** `models/readiness-reports/`

### Step 3: Execute Deployment

```bash
# Deploy to production with gradual rollout
npm run deploy:production -- \
  --model v20251123-214500 \
  --strategy gradual \
  --approve

# Deployment stages:
# Stage 1: 10% traffic (60 minutes)
# Stage 2: 50% traffic (120 minutes)
# Stage 3: 100% traffic (full deployment)
```

**Deployment Progress:**

```
[Deploy] Starting deployment deploy_1732400000_abc123
[Deploy] Model: v20251123-214500
[Deploy] Strategy: gradual

[Deploy] Stage 1/3: Initial Rollout (10% traffic)
[Deploy] ✅ Traffic updated: 10%
[Deploy] ⏳ Monitoring for 60 minutes...
[Deploy] ✅ Health checks passing
[Deploy] ✅ Performance acceptable
[Deploy] ✅ Stage 1 completed

[Deploy] Stage 2/3: Expanded Rollout (50% traffic)
[Deploy] ✅ Traffic updated: 50%
[Deploy] ⏳ Monitoring for 120 minutes...
[Deploy] ✅ Health checks passing
[Deploy] ✅ Performance acceptable
[Deploy] ✅ Stage 2 completed

[Deploy] Stage 3/3: Full Deployment (100% traffic)
[Deploy] ✅ Model promoted to production
[Deploy] ✅ Traffic updated: 100%
[Deploy] ✅ Post-deployment verification passed

[Deploy] ✅ Deployment completed successfully
[Deploy] Duration: 3h 15m
```

### Step 4: Post-Deployment Verification

```bash
# Verify deployment
npm run deploy:verify

# Check production model
npm run model:current

# Run smoke tests
npm run test:smoke
```

---

## Validation Steps

### Automated Validation

The validation test suite automatically runs:

1. **HTB Machine Tests** (20 machines)
   - 10 Easy machines
   - 7 Medium machines
   - 3 Hard machines

2. **Performance Benchmarks**
   - Success rate measurement
   - Execution time analysis
   - False positive rate tracking

3. **Statistical Tests**
   - Chi-square test for success rate
   - T-test for execution time
   - Effect size calculation

4. **Regression Detection**
   - Performance vs baseline
   - False positive comparison

### Manual Validation

After automated tests pass, perform manual validation:

```bash
# 1. Test on sample machine
npm run test:manual -- --machine "Lame"

# 2. Verify output quality
npm run test:verify-output

# 3. Check false positives
npm run test:check-fp

# 4. Review execution logs
tail -f logs/deployment.log
```

---

## Rollback Procedures

### Automatic Rollback

Automatic rollback triggers on:

- Performance drop > 15%
- Error rate > 10%
- 3 consecutive health check failures

### Manual Rollback

#### Emergency Rollback (< 5 minutes)

```bash
# Execute emergency rollback
npm run rollback:emergency -- \
  --reason "performance_degradation" \
  --details "Success rate dropped to 45%"

# Expected output:
# [Rollback] Starting rollback rollback_1732400000_xyz789
# [Rollback] Reason: performance_degradation
# [Rollback] ✅ Backup Current State (1.2s)
# [Rollback] ✅ Rollback Model Version (2.5s)
# [Rollback] ✅ Restore Configuration (0.8s)
# [Rollback] ✅ Verify State Consistency (1.1s)
# [Rollback] ✅ Run Validation Tests (45.3s)
# [Rollback] ✅ Run Health Checks (3.2s)
# [Rollback] ✅ Verify Performance (2.1s)
# 
# [Rollback] ✅ Rollback completed successfully
# [Rollback] Duration: 56.2s
# [Rollback] Rolled back from v20251123-214500 to v20251122-183000
```

#### Verify Rollback

```bash
# Check current production version
npm run model:current

# Verify system health
npm run health:check

# Run validation tests
npm run test:validation -- --quick
```

### Rollback Validation

After rollback, verify:

1. ✅ Model version restored
2. ✅ Configuration restored
3. ✅ State consistency verified
4. ✅ Health checks passing
5. ✅ Performance acceptable

---

## Post-Deployment Monitoring

### Real-Time Monitoring

```bash
# Start monitoring dashboard
npm run monitor:dashboard

# View in browser: http://localhost:3000/monitoring
```

### Key Metrics to Monitor

**Performance Metrics:**
- Success rate (target: ≥65%)
- False positive rate (target: ≤15%)
- Average execution time (target: ≤2 hours)

**System Health:**
- Qdrant connection status
- GPU utilization
- Memory usage
- Disk space

**Quality Metrics:**
- Validation loss
- Training accuracy
- Data quality score

### Monitoring Commands

```bash
# View current metrics
npm run monitor:current

# View performance trends
npm run monitor:trends

# Check for anomalies
npm run monitor:anomalies

# Export metrics
npm run monitor:export -- --format json --output metrics.json
```

### Alert Configuration

Alerts are configured in [`config/monitoring.json`](../config/monitoring.json):

- **Critical:** Performance drop >15%, resource exhaustion
- **High:** False positive spike, execution time increase
- **Medium:** Minor performance degradation
- **Low:** Informational alerts

---

## Troubleshooting

### Common Issues

#### 1. Validation Tests Failing

**Symptom:** Success rate < 65%

**Solution:**
```bash
# Check model quality
npm run model:analyze -- --model v20251123-214500

# Review failed machines
npm run test:review-failures

# Retrain if necessary
npm run train:retrain -- --additional-data
```

#### 2. Deployment Stuck

**Symptom:** Deployment not progressing

**Solution:**
```bash
# Check deployment status
npm run deploy:status

# View deployment logs
tail -f logs/deployment.log

# Cancel if necessary
npm run deploy:cancel

# Rollback
npm run rollback:emergency
```

#### 3. Health Checks Failing

**Symptom:** Health checks not passing

**Solution:**
```bash
# Run detailed health check
npm run health:check --verbose

# Check specific components
npm run health:check --component qdrant
npm run health:check --component gpu
npm run health:check --component filesystem

# Restart services if needed
npm run services:restart
```

#### 4. Performance Degradation

**Symptom:** Success rate dropping after deployment

**Solution:**
```bash
# Analyze performance
npm run monitor:analyze

# Compare to baseline
npm run monitor:compare-baseline

# Rollback if severe
npm run rollback:emergency -- \
  --reason "performance_degradation" \
  --details "Success rate dropped from 67% to 52%"
```

#### 5. Rollback Fails

**Symptom:** Rollback operation fails

**Solution:**
```bash
# Check rollback logs
tail -f logs/rollback.log

# Verify previous version exists
npm run model:list --status archived

# Manual rollback
npm run model:restore -- --version v20251122-183000

# Verify restoration
npm run model:verify
```

### Getting Help

**Documentation:**
- [Troubleshooting Guide](./PHASE5_TROUBLESHOOTING.md)
- [Monitoring Guide](./PHASE5_MONITORING.md)
- [Rollback Procedures](./PHASE5_ROLLBACK_PROCEDURE.md)

**Logs:**
- Deployment: `logs/deployment.log`
- Rollback: `logs/rollback.log`
- Health: `logs/health.log`
- Monitoring: `logs/monitoring.log`

**Support:**
- Check logs first
- Review documentation
- Contact system administrator

---

## Success Verification

After deployment, verify success:

```bash
# Run full verification suite
npm run deploy:verify-success

# Expected output:
# ✅ Model deployed: v20251123-214500
# ✅ Production status: active
# ✅ Success rate: 67.5%
# ✅ False positive rate: 12.3%
# ✅ Health checks: all passing
# ✅ Monitoring: active
# ✅ Rollback capability: verified
# 
# 🎉 Deployment successful!
```

---

## Maintenance

### Daily Tasks

```bash
# Check system health
npm run health:check

# Review metrics
npm run monitor:daily-report

# Check for alerts
npm run monitor:alerts
```

### Weekly Tasks

```bash
# Review performance trends
npm run monitor:weekly-report

# Check disk space
npm run system:check-disk

# Backup models
npm run backup:weekly
```

### Monthly Tasks

```bash
# Generate monthly report
npm run monitor:monthly-report

# Review and archive old data
npm run data:archive

# Update dependencies
npm run deps:update
```

---

## Appendix

### Configuration Reference

- **Validation:** [`config/validation.json`](../config/validation.json)
- **Production:** [`config/production.json`](../config/production.json)
- **Monitoring:** [`config/monitoring.json`](../config/monitoring.json)
- **Deployment:** [`config/deployment.json`](../config/deployment.json)

### API Reference

- **Model Manager:** [`src/core/training/model_manager.ts`](../src/core/training/model_manager.ts)
- **Deployment Manager:** [`src/core/training/deployment_manager.ts`](../src/core/training/deployment_manager.ts)
- **Rollback Manager:** [`src/core/training/rollback_manager.ts`](../src/core/training/rollback_manager.ts)
- **Readiness Checker:** [`src/core/training/readiness_checker.ts`](../src/core/training/readiness_checker.ts)

### Test Reference

- **Validation Tests:** [`src/tests/phase5_validation.test.ts`](../src/tests/phase5_validation.test.ts)

---

**Document Version:** 1.0  
**Last Updated:** 2025-11-23  
**Next Review:** After first production deployment