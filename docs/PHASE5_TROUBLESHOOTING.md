# Phase 5 Troubleshooting Guide

Comprehensive troubleshooting guide for the continuous learning system, covering common issues, diagnostic procedures, and solutions.

## Table of Contents

1. [Training Issues](#training-issues)
2. [Deployment Issues](#deployment-issues)
3. [Performance Issues](#performance-issues)
4. [Health Check Issues](#health-check-issues)
5. [Data Collection Issues](#data-collection-issues)
6. [Model Issues](#model-issues)
7. [System Resource Issues](#system-resource-issues)
8. [Integration Issues](#integration-issues)

---

## Training Issues

### Issue: Training Job Fails to Start

**Symptoms:**
- Training status remains "idle"
- No training logs generated
- Error: "Training job failed to start"

**Diagnosis:**
```bash
# Check training manager status
node -e "require('./src/core/training/training_manager').TrainingPipelineManager"

# Check Axolotl installation
python3 -c "import axolotl; print(axolotl.__version__)"

# Check GPU availability
nvidia-smi
```

**Solutions:**

1. **Missing Dependencies:**
   ```bash
   # Reinstall Axolotl
   cd /path/to/axolotl
   pip install -e .
   ```

2. **GPU Not Available:**
   ```bash
   # Check CUDA installation
   nvcc --version
   
   # Verify GPU drivers
   nvidia-smi
   
   # If GPU unavailable, configure CPU training in config/axolotl_config.yml
   ```

3. **Insufficient Training Data:**
   ```bash
   # Check training data count
   ls -l config/training_data.json
   
   # Verify minimum examples met (default: 100)
   jq '.examples | length' config/training_data.json
   ```

---

### Issue: Training Job Hangs or Times Out

**Symptoms:**
- Training progress stuck at specific percentage
- No log updates for extended period
- GPU utilization drops to 0%

**Diagnosis:**
```bash
# Check training process
ps aux | grep axolotl

# Monitor GPU usage
watch -n 1 nvidia-smi

# Check training logs
tail -f logs/training/*.log
```

**Solutions:**

1. **Out of Memory:**
   ```bash
   # Reduce batch size in config/axolotl_config.yml
   # micro_batch_size: 1
   # gradient_accumulation_steps: 8
   ```

2. **Deadlock in Data Loading:**
   ```bash
   # Kill hung process
   pkill -9 -f axolotl
   
   # Restart training with reduced workers
   # num_workers: 1 in config
   ```

3. **Corrupted Training Data:**
   ```bash
   # Validate training data
   python3 scripts/format_training_data.py --validate
   
   # Remove corrupted entries
   python3 scripts/format_training_data.py --clean
   ```

---

### Issue: Training Completes But Model Performance Poor

**Symptoms:**
- Success rate < 60%
- High false positive rate (> 20%)
- Model fails validation

**Diagnosis:**
```bash
# Check training metrics
cat models/v*/training_metrics.json

# Analyze training data quality
node -e "
const { QualityFilter } = require('./src/core/training/data_collector');
const filter = new QualityFilter();
// Check quality scores
"
```

**Solutions:**

1. **Low Quality Training Data:**
   ```bash
   # Increase quality threshold
   # Edit config/training_config.json
   # "qualityThreshold": 0.8
   
   # Re-collect data with stricter filters
   ```

2. **Insufficient Training Examples:**
   ```bash
   # Check example count by difficulty
   jq '.examples | group_by(.target.difficulty) | map({difficulty: .[0].target.difficulty, count: length})' config/training_data.json
   
   # Collect more examples for underrepresented difficulties
   ```

3. **Overfitting:**
   ```bash
   # Increase regularization in config/axolotl_config.yml
   # weight_decay: 0.1
   # dropout: 0.1
   
   # Reduce training epochs
   # num_epochs: 1
   ```

---

## Deployment Issues

### Issue: Deployment Fails Validation

**Symptoms:**
- Pre-deployment validation fails
- Error: "Model does not meet quality gates"
- Deployment blocked

**Diagnosis:**
```bash
# Run readiness checker
./scripts/deploy_production.sh --model-version v1.2.0 --dry-run

# Check validation results
cat logs/deployments/deploy_*/validation_report.md
```

**Solutions:**

1. **Success Rate Below Threshold:**
   ```bash
   # Lower threshold temporarily (not recommended)
   # Edit config/deployment.json
   # "validation": { "minSuccessRate": 0.65 }
   
   # Or retrain model with more data
   ```

2. **False Positive Rate Too High:**
   ```bash
   # Analyze false positives
   jq '.examples[] | select(.learning.false_positives > 0)' config/training_data.json
   
   # Add negative examples to training data
   ```

3. **Insufficient Test Samples:**
   ```bash
   # Run more test cases
   # Minimum 50 samples required
   ```

---

### Issue: Deployment Rollback Triggered

**Symptoms:**
- Automatic rollback during deployment
- Error: "Health check failed during deployment"
- Traffic reverted to previous version

**Diagnosis:**
```bash
# Check deployment logs
cat logs/deployments/deploy_*/deployment.log

# Check health check results
cat logs/health/health_*.json

# Review rollback reason
jq '.rollback.reason' models/rollback-history/rollback_*.json
```

**Solutions:**

1. **Performance Degradation:**
   ```bash
   # Investigate performance drop
   # Compare metrics before/after deployment
   
   # If legitimate issue, fix and redeploy
   # If false alarm, adjust thresholds in config/deployment.json
   ```

2. **Health Check Failures:**
   ```bash
   # Check system health
   node -e "
   const { HealthCheckSystem } = require('./src/core/training/health_checker');
   // Run health checks
   "
   
   # Fix underlying issues before redeploying
   ```

3. **Resource Exhaustion:**
   ```bash
   # Check system resources
   df -h
   free -h
   nvidia-smi
   
   # Free up resources
   # Clean old logs: find logs/ -mtime +30 -delete
   # Clean old models: find models/ -mtime +90 -delete
   ```

---

## Performance Issues

### Issue: Slow Execution Times

**Symptoms:**
- Average execution time > 2 hours
- Timeout errors
- Poor user experience

**Diagnosis:**
```bash
# Check performance metrics
cat models/metrics/metrics_*.json | jq '.avgTimeToSuccess'

# Profile execution
# Enable detailed logging in config/monitoring.json
```

**Solutions:**

1. **Inefficient Tool Usage:**
   ```bash
   # Analyze tool usage patterns
   jq '.execution.tools_used' config/training_data.json
   
   # Optimize tool selection in agents
   ```

2. **Network Latency:**
   ```bash
   # Check HTB API latency
   curl -w "@curl-format.txt" -o /dev/null -s https://labs.hackthebox.com/api/v4/
   
   # Use proxy pool for better performance
   ```

3. **Resource Contention:**
   ```bash
   # Check concurrent executions
   ps aux | grep node | wc -l
   
   # Limit concurrent hunts in config
   ```

---

### Issue: High False Positive Rate

**Symptoms:**
- False positive rate > 15%
- Many invalid findings reported
- Wasted verification time

**Diagnosis:**
```bash
# Analyze false positives
jq '.examples[] | select(.learning.false_positives > 0) | {target: .target.name, fp: .learning.false_positives, techniques: .learning.techniques_learned}' config/training_data.json

# Check validation logic
grep -r "validate" src/agents/
```

**Solutions:**
1. **Weak Validation:**
   ```typescript
   // Strengthen validation in agents
   // Add multiple verification steps
   // Require proof of exploitability
   ```

2. **Overly Aggressive Detection:**
   ```bash
   # Tune detection thresholds
   # Add more negative examples to training data
   ```

3. **Context Misunderstanding:**
   ```bash
   # Improve context gathering
   # Add more reconnaissance steps
   ```

---

## Health Check Issues

### Issue: Health Checks Failing

**Symptoms:**
- Multiple components showing "unhealthy"
- Alerts flooding dashboard
- System degraded

**Diagnosis:**
```bash
# Run manual health check
node -e "
const { HealthCheckSystem } = require('./src/core/training/health_checker');
const { QdrantClient } = require('./src/core/memory/qdrant_client');
const qdrant = new QdrantClient({url: 'http://localhost:6333', collectionName: 'huntress'});
const checker = new HealthCheckSystem(qdrant, {/* config */});
checker.initialize().then(() => checker.performHealthCheck());
"

# Check individual components
systemctl status qdrant
ps aux | grep node
nvidia-smi
```

**Solutions:**

1. **Qdrant Connection Failed:**
   ```bash
   # Restart Qdrant
   docker restart qdrant
   
   # Or if running locally
   systemctl restart qdrant
   
   # Verify connection
   curl http://localhost:6333/collections
   ```

2. **GPU Unavailable:**
   ```bash
   # Check GPU status
   nvidia-smi
   
   # Restart GPU drivers if needed
   sudo rmmod nvidia_uvm nvidia_drm nvidia_modeset nvidia
   sudo modprobe nvidia
   ```

3. **Disk Space Critical:**
   ```bash
   # Clean up space
   find logs/ -mtime +30 -delete
   find backups/ -mtime +90 -delete
   find models/ -name "*.tmp" -delete
   
   # Verify space
   df -h
   ```

---

## Data Collection Issues

### Issue: No New Training Examples

**Symptoms:**
- Training data count not increasing
- Learning loop idle
- No new HTB machines attempted

**Diagnosis:**
```bash
# Check data collection
jq '.examples | length' config/training_data.json

# Check HTB API connectivity
curl -H "Authorization: Bearer $HTB_API_KEY" https://labs.hackthebox.com/api/v4/machine/list

# Check learning loop status
cat models/learning_loop_state.json
```

**Solutions:**

1. **HTB API Issues:**
   ```bash
   # Verify API key
   echo $HTB_API_KEY
   
   # Test API access
   python3 scripts/htb_runner.py --test
   
   # Regenerate API key if needed
   ```

2. **Quality Filter Too Strict:**
   ```bash
   # Lower quality threshold temporarily
   # Edit config/training_config.json
   # "qualityThreshold": 0.6
   ```

3. **No Available Machines:**
   ```bash
   # Check machine availability
   python3 scripts/htb_runner.py --list-machines
   
   # Adjust difficulty filters
   ```

---

## Model Issues

### Issue: Model Files Corrupted

**Symptoms:**
- Error loading model
- "Model not found" despite file existing
- Deployment fails with file errors

**Diagnosis:**
```bash
# Check model files
ls -lh models/v*/

# Verify file integrity
md5sum models/v*/adapter_model.bin

# Check model metadata
cat models/v*/model_metadata.json
```

**Solutions:**

1. **Restore from Backup:**
   ```bash
   # List backups
   ls -lt backups/deployments/
   
   # Restore latest backup
   cp -r backups/deployments/pre-deploy-*/models/v* models/
   ```

2. **Retrain Model:**
   ```bash
   # Force new training cycle
   node -e "
   const { LearningLoopOrchestrator } = require('./src/core/training/learning_loop');
   // Trigger manual training
   "
   ```

3. **Clean and Rebuild:**
   ```bash
   # Remove corrupted model
   rm -rf models/v1.2.0
   
   # Retrain from scratch
   ```

---

## System Resource Issues

### Issue: Out of Memory

**Symptoms:**
- Process killed by OOM killer
- System becomes unresponsive
- Training fails with memory errors

**Diagnosis:**
```bash
# Check memory usage
free -h
ps aux --sort=-%mem | head -10

# Check OOM killer logs
dmesg | grep -i "out of memory"
journalctl -k | grep -i "killed process"
```

**Solutions:**

1. **Reduce Memory Usage:**
   ```bash
   # Reduce batch size
   # Edit config/axolotl_config.yml
   # micro_batch_size: 1
   
   # Limit concurrent processes
   # Edit config/training_config.json
   # "maxConcurrentJobs": 1
   ```

2. **Add Swap Space:**
   ```bash
   # Create swap file
   sudo fallocate -l 8G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile
   ```

3. **Upgrade System:**
   ```bash
   # Consider upgrading RAM
   # Minimum recommended: 16GB
   # Optimal: 32GB+
   ```

---

### Issue: GPU Out of Memory

**Symptoms:**
- CUDA out of memory errors
- Training crashes during forward pass
- GPU memory usage at 100%

**Diagnosis:**
```bash
# Check GPU memory
nvidia-smi

# Monitor GPU usage
watch -n 1 nvidia-smi
```

**Solutions:**

1. **Reduce Batch Size:**
   ```yaml
   # config/axolotl_config.yml
   micro_batch_size: 1
   gradient_accumulation_steps: 16
   ```

2. **Enable Gradient Checkpointing:**
   ```yaml
   # config/axolotl_config.yml
   gradient_checkpointing: true
   ```

3. **Use Smaller Model:**
   ```yaml
   # config/axolotl_config.yml
   base_model: "mistralai/Mistral-7B-v0.1"  # Instead of 13B
   ```

---

## Integration Issues

### Issue: Tauri Commands Failing

**Symptoms:**
- Frontend cannot communicate with backend
- Tool execution fails
- "Command not found" errors

**Diagnosis:**
```bash
# Check Tauri build
cd src-tauri
cargo check

# Test commands
cargo test
```

**Solutions:**

1. **Rebuild Tauri:**
   ```bash
   cd src-tauri
   cargo clean
   cargo build
   ```

2. **Check Command Registration:**
   ```rust
   // Verify in src-tauri/src/main.rs
   // All commands registered in tauri::Builder
   ```

3. **Update Dependencies:**
   ```bash
   cd src-tauri
   cargo update
   ```

---

## Emergency Procedures

### Complete System Reset

If all else fails, perform a complete system reset:

```bash
# 1. Backup current state
./scripts/deploy_production.sh --rollback

# 2. Stop all processes
pkill -f node
pkill -f python
docker stop qdrant

# 3. Clean temporary files
rm -rf logs/*.log
rm -rf models/*.tmp
rm -rf /tmp/huntress-*

# 4. Restart services
docker start qdrant
npm run dev

# 5. Verify health
node -e "require('./src/core/training/health_checker')"
```

### Data Recovery

If training data is lost:

```bash
# 1. Check backups
ls -lt backups/

# 2. Restore from latest backup
cp backups/training_data_*.json config/training_data.json

# 3. Verify integrity
jq '.examples | length' config/training_data.json

# 4. If no backups, re-collect data
python3 scripts/htb_runner.py --collect-all
```

---

## Getting Help

If issues persist:

1. **Check Logs:**
   ```bash
   # Training logs
   tail -f logs/training/*.log
   
   # Deployment logs
   tail -f logs/deployments/*.log
   
   # Health logs
   tail -f logs/health/*.log
   ```

2. **Enable Debug Mode:**
   ```bash
   # Set environment variable
   export DEBUG=huntress:*
   
   # Run with verbose logging
   npm run dev -- --verbose
   ```

3. **Collect Diagnostic Information:**
   ```bash
   # System info
   uname -a
   node --version
   python3 --version
   nvidia-smi
   
   # Configuration
   cat config/*.json
   
   # Recent logs
   tail -100 logs/**/*.log
   ```

4. **Contact Support:**
   - Include diagnostic information
   - Describe steps to reproduce
   - Attach relevant logs
   - Specify system configuration

---

## Preventive Measures

### Regular Maintenance

```bash
# Weekly tasks
- Clean old logs: find logs/ -mtime +30 -delete
- Verify backups: ls -lt backups/
- Check disk space: df -h
- Review alerts: cat logs/alerts.log

# Monthly tasks
- Archive old models: tar -czf models_archive_$(date +%Y%m).tar.gz models/
- Update dependencies: npm update && pip install -U -r requirements.txt
- Review performance trends: node scripts/analyze_metrics.js
- Test rollback procedure: ./scripts/deploy_production.sh --rollback --dry-run
```

### Monitoring Best Practices

1. Set up automated alerts for critical issues
2. Monitor resource usage trends
3. Review performance metrics weekly
4. Test disaster recovery procedures monthly
5. Keep documentation updated

---

## Appendix: Error Codes

| Code | Description | Severity | Action |
|------|-------------|----------|--------|
| E001 | Training job failed | High | Check logs, verify data |
| E002 | Deployment validation failed | High | Review quality gates |
| E003 | Health check failed | Critical | Investigate component |
| E004 | Rollback triggered | High | Review deployment logs |
| E005 | Out of memory | Critical | Reduce batch size |
| E006 | GPU unavailable | Medium | Check drivers |
| E007 | Data collection failed | Medium | Verify HTB API |
| E008 | Model corrupted | High | Restore from backup |

---

**Last Updated:** 2025-01-23  
**Version:** 1.0.0  
**Maintainer:** Huntress Development Team