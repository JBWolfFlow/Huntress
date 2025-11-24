# Quick Start Guide: Phase 5 Continuous Learning System

**Last Updated:** 2025-11-23  
**Estimated Setup Time:** 2-4 hours (depending on download speeds)

---

## Overview

This guide will help you set up and run the Phase 5 continuous learning system, which enables Huntress to automatically improve through training on HackTheBox machines using local LoRA fine-tuning of Llama-3.1-70B.

---

## Prerequisites Checklist

### Hardware Requirements
- [ ] NVIDIA GPU with 24GB+ VRAM (RTX 3090, RTX 4090, or A100)
- [ ] 64GB+ system RAM
- [ ] 500GB+ free disk space (for models and training data)
- [ ] Stable internet connection (for initial downloads)

### Software Requirements
- [ ] Ubuntu 20.04+ or Kali Linux
- [ ] CUDA 11.8 or higher
- [ ] Python 3.10+
- [ ] Node.js 18+
- [ ] Docker and Docker Compose
- [ ] Git

### Account Requirements
- [ ] HackTheBox subscription (VIP or VIP+)
- [ ] HackTheBox API token
- [ ] HuggingFace account
- [ ] HuggingFace token (with Llama access approved)
- [ ] OpenAI API key (for embeddings)

---

## Step 1: Verify GPU and CUDA

```bash
# Check NVIDIA GPU
nvidia-smi

# Expected output: GPU name, memory, CUDA version
# Example: Tesla A100-SXM4-80GB, CUDA Version: 12.0

# Check CUDA version
nvcc --version

# If CUDA < 11.8, install/upgrade:
# https://developer.nvidia.com/cuda-downloads
```

**Minimum Requirements:**
- GPU Memory: 24GB+ VRAM
- CUDA Version: 11.8+

---

## Step 2: Install System Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python 3.10+
sudo apt install python3.10 python3.10-venv python3-pip -y

# Install Node.js 18+
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install nodejs -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo apt install docker-compose -y

# Verify installations
python3 --version  # Should be 3.10+
node --version     # Should be 18+
docker --version
nvidia-smi         # Should show GPU info
```

---

## Step 3: Clone and Setup Huntress

```bash
# Clone repository (if not already done)
cd ~/Desktop
git clone <repository-url> Huntress
cd Huntress

# Install Node.js dependencies
npm install
npm install recharts  # For training dashboard

# Install Rust dependencies (if not already done)
cd src-tauri
cargo build
cd ..
```

---

## Step 4: Configure Environment Variables

```bash
# Copy environment template
cp config/.env.example .env

# Edit .env file
nano .env
```

**Required Environment Variables:**

```bash
# HackTheBox API (Required for Phase 5)
HTB_API_TOKEN=your_htb_api_token_here

# HuggingFace API (Required for Phase 5 LoRA Training)
HUGGINGFACE_TOKEN=hf_your_huggingface_token_here

# OpenAI API (Required for embeddings)
OPENAI_API_KEY=sk-your_openai_api_key_here

# Qdrant Vector Database
QDRANT_URL=http://localhost:6333

# Anthropic Claude (for AI supervision)
ANTHROPIC_API_KEY=sk-ant-your_anthropic_key_here

# HackerOne API (for reporting)
HACKERONE_API_KEY=your_hackerone_api_key_here
HACKERONE_API_SECRET=your_hackerone_api_secret_here
```

**How to Get API Tokens:**

1. **HTB API Token:**
   - Go to https://www.hackthebox.com/home/settings/api
   - Generate new API token
   - Copy token to `.env`

2. **HuggingFace Token:**
   - Go to https://huggingface.co/settings/tokens
   - Create new token with "Read" access
   - Request access to Llama-3.1-70B: https://huggingface.co/meta-llama/Llama-3.1-70B-Instruct
   - Wait for approval (usually instant)
   - Copy token to `.env`

3. **OpenAI API Key:**
   - Go to https://platform.openai.com/api-keys
   - Create new secret key
   - Copy key to `.env`

---

## Step 5: Start Qdrant Vector Database

```bash
# Start Qdrant using Docker Compose
docker-compose up -d

# Verify Qdrant is running
curl http://localhost:6333/health

# Expected output: {"status":"ok"}

# View Qdrant logs (optional)
docker-compose logs -f qdrant
```

---

## Step 6: Setup Axolotl for LoRA Training

```bash
# Make setup script executable
chmod +x scripts/setup_axolotl.sh

# Run Axolotl setup (takes 10-15 minutes)
./scripts/setup_axolotl.sh

# The script will:
# 1. Create Python virtual environment
# 2. Install Axolotl and dependencies
# 3. Verify CUDA compatibility
# 4. Check GPU memory
# 5. Setup HuggingFace authentication
# 6. Create necessary directories

# Activate Axolotl environment
source venv/axolotl/bin/activate
```

**Troubleshooting:**
- If CUDA errors occur, ensure CUDA 11.8+ is installed
- If memory errors occur, ensure 64GB+ RAM available
- If HuggingFace errors occur, verify token and Llama access

---

## Step 7: Download Llama-3.1-70B Base Model

```bash
# Activate Axolotl environment (if not already)
source venv/axolotl/bin/activate

# Login to HuggingFace
huggingface-cli login
# Paste your HuggingFace token when prompted

# Download Llama-3.1-70B-Instruct (takes 1-2 hours, ~140GB)
huggingface-cli download meta-llama/Llama-3.1-70B-Instruct \
  --local-dir models/llama-3.1-70b \
  --local-dir-use-symlinks False

# Verify download
ls -lh models/llama-3.1-70b/
# Should see model files totaling ~140GB
```

**Note:** This is a large download. Ensure stable internet connection.

---

## Step 8: Run First HTB Training Session

```bash
# Ensure HTB_API_TOKEN is set in .env
source .env

# Run single HTB training session (takes 1-2 hours)
python scripts/htb_runner.py --sessions 1

# The script will:
# 1. Select an Easy HTB machine
# 2. Spawn the machine
# 3. Run Huntress agent
# 4. Collect training data
# 5. Store in Qdrant
# 6. Terminate machine

# Monitor progress
tail -f htb_runner.log
```

**Expected Output:**
```
[INFO] HTB Runner started
[INFO] Selected machine: Lame (Easy)
[INFO] Spawning machine...
[INFO] Machine spawned: 10.10.10.3
[INFO] Running agent...
[INFO] Agent completed
[INFO] Flags found: 2/2
[INFO] Training data collected
[INFO] Quality score: 0.85
[INFO] Stored in Qdrant
[INFO] Session complete
```

---

## Step 9: Format Training Data

```bash
# Format collected data for Axolotl training
python scripts/format_training_data.py \
  --qdrant-url http://localhost:6333 \
  --collection training_data \
  --output training_data/htb_sessions.jsonl \
  --quality-threshold 0.6 \
  --max-examples 100

# Verify formatted data
ls -lh training_data/
# Should see:
# - htb_sessions.jsonl (training set)
# - htb_sessions_val.jsonl (validation set)
# - htb_sessions_stats.json (statistics)

# View statistics
cat training_data/htb_sessions_stats.json
```

---

## Step 10: Run First Training Job

```bash
# Activate Axolotl environment
source venv/axolotl/bin/activate

# Start training (takes 30 minutes - 3 hours depending on data size)
axolotl train config/axolotl_config.yml

# Monitor GPU usage in another terminal
watch -n 1 nvidia-smi

# Training will:
# 1. Load Llama-3.1-70B in 8-bit
# 2. Train LoRA adapters
# 3. Save checkpoints every epoch
# 4. Generate final model

# Output directory: models/huntress-lora-v1/
```

**Expected Training Output:**
```
Loading base model...
Model loaded in 8-bit: 70GB VRAM
Training LoRA adapters (rank=32)...
Epoch 1/3: loss=0.45, lr=2e-4
Epoch 2/3: loss=0.32, lr=1.5e-4
Epoch 3/3: loss=0.28, lr=1e-4
Training complete!
Saved to: models/huntress-lora-v1/
```

---

## Step 11: Launch Training Dashboard

```bash
# In a new terminal, start the development server
cd ~/Desktop/Huntress
npm run dev

# Open browser to:
# http://localhost:5173/dashboard

# The dashboard shows:
# - Real-time performance metrics
# - Training status and progress
# - Model version history
# - A/B test results
# - Resource usage graphs
# - Alert notifications
# - Manual controls
```

---

## Step 12: Deploy Trained Model

```bash
# Deploy model to production using deployment script
./scripts/deploy_production.sh \
  --model-version v20251123-150000 \
  --strategy gradual

# The script will:
# 1. Validate model
# 2. Backup current state
# 3. Deploy to 10% traffic
# 4. Monitor health
# 5. Deploy to 50% traffic
# 6. Monitor health
# 7. Deploy to 100% traffic
# 8. Verify deployment

# Monitor deployment
tail -f logs/deployment.log
```

---

## Step 13: Start Continuous Learning Loop

```typescript
// In your application code or via dashboard

import { createContinuousLearningSystem } from './src/core/training';
import { QdrantClient } from './src/core/memory/qdrant_client';

// Initialize Qdrant
const qdrant = new QdrantClient({
  url: process.env.QDRANT_URL || 'http://localhost:6333',
});

// Create continuous learning system
const system = createContinuousLearningSystem(qdrant);

// Initialize and start
await system.initialize();
await system.start();

console.log('Continuous learning system started!');

// The system will now:
// - Monitor for training triggers
// - Automatically collect data from HTB
// - Train new models when triggered
// - Run A/B tests
// - Deploy winning models
// - Monitor performance
// - Rollback on issues
```

---

## Verification Checklist

After completing all steps, verify:

- [ ] GPU is detected and has 24GB+ VRAM
- [ ] CUDA 11.8+ is installed
- [ ] All environment variables are set in `.env`
- [ ] Qdrant is running at http://localhost:6333
- [ ] Axolotl environment is created
- [ ] Llama-3.1-70B model is downloaded (~140GB)
- [ ] First HTB session completed successfully
- [ ] Training data is formatted and stored
- [ ] First training job completed
- [ ] Model is deployed
- [ ] Dashboard is accessible at http://localhost:5173/dashboard
- [ ] Continuous learning loop is running

---

## Common Issues and Solutions

### Issue: CUDA Out of Memory

**Solution:**
```bash
# Reduce batch size in config/axolotl_config.yml
micro_batch_size: 1  # Instead of 2
gradient_accumulation_steps: 8  # Instead of 4

# Or use smaller model
# Download Llama-3.1-8B instead of 70B
```

### Issue: HTB API Rate Limiting

**Solution:**
```bash
# Increase delay between sessions
python scripts/htb_runner.py --sessions 5 --delay 600  # 10 min delay
```

### Issue: Training Job Fails

**Solution:**
```bash
# Check logs
tail -f logs/training.log

# Verify GPU memory
nvidia-smi

# Check disk space
df -h

# Restart training with checkpoint
axolotl train config/axolotl_config.yml --resume_from_checkpoint
```

### Issue: Qdrant Connection Failed

**Solution:**
```bash
# Restart Qdrant
docker-compose restart qdrant

# Check Qdrant logs
docker-compose logs qdrant

# Verify port is not in use
sudo netstat -tulpn | grep 6333
```

### Issue: Model Download Fails

**Solution:**
```bash
# Verify HuggingFace token
huggingface-cli whoami

# Check Llama access
# Visit: https://huggingface.co/meta-llama/Llama-3.1-70B-Instruct

# Resume download
huggingface-cli download meta-llama/Llama-3.1-70B-Instruct \
  --local-dir models/llama-3.1-70b \
  --resume-download
```

---

## Next Steps

After successful setup:

1. **Run Multiple HTB Sessions:**
   ```bash
   python scripts/htb_runner.py --sessions 10 --delay 300
   ```

2. **Monitor Performance:**
   - Check dashboard regularly
   - Review training metrics
   - Analyze A/B test results

3. **Optimize Configuration:**
   - Adjust quality thresholds
   - Tune training parameters
   - Configure alert rules

4. **Scale Up:**
   - Increase HTB session frequency
   - Train on more machines
   - Deploy to production

---

## Additional Resources

- **Full Documentation:** [`PHASE5_COMPLETE.md`](PHASE5_COMPLETE.md)
- **Troubleshooting Guide:** [`docs/PHASE5_TROUBLESHOOTING.md`](docs/PHASE5_TROUBLESHOOTING.md)
- **Monitoring Guide:** [`docs/PHASE5_MONITORING.md`](docs/PHASE5_MONITORING.md)
- **Rollback Procedures:** [`docs/PHASE5_ROLLBACK_PROCEDURE.md`](docs/PHASE5_ROLLBACK_PROCEDURE.md)
- **Architecture Overview:** [`docs/PHASE5_ARCHITECTURE.md`](docs/PHASE5_ARCHITECTURE.md)

---

## Support

For issues or questions:
1. Check troubleshooting guide
2. Review logs in `logs/` directory
3. Check dashboard for alerts
4. Verify all prerequisites are met

---

**Congratulations!** You've successfully set up the Phase 5 continuous learning system. Huntress will now automatically improve through training on HackTheBox machines.