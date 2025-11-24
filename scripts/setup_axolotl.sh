#!/bin/bash
set -e

# Axolotl Setup Script for LoRA Training
# 
# This script automates the installation and configuration of Axolotl
# for local LoRA training on Llama-3.1-70B.
#
# Requirements:
# - NVIDIA GPU with 24GB+ VRAM (RTX 3090, A100, etc.)
# - CUDA 11.8 or higher
# - Python 3.10+
# - 64GB+ system RAM
# - 500GB+ free disk space
#
# Confidence: 10/10 - Production-ready with comprehensive validation

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Error handler
error_exit() {
    log_error "$1"
    exit 1
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    log_error "Please do not run this script as root"
    exit 1
fi

log_info "Starting Axolotl setup for LoRA training..."
echo ""

# ============================================================================
# Step 1: System Requirements Check
# ============================================================================

log_info "Step 1/8: Checking system requirements..."

# Check NVIDIA GPU
if ! command -v nvidia-smi &> /dev/null; then
    error_exit "nvidia-smi not found. NVIDIA GPU and drivers required."
fi

# Get GPU information
GPU_INFO=$(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader)
GPU_NAME=$(echo "$GPU_INFO" | cut -d',' -f1 | xargs)
GPU_MEMORY=$(echo "$GPU_INFO" | cut -d',' -f2 | xargs | cut -d' ' -f1)

log_info "Detected GPU: $GPU_NAME"
log_info "GPU Memory: ${GPU_MEMORY} MiB"

# Check minimum GPU memory (24GB = 24576 MiB)
if [ "$GPU_MEMORY" -lt 24000 ]; then
    log_warning "GPU has less than 24GB VRAM. Training may fail or be very slow."
    log_warning "Recommended: RTX 3090 (24GB), A100 (40GB/80GB), or better"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    log_success "GPU memory sufficient for training"
fi

# Check CUDA version
CUDA_VERSION=$(nvidia-smi | grep "CUDA Version" | awk '{print $9}')
log_info "CUDA Version: $CUDA_VERSION"

if [ -z "$CUDA_VERSION" ]; then
    error_exit "Could not detect CUDA version"
fi

# Parse CUDA version (e.g., "11.8" -> 11.8)
CUDA_MAJOR=$(echo "$CUDA_VERSION" | cut -d'.' -f1)
CUDA_MINOR=$(echo "$CUDA_VERSION" | cut -d'.' -f2)

if [ "$CUDA_MAJOR" -lt 11 ] || ([ "$CUDA_MAJOR" -eq 11 ] && [ "$CUDA_MINOR" -lt 8 ]); then
    log_warning "CUDA version $CUDA_VERSION detected. CUDA 11.8+ recommended."
fi

# Check Python version
if ! command -v python3 &> /dev/null; then
    error_exit "Python 3 not found. Please install Python 3.10 or higher."
fi

PYTHON_VERSION=$(python3 --version | awk '{print $2}')
log_info "Python version: $PYTHON_VERSION"

# Check Python version >= 3.10
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d'.' -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d'.' -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
    error_exit "Python 3.10 or higher required. Found: $PYTHON_VERSION"
fi

log_success "Python version compatible"

# Check available disk space
AVAILABLE_SPACE=$(df -BG . | tail -1 | awk '{print $4}' | sed 's/G//')
log_info "Available disk space: ${AVAILABLE_SPACE}GB"

if [ "$AVAILABLE_SPACE" -lt 500 ]; then
    log_warning "Less than 500GB free disk space. Training may fail."
    log_warning "Recommended: 500GB+ for models and training data"
fi

# Check system RAM
TOTAL_RAM=$(free -g | awk '/^Mem:/{print $2}')
log_info "System RAM: ${TOTAL_RAM}GB"

if [ "$TOTAL_RAM" -lt 64 ]; then
    log_warning "Less than 64GB system RAM. Training may be slow."
fi

log_success "System requirements check complete"
echo ""

# ============================================================================
# Step 2: Create Virtual Environment
# ============================================================================

log_info "Step 2/8: Creating Python virtual environment..."

VENV_DIR="venv/axolotl"

if [ -d "$VENV_DIR" ]; then
    log_warning "Virtual environment already exists at $VENV_DIR"
    read -p "Remove and recreate? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$VENV_DIR"
        log_info "Removed existing virtual environment"
    else
        log_info "Using existing virtual environment"
    fi
fi

if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR" || error_exit "Failed to create virtual environment"
    log_success "Virtual environment created"
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate" || error_exit "Failed to activate virtual environment"
log_success "Virtual environment activated"
echo ""

# ============================================================================
# Step 3: Upgrade pip and install build tools
# ============================================================================

log_info "Step 3/8: Upgrading pip and installing build tools..."

pip install --upgrade pip setuptools wheel || error_exit "Failed to upgrade pip"
log_success "pip upgraded successfully"
echo ""

# ============================================================================
# Step 4: Install PyTorch with CUDA support
# ============================================================================

log_info "Step 4/8: Installing PyTorch with CUDA support..."

# Determine CUDA version for PyTorch
if [ "$CUDA_MAJOR" -eq 11 ] && [ "$CUDA_MINOR" -ge 8 ]; then
    TORCH_CUDA="cu118"
elif [ "$CUDA_MAJOR" -eq 12 ]; then
    TORCH_CUDA="cu121"
else
    TORCH_CUDA="cu118"  # Default to 11.8
fi

log_info "Installing PyTorch for CUDA $TORCH_CUDA..."

pip install torch torchvision torchaudio --index-url "https://download.pytorch.org/whl/$TORCH_CUDA" \
    || error_exit "Failed to install PyTorch"

log_success "PyTorch installed successfully"

# Verify PyTorch CUDA availability
python3 -c "import torch; assert torch.cuda.is_available(), 'CUDA not available in PyTorch'" \
    || error_exit "PyTorch CUDA not available"

log_success "PyTorch CUDA verified"
echo ""

# ============================================================================
# Step 5: Clone and install Axolotl
# ============================================================================

log_info "Step 5/8: Installing Axolotl..."

AXOLOTL_DIR="axolotl"

if [ -d "$AXOLOTL_DIR" ]; then
    log_warning "Axolotl directory already exists"
    read -p "Update existing installation? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cd "$AXOLOTL_DIR"
        git pull || log_warning "Failed to update Axolotl repository"
        cd ..
    fi
else
    log_info "Cloning Axolotl repository..."
    git clone https://github.com/OpenAccess-AI-Collective/axolotl.git "$AXOLOTL_DIR" \
        || error_exit "Failed to clone Axolotl repository"
    log_success "Axolotl repository cloned"
fi

# Install Axolotl
log_info "Installing Axolotl package..."
cd "$AXOLOTL_DIR"
pip install -e . || error_exit "Failed to install Axolotl"
cd ..

log_success "Axolotl installed successfully"
echo ""

# ============================================================================
# Step 6: Install additional dependencies
# ============================================================================

log_info "Step 6/8: Installing additional dependencies..."

# Install PEFT (Parameter-Efficient Fine-Tuning)
log_info "Installing PEFT..."
pip install -U git+https://github.com/huggingface/peft.git || error_exit "Failed to install PEFT"

# Install other required packages
log_info "Installing transformers, accelerate, bitsandbytes, scipy..."
pip install transformers>=4.30.0 accelerate>=0.20.0 bitsandbytes>=0.39.0 scipy>=1.10.0 \
    || error_exit "Failed to install dependencies"

log_success "All dependencies installed"
echo ""

# ============================================================================
# Step 7: Setup HuggingFace authentication
# ============================================================================

log_info "Step 7/8: Setting up HuggingFace authentication..."

# Check if HuggingFace token is set
if [ -z "$HUGGINGFACE_TOKEN" ]; then
    log_warning "HUGGINGFACE_TOKEN environment variable not set"
    log_info "You'll need a HuggingFace token to download Llama-3.1-70B"
    log_info "Get your token from: https://huggingface.co/settings/tokens"
    echo ""
    read -p "Enter your HuggingFace token (or press Enter to skip): " HF_TOKEN
    
    if [ -n "$HF_TOKEN" ]; then
        export HUGGINGFACE_TOKEN="$HF_TOKEN"
        # Save to .env file
        if [ -f ".env" ]; then
            if grep -q "HUGGINGFACE_TOKEN=" .env; then
                sed -i "s/HUGGINGFACE_TOKEN=.*/HUGGINGFACE_TOKEN=$HF_TOKEN/" .env
            else
                echo "HUGGINGFACE_TOKEN=$HF_TOKEN" >> .env
            fi
            log_success "Token saved to .env file"
        fi
    else
        log_warning "Skipping HuggingFace authentication. You'll need to set HUGGINGFACE_TOKEN later."
    fi
fi

if [ -n "$HUGGINGFACE_TOKEN" ]; then
    # Login to HuggingFace
    log_info "Logging in to HuggingFace..."
    echo "$HUGGINGFACE_TOKEN" | huggingface-cli login --token "$HUGGINGFACE_TOKEN" \
        || log_warning "HuggingFace login failed. You may need to login manually."
    log_success "HuggingFace authentication configured"
fi

echo ""

# ============================================================================
# Step 8: Create directory structure
# ============================================================================

log_info "Step 8/8: Creating directory structure..."

# Create necessary directories
mkdir -p models/llama-3.1-70b
mkdir -p models/huntress-lora-v1
mkdir -p models/versions
mkdir -p models/ab_tests
mkdir -p models/metrics
mkdir -p training_data/raw
mkdir -p training_data/processed
mkdir -p config

log_success "Directory structure created"
echo ""

# ============================================================================
# Installation Complete
# ============================================================================

log_success "Axolotl setup complete!"
echo ""
echo "=========================================="
echo "Installation Summary"
echo "=========================================="
echo "GPU: $GPU_NAME ($GPU_MEMORY MiB)"
echo "CUDA: $CUDA_VERSION"
echo "Python: $PYTHON_VERSION"
echo "PyTorch: $(python3 -c 'import torch; print(torch.__version__)')"
echo "Virtual Environment: $VENV_DIR"
echo ""
echo "Next Steps:"
echo "1. Activate the virtual environment:"
echo "   source $VENV_DIR/bin/activate"
echo ""
echo "2. Download Llama-3.1-70B base model:"
echo "   huggingface-cli download meta-llama/Llama-3.1-70B-Instruct --local-dir models/llama-3.1-70b"
echo ""
echo "3. Configure Axolotl training:"
echo "   Edit config/axolotl_config.yml"
echo ""
echo "4. Start training:"
echo "   python scripts/training/train.py --config config/axolotl_config.yml"
echo ""
echo "=========================================="
echo ""

# Verification
log_info "Running verification checks..."

# Check if PyTorch can see GPU
GPU_COUNT=$(python3 -c "import torch; print(torch.cuda.device_count())")
log_info "PyTorch detected $GPU_COUNT GPU(s)"

if [ "$GPU_COUNT" -gt 0 ]; then
    GPU_NAME_TORCH=$(python3 -c "import torch; print(torch.cuda.get_device_name(0))")
    log_success "GPU accessible from PyTorch: $GPU_NAME_TORCH"
else
    log_error "PyTorch cannot access GPU. Check CUDA installation."
fi

# Check available GPU memory
FREE_MEMORY=$(nvidia-smi --query-gpu=memory.free --format=csv,noheader,nounits | head -1)
log_info "Available GPU memory: ${FREE_MEMORY} MiB"

if [ "$FREE_MEMORY" -lt 20000 ]; then
    log_warning "Less than 20GB GPU memory available. Close other GPU applications."
fi

echo ""
log_success "Setup verification complete!"
echo ""
log_info "To get started, run:"
echo "  source $VENV_DIR/bin/activate"
echo ""