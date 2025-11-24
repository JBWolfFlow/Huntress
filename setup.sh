#!/bin/bash

# HUNTRESS Setup Script
# Installs all system dependencies required for Tauri development on Linux

set -e  # Exit on error

echo "=================================="
echo "HUNTRESS Setup Script"
echo "=================================="
echo ""

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "❌ Error: This script is designed for Linux systems"
    echo "   Detected OS: $OSTYPE"
    exit 1
fi

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "❌ Error: Do not run this script as root"
   echo "   Run without sudo - it will prompt for password when needed"
   exit 1
fi

echo "📦 Installing system dependencies..."
echo ""

# Update package list
echo "→ Updating package list..."
sudo apt-get update

# Install Tauri dependencies
echo ""
echo "→ Installing Tauri system libraries..."
sudo apt-get install -y \
    libglib2.0-dev \
    libgtk-3-dev \
    libwebkit2gtk-4.1-dev \
    libayatana-appindicator3-dev \
    librsvg2-dev \
    patchelf

# Install build tools
echo ""
echo "→ Installing build tools..."
sudo apt-get install -y \
    build-essential \
    curl \
    wget \
    file \
    libssl-dev \
    pkg-config

echo ""
echo "✅ System dependencies installed successfully!"
echo ""

# Check for Rust
if command -v rustc &> /dev/null; then
    RUST_VERSION=$(rustc --version)
    echo "✅ Rust is installed: $RUST_VERSION"
else
    echo "⚠️  Rust is not installed"
    echo ""
    read -p "Would you like to install Rust now? (y/n) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "→ Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source $HOME/.cargo/env
        echo "✅ Rust installed successfully!"
    else
        echo "⚠️  Skipping Rust installation"
        echo "   Install manually: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    fi
fi

echo ""

# Check for Node.js
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    echo "✅ Node.js is installed: $NODE_VERSION"
else
    echo "⚠️  Node.js is not installed"
    echo "   Install manually: https://nodejs.org/"
fi

echo ""
echo "=================================="
echo "Setup Complete!"
echo "=================================="
echo ""
echo "Next steps:"
echo "1. Install Node.js dependencies: npm install"
echo "2. Run development server: npm run tauri dev"
echo "3. Build for production: npm run tauri build"
echo ""
echo "For more information, see SETUP.md"
echo ""