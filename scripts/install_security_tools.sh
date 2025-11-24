#!/bin/bash

# HUNTRESS Security Tools Installation Script
# This script installs waybackurls and nuclei for OAuth Hunter

set -e

echo "🔧 Installing Security Tools for HUNTRESS OAuth Hunter..."
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}❌ Go is not installed. Please install Go first:${NC}"
    echo "   Visit: https://golang.org/doc/install"
    exit 1
fi

echo -e "${GREEN}✓ Go is installed: $(go version)${NC}"
echo ""

# Install waybackurls
echo -e "${YELLOW}📦 Installing waybackurls...${NC}"
if go install github.com/tomnomnom/waybackurls@latest; then
    echo -e "${GREEN}✓ waybackurls installed successfully${NC}"
else
    echo -e "${RED}❌ Failed to install waybackurls${NC}"
    exit 1
fi
echo ""

# Install nuclei
echo -e "${YELLOW}📦 Installing nuclei...${NC}"
if go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest; then
    echo -e "${GREEN}✓ nuclei installed successfully${NC}"
else
    echo -e "${RED}❌ Failed to install nuclei${NC}"
    exit 1
fi
echo ""

# Update nuclei templates
echo -e "${YELLOW}📦 Updating nuclei templates...${NC}"
if nuclei -update-templates; then
    echo -e "${GREEN}✓ nuclei templates updated${NC}"
else
    echo -e "${YELLOW}⚠ Failed to update nuclei templates (this is optional)${NC}"
fi
echo ""

# Verify installations
echo -e "${YELLOW}🔍 Verifying installations...${NC}"
echo ""

if command -v waybackurls &> /dev/null; then
    echo -e "${GREEN}✓ waybackurls is available in PATH${NC}"
else
    echo -e "${RED}❌ waybackurls not found in PATH${NC}"
    echo -e "${YELLOW}   Add ~/go/bin to your PATH:${NC}"
    echo '   export PATH=$PATH:~/go/bin'
fi

if command -v nuclei &> /dev/null; then
    echo -e "${GREEN}✓ nuclei is available in PATH${NC}"
    echo "   Version: $(nuclei -version 2>&1 | head -n 1)"
else
    echo -e "${RED}❌ nuclei not found in PATH${NC}"
    echo -e "${YELLOW}   Add ~/go/bin to your PATH:${NC}"
    echo '   export PATH=$PATH:~/go/bin'
fi

echo ""
echo -e "${GREEN}✅ Security tools installation complete!${NC}"
echo ""
echo "Next steps:"
echo "1. Ensure ~/go/bin is in your PATH"
echo "2. Set up Qdrant database (see docker-compose.yml)"
echo "3. Configure .env file with API keys"
echo "4. Run: npm run dev"