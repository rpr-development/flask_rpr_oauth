#!/bin/bash
# Pre-deployment validation script voor flask-rpr-oauth
# Quick version for bash/zsh

set -e  # Exit on error

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}Flask RPR OAuth - Pre-Deploy${NC}"
echo -e "${BLUE}================================${NC}\n"

# Step 1: Linting
echo -e "${BLUE}▶ Running linting checks...${NC}"
flake8 flask_rpr_oauth --count --select=E9,F63,F7,F82 --show-source --statistics
echo -e "${GREEN}✓ Linting passed${NC}\n"

# Step 2: Format check
echo -e "${BLUE}▶ Checking code format...${NC}"
black --check flask_rpr_oauth tests examples || true
echo -e "${YELLOW}⚠ Format check complete${NC}\n"

# Step 3: Tests
echo -e "${BLUE}▶ Running tests...${NC}"
pytest -v
echo -e "${GREEN}✓ Tests passed${NC}\n"

# Step 4: Build
echo -e "${BLUE}▶ Building package...${NC}"
rm -rf build dist *.egg-info
python -m build
echo -e "${GREEN}✓ Package built${NC}\n"

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}✓ ALL CHECKS PASSED${NC}"
echo -e "${GREEN}================================${NC}\n"

echo "Ready for deployment! 🚀"
