#!/bin/bash
# Pre-deployment validation script voor flask-rpr-oauth
# Quick version for bash/zsh

set -e  # Exit on error

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}Flask RPR OAuth - Pre-Deploy${NC}"
echo -e "${BLUE}================================${NC}\n"

# Step 0: Git Status
echo -e "${BLUE}▶ Checking Git status...${NC}"
if [[ -n $(git status --porcelain) ]]; then
    echo -e "${YELLOW}⚠ You have uncommitted changes:${NC}"
    git status --porcelain
else
    echo -e "${GREEN}✓ Working directory is clean${NC}"
fi
CURRENT_BRANCH=$(git branch --show-current)
echo "Current branch: $CURRENT_BRANCH"
if [[ "$CURRENT_BRANCH" != "main" ]]; then
    echo -e "${YELLOW}⚠ Not on 'main' branch${NC}\n"
else
    echo ""
fi

# Step 1: Linting
echo -e "${BLUE}▶ Running linting checks...${NC}"
flake8 flask_rpr_oauth --count --select=E9,F63,F7,F82 --show-source --statistics
echo -e "${GREEN}✓ Linting passed${NC}\n"

# Step 2: Security check (bandit)
echo -e "${BLUE}▶ Running security checks (bandit)...${NC}"
bandit -r flask_rpr_oauth -ll
echo -e "${GREEN}✓ Security check passed${NC}\n"

# Step 3: Type checking (mypy)
echo -e "${BLUE}▶ Running type checks (mypy)...${NC}"
mypy flask_rpr_oauth --ignore-missing-imports || echo -e "${YELLOW}⚠ Type issues found (non-critical)${NC}"
echo ""

# Step 4: Format check
echo -e "${BLUE}▶ Checking code format...${NC}"
black --check flask_rpr_oauth tests examples || echo -e "${YELLOW}⚠ Format issues found (non-critical)${NC}"
echo ""

# Step 5: Tests
echo -e "${BLUE}▶ Running tests...${NC}"
pytest -v
echo -e "${GREEN}✓ Tests passed${NC}\n"

# Step 6: Coverage
echo -e "${BLUE}▶ Running coverage...${NC}"
pytest --cov=flask_rpr_oauth --cov-report=term --cov-report=html || echo -e "${YELLOW}⚠ Coverage report failed (non-critical)${NC}"
echo ""

# Step 7: Version check
echo -e "${BLUE}▶ Checking version consistency...${NC}"
INIT_VERSION=$(grep '__version__' flask_rpr_oauth/__init__.py | sed 's/.*"\(.*\)".*/\1/')
SETUP_VERSION=$(grep 'version=' setup.py | sed 's/.*"\(.*\)".*/\1/')
PYPROJECT_VERSION=$(grep '^version' pyproject.toml | sed 's/.*"\(.*\)".*/\1/')
echo "  __init__.py: $INIT_VERSION"
echo "  setup.py: $SETUP_VERSION"
echo "  pyproject.toml: $PYPROJECT_VERSION"
if [[ "$INIT_VERSION" == "$SETUP_VERSION" && "$SETUP_VERSION" == "$PYPROJECT_VERSION" ]]; then
    echo -e "${GREEN}✓ Version is consistent: $INIT_VERSION${NC}\n"
else
    echo -e "${RED}✗ Version mismatch!${NC}\n"
    exit 1
fi

# Step 8: Build
echo -e "${BLUE}▶ Building package...${NC}"
rm -rf build dist *.egg-info
python -m build
echo -e "${GREEN}✓ Package built${NC}\n"

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}✓ ALL CHECKS PASSED${NC}"
echo -e "${GREEN}================================${NC}\n"

echo -e "${GREEN}Package version $INIT_VERSION is ready for deployment! 🚀${NC}"
echo -e "\n${CYAN}Next steps:${NC}"
echo "  1. Review changes: git diff"
echo "  2. Commit: git add . && git commit -m 'chore: release v$INIT_VERSION'"
echo "  3. Tag: git tag -a v$INIT_VERSION -m 'Release v$INIT_VERSION'"
echo "  4. Push: git push origin main --tags"
