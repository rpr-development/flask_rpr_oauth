# Pre-deployment validation script voor flask-rpr-oauth
# PowerShell version for Windows

$ErrorActionPreference = "Stop"

Write-Host "`n================================" -ForegroundColor Blue
Write-Host "Flask RPR OAuth - Pre-Deploy" -ForegroundColor Blue
Write-Host "================================`n" -ForegroundColor Blue

# Step 0: Git Status
Write-Host "▶ Checking Git status..." -ForegroundColor Blue
$gitStatus = git status --porcelain
if ($gitStatus) {
    Write-Host "⚠ You have uncommitted changes:" -ForegroundColor Yellow
    Write-Host $gitStatus
} else {
    Write-Host "✓ Working directory is clean" -ForegroundColor Green
}
$currentBranch = git branch --show-current
Write-Host "Current branch: $currentBranch"
if ($currentBranch -ne "main") {
    Write-Host "⚠ Not on 'main' branch`n" -ForegroundColor Yellow
} else {
    Write-Host ""
}

# Step 1: Linting
Write-Host "▶ Running linting checks..." -ForegroundColor Blue
flake8 flask_rpr_oauth --count --select=E9,F63,F7,F82 --show-source --statistics
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Linting passed`n" -ForegroundColor Green
} else {
    Write-Host "✗ Linting failed`n" -ForegroundColor Red
    exit 1
}

# Step 2: Security check (bandit)
Write-Host "▶ Running security checks (bandit)..." -ForegroundColor Blue
bandit -r flask_rpr_oauth -ll
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Security check passed`n" -ForegroundColor Green
} else {
    Write-Host "✗ Security issues found`n" -ForegroundColor Red
    exit 1
}

# Step 3: Type checking (mypy)
Write-Host "▶ Running type checks (mypy)..." -ForegroundColor Blue
mypy flask_rpr_oauth --ignore-missing-imports
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Type check passed`n" -ForegroundColor Green
} else {
    Write-Host "⚠ Type issues found (non-critical)`n" -ForegroundColor Yellow
}

# Step 4: Format check
Write-Host "▶ Checking code format..." -ForegroundColor Blue
black --check flask_rpr_oauth tests examples
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Format check passed`n" -ForegroundColor Green
} else {
    Write-Host "⚠ Format issues found (non-critical)`n" -ForegroundColor Yellow
}

# Step 5: Tests
Write-Host "▶ Running tests..." -ForegroundColor Blue
pytest -v
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Tests passed`n" -ForegroundColor Green
} else {
    Write-Host "✗ Tests failed`n" -ForegroundColor Red
    exit 1
}

# Step 6: Coverage
Write-Host "▶ Running coverage..." -ForegroundColor Blue
pytest --cov=flask_rpr_oauth --cov-report=term --cov-report=html
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Coverage report generated`n" -ForegroundColor Green
} else {
    Write-Host "⚠ Coverage report failed (non-critical)`n" -ForegroundColor Yellow
}

# Step 7: Version check
Write-Host "▶ Checking version consistency..." -ForegroundColor Blue
$initVersion = (Get-Content flask_rpr_oauth/__init__.py | Select-String '__version__').ToString() -replace '.*"([^"]+)".*', '$1'
$setupVersion = (Get-Content setup.py | Select-String 'version=').ToString() -replace '.*"([^"]+)".*', '$1'
$pyprojectVersion = (Get-Content pyproject.toml | Select-String '^version').ToString() -replace '.*"([^"]+)".*', '$1'
Write-Host "  __init__.py: $initVersion"
Write-Host "  setup.py: $setupVersion"
Write-Host "  pyproject.toml: $pyprojectVersion"
if (($initVersion -eq $setupVersion) -and ($setupVersion -eq $pyprojectVersion)) {
    Write-Host "✓ Version is consistent: $initVersion`n" -ForegroundColor Green
} else {
    Write-Host "✗ Version mismatch!`n" -ForegroundColor Red
    exit 1
}

# Step 8: Build
Write-Host "▶ Building package..." -ForegroundColor Blue
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
Get-ChildItem -Filter "*.egg-info" -Recurse | Remove-Item -Recurse -Force
python -m build
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Package built`n" -ForegroundColor Green
} else {
    Write-Host "✗ Build failed`n" -ForegroundColor Red
    exit 1
}

Write-Host "`n================================" -ForegroundColor Green
Write-Host "✓ ALL CHECKS PASSED" -ForegroundColor Green
Write-Host "================================`n" -ForegroundColor Green

Write-Host "Package version $initVersion is ready for deployment! 🚀" -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "  1. Review changes: git diff"
Write-Host "  2. Commit: git add . ; git commit -m 'chore: release v$initVersion'"
Write-Host "  3. Tag: git tag -a v$initVersion -m 'Release v$initVersion'"
Write-Host "  4. Push: git push origin main --tags"
