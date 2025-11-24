# Pre-deployment validation script voor flask-rpr-oauth
# PowerShell version for Windows

$ErrorActionPreference = "Stop"

Write-Host "`n================================" -ForegroundColor Blue
Write-Host "Flask RPR OAuth - Pre-Deploy" -ForegroundColor Blue
Write-Host "================================`n" -ForegroundColor Blue

# Step 1: Linting
Write-Host "▶ Running linting checks..." -ForegroundColor Blue
flake8 flask_rpr_oauth --count --select=E9,F63,F7,F82 --show-source --statistics
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Linting passed`n" -ForegroundColor Green
} else {
    Write-Host "✗ Linting failed`n" -ForegroundColor Red
    exit 1
}

# Step 2: Format check
Write-Host "▶ Checking code format..." -ForegroundColor Blue
black --check flask_rpr_oauth tests examples
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Format check passed`n" -ForegroundColor Green
} else {
    Write-Host "⚠ Format issues found (non-critical)`n" -ForegroundColor Yellow
}

# Step 3: Tests
Write-Host "▶ Running tests..." -ForegroundColor Blue
pytest -v
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Tests passed`n" -ForegroundColor Green
} else {
    Write-Host "✗ Tests failed`n" -ForegroundColor Red
    exit 1
}

# Step 4: Build
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

Write-Host "Ready for deployment! 🚀" -ForegroundColor Green
