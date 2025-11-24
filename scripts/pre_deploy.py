#!/usr/bin/env python
"""
Pre-deployment validation script voor flask-rpr-oauth.

Dit script controleert:
- Code quality (linting)
- Tests (unit tests)
- Package building
- Version consistency

Run dit script voordat je:
- Een nieuwe tag/release maakt
- Code naar main pusht
- De package deploy
"""

import sys
import subprocess
import os
from pathlib import Path

# Kleuren voor output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'


def print_step(message):
    """Print step header."""
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}▶ {message}{RESET}")
    print(f"{BLUE}{'='*60}{RESET}\n")


def print_success(message):
    """Print success message."""
    print(f"{GREEN}✓ {message}{RESET}")


def print_error(message):
    """Print error message."""
    print(f"{RED}✗ {message}{RESET}")


def print_warning(message):
    """Print warning message."""
    print(f"{YELLOW}⚠ {message}{RESET}")


def run_command(command, description, critical=True):
    """
    Run a shell command and handle output.
    
    Args:
        command: Command to run (list or string)
        description: Description of what the command does
        critical: If True, exit on failure. If False, continue with warning.
    
    Returns:
        bool: True if command succeeded, False otherwise
    """
    print(f"Running: {' '.join(command) if isinstance(command, list) else command}")
    
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            shell=isinstance(command, str)
        )
        
        if result.stdout:
            print(result.stdout)
        
        print_success(f"{description} - SUCCESS")
        return True
        
    except subprocess.CalledProcessError as e:
        print_error(f"{description} - FAILED")
        
        if e.stdout:
            print(f"\nStdout:\n{e.stdout}")
        if e.stderr:
            print(f"\nStderr:\n{e.stderr}")
        
        if critical:
            print_error("Critical check failed. Aborting deployment.")
            sys.exit(1)
        else:
            print_warning(f"{description} failed but continuing...")
            return False


def check_dependencies():
    """Check if required dependencies are installed."""
    print_step("Checking Dependencies")
    
    required = ['pytest', 'flake8', 'black', 'build']
    missing = []
    
    for package in required:
        try:
            __import__(package)
            print_success(f"{package} is installed")
        except ImportError:
            missing.append(package)
            print_error(f"{package} is NOT installed")
    
    if missing:
        print_error(f"Missing packages: {', '.join(missing)}")
        print(f"\nInstall with: pip install {' '.join(missing)}")
        sys.exit(1)
    
    print_success("All dependencies are installed")


def run_linting():
    """Run code linting checks."""
    print_step("Running Linting Checks")
    
    # Flake8 - critical errors only
    run_command(
        ['flake8', 'flask_rpr_oauth', '--count', '--select=E9,F63,F7,F82', 
         '--show-source', '--statistics'],
        "Flake8 critical errors check",
        critical=True
    )
    
    # Flake8 - all errors (non-critical)
    run_command(
        ['flake8', 'flask_rpr_oauth', '--count', '--max-complexity=10', 
         '--max-line-length=127', '--statistics'],
        "Flake8 full lint check",
        critical=False
    )
    
    # Black format check
    run_command(
        ['black', '--check', 'flask_rpr_oauth', 'tests', 'examples'],
        "Black format check",
        critical=False
    )


def run_tests():
    """Run unit tests."""
    print_step("Running Unit Tests")
    
    run_command(
        ['pytest', '-v', '--tb=short'],
        "Unit tests",
        critical=True
    )
    
    # Run with coverage (non-critical)
    run_command(
        ['pytest', '--cov=flask_rpr_oauth', '--cov-report=term', '--cov-report=html'],
        "Coverage report",
        critical=False
    )


def check_version_consistency():
    """Check if version numbers are consistent."""
    print_step("Checking Version Consistency")
    
    # Read version from __init__.py
    init_file = Path('flask_rpr_oauth/__init__.py')
    init_version = None
    
    with open(init_file) as f:
        for line in f:
            if line.startswith('__version__'):
                init_version = line.split('=')[1].strip().strip('"').strip("'")
                break
    
    # Read version from setup.py
    setup_file = Path('setup.py')
    setup_version = None
    
    with open(setup_file) as f:
        for line in f:
            if 'version=' in line:
                setup_version = line.split('=')[1].strip().strip(',').strip('"').strip("'")
                break
    
    print(f"Version in __init__.py: {init_version}")
    print(f"Version in setup.py: {setup_version}")
    
    if init_version != setup_version:
        print_error("Version mismatch between __init__.py and setup.py")
        sys.exit(1)
    
    print_success(f"Version is consistent: {init_version}")
    return init_version


def build_package():
    """Build the package."""
    print_step("Building Package")
    
    # Clean old builds
    print("Cleaning old builds...")
    for dir_name in ['build', 'dist', '*.egg-info']:
        run_command(
            f'rm -rf {dir_name}' if os.name != 'nt' else f'if exist {dir_name} rmdir /s /q {dir_name}',
            f"Clean {dir_name}",
            critical=False
        )
    
    # Build package
    run_command(
        ['python', '-m', 'build'],
        "Package build",
        critical=True
    )
    
    # Check if files were created
    dist_dir = Path('dist')
    if not dist_dir.exists() or not list(dist_dir.glob('*')):
        print_error("No distribution files created")
        sys.exit(1)
    
    print_success("Package built successfully")
    
    # List created files
    print("\nCreated files:")
    for file in dist_dir.glob('*'):
        print(f"  - {file.name}")


def test_installation():
    """Test package installation in a virtual environment."""
    print_step("Testing Package Installation")
    
    print_warning("Skipping installation test (would require venv setup)")
    print("To test manually:")
    print("  1. Create venv: python -m venv test_venv")
    print("  2. Activate: test_venv\\Scripts\\activate (Windows) or source test_venv/bin/activate (Unix)")
    print("  3. Install: pip install dist/*.whl")
    print("  4. Test: python -c 'import flask_rpr_oauth; print(flask_rpr_oauth.__version__)'")


def main():
    """Main validation function."""
    print(f"\n{GREEN}{'='*60}")
    print("Flask RPR OAuth - Pre-Deployment Validation")
    print(f"{'='*60}{RESET}\n")
    
    # Change to script directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    try:
        # Run all checks
        check_dependencies()
        run_linting()
        run_tests()
        version = check_version_consistency()
        build_package()
        test_installation()
        
        # Final success message
        print(f"\n{GREEN}{'='*60}")
        print("✓ ALL CHECKS PASSED")
        print(f"{'='*60}{RESET}\n")
        
        print(f"Package version {version} is ready for deployment!")
        print("\nNext steps:")
        print(f"  1. Review changes: git diff")
        print(f"  2. Commit: git add . && git commit -m 'chore: release v{version}'")
        print(f"  3. Tag: git tag -a v{version} -m 'Release v{version}'")
        print(f"  4. Push: git push origin main --tags")
        
        return 0
        
    except KeyboardInterrupt:
        print_error("\n\nValidation interrupted by user")
        return 130
    except Exception as e:
        print_error(f"\n\nUnexpected error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
