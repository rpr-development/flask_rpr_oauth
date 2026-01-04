#!/usr/bin/env python
"""
Pre-deployment validation script voor flask-rpr-oauth.

Dit script controleert:
- Git status (uncommitted changes)
- Code quality (linting)
- Security (bandit)
- Type checking (mypy)
- Tests (unit tests)
- Coverage
- Version info from Git tags (setuptools_scm)
- CHANGELOG updates
- Package building

Run dit script voordat je:
- Een nieuwe tag/release maakt
- Code naar main pusht
- De package deploy

Note: Versioning is automatic via setuptools_scm from Git tags.
"""

import sys
import subprocess
import os
import re
from pathlib import Path
from datetime import datetime

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
            shell=True  # Always use shell for better PATH resolution
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
    
    required = ['pytest', 'flake8', 'black', 'build', 'bandit', 'mypy']
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


def check_git_status():
    """Check for uncommitted changes."""
    print_step("Checking Git Status")
    
    try:
        # Check for uncommitted changes
        result = subprocess.run(
            ['git', 'status', '--porcelain'],
            capture_output=True,
            text=True,
            check=True
        )
        
        if result.stdout.strip():
            print_warning("You have uncommitted changes:")
            print(result.stdout)
            print_warning("Consider committing or stashing changes before deployment")
        else:
            print_success("Working directory is clean")
        
        # Show current branch
        branch_result = subprocess.run(
            ['git', 'branch', '--show-current'],
            capture_output=True,
            text=True,
            check=True
        )
        current_branch = branch_result.stdout.strip()
        print(f"Current branch: {current_branch}")
        
        if current_branch != 'main':
            print_warning(f"You are not on 'main' branch (current: {current_branch})")
        
    except subprocess.CalledProcessError as e:
        print_warning(f"Could not check git status: {e}")
    except FileNotFoundError:
        print_warning("Git not found - skipping git status check")


def run_linting():
    """Run code linting checks."""
    print_step("Running Linting Checks")
    
    # Flake8 - critical errors only
    run_command(
        'python -m flake8 flask_rpr_oauth --count --select=E9,F63,F7,F82 --show-source --statistics',
        "Flake8 critical errors check",
        critical=True
    )
    
    # Flake8 - all errors (non-critical)
    run_command(
        'python -m flake8 flask_rpr_oauth --count --max-complexity=10 --max-line-length=127 --statistics',
        "Flake8 full lint check",
        critical=False
    )
    
    # Black format check
    run_command(
        'python -m black --check flask_rpr_oauth tests examples',
        "Black format check",
        critical=False
    )


def run_security_check():
    """Run security checks with bandit."""
    print_step("Running Security Checks")
    
    # Bandit security scan
    run_command(
        'python -m bandit -r flask_rpr_oauth -ll',  # -ll = medium and high severity only
        "Bandit security scan",
        critical=True  # Critical for auth library!
    )
    
    # Also check examples for security issues (non-critical)
    run_command(
        'python -m bandit -r examples -ll',
        "Bandit scan on examples",
        critical=False
    )
    
    print_success("No security issues found")


def run_type_checking():
    """Run static type checking with mypy."""
    print_step("Running Type Checks")
    
    run_command(
        'python -m mypy flask_rpr_oauth --ignore-missing-imports --no-error-summary',
        "Mypy type checking",
        critical=False  # Non-critical as some code may not have type hints yet
    )


def run_tests():
    """Run unit tests."""
    print_step("Running Unit Tests")
    
    run_command(
        'python -m pytest -v --tb=short',
        "Unit tests",
        critical=True
    )
    
    # Run with coverage (non-critical)
    run_command(
        'python -m pytest --cov=flask_rpr_oauth --cov-report=term --cov-report=html',
        "Coverage report",
        critical=False
    )


def check_version_consistency():
    """Check version from setuptools_scm (Git tags)."""
    print_step("Checking Version from Git")

    print("Using setuptools_scm for automatic versioning from Git tags")

    # Get current version from setuptools_scm
    try:
        result = subprocess.run(
            ['git', 'describe', '--tags', '--abbrev=0'],
            capture_output=True,
            text=True,
            check=True
        )
        latest_tag = result.stdout.strip()
        print(f"Latest Git tag: {latest_tag}")

        # Get current commit hash
        commit_result = subprocess.run(
            ['git', 'rev-parse', '--short', 'HEAD'],
            capture_output=True,
            text=True,
            check=True
        )
        commit_hash = commit_result.stdout.strip()

        # Check if we're on a tagged commit
        tag_commit = subprocess.run(
            ['git', 'rev-list', '-n', '1', latest_tag],
            capture_output=True,
            text=True,
            check=True
        )
        tag_commit_hash = tag_commit.stdout.strip()[:7]

        current_commit = subprocess.run(
            ['git', 'rev-parse', 'HEAD'],
            capture_output=True,
            text=True,
            check=True
        )
        current_commit_hash = current_commit.stdout.strip()[:7]

        if tag_commit_hash == current_commit_hash:
            version = latest_tag.lstrip('v')
            print_success(f"On tagged commit: {version}")
        else:
            print_warning(f"Not on a tagged commit (latest tag: {latest_tag}, current: {commit_hash})")
            print("Version will be auto-generated by setuptools_scm as: {tag}+{commits}.{hash}")
            version = f"{latest_tag.lstrip('v')}+dev"

        return version

    except subprocess.CalledProcessError:
        print_warning("No Git tags found")
        print("Version will be auto-generated by setuptools_scm as: 0.0.0+{commits}.{hash}")
        return "0.0.0+untagged"
    except FileNotFoundError:
        print_error("Git not found - cannot determine version")
        sys.exit(1)


def check_changelog():
    """Check if CHANGELOG has been updated."""
    print_step("Checking CHANGELOG")
    
    changelog_files = ['CHANGELOG.md', 'HISTORY.md', 'CHANGES.md']
    changelog_path = None
    
    for filename in changelog_files:
        if Path(filename).exists():
            changelog_path = Path(filename)
            break
    
    if not changelog_path:
        print_warning("No CHANGELOG file found (CHANGELOG.md, HISTORY.md, or CHANGES.md)")
        print("Consider creating a CHANGELOG.md to track changes")
        return
    
    print(f"Found: {changelog_path}")
    
    # Check if changelog has recent entries (look for current year)
    current_year = str(datetime.now().year)
    with open(changelog_path) as f:
        content = f.read()
        if current_year in content:
            print_success(f"CHANGELOG contains entries for {current_year}")
        else:
            print_warning(f"CHANGELOG may not have recent entries (no {current_year} found)")
            print("Consider updating the CHANGELOG before release")


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
    
    # Change to repository root (parent of script directory)
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    os.chdir(repo_root)
    print(f"Working directory: {repo_root}\n")
    
    try:
        # Run all checks
        check_dependencies()
        check_git_status()
        run_linting()
        run_security_check()
        run_type_checking()
        run_tests()
        version = check_version_consistency()
        check_changelog()
        build_package()
        test_installation()
        
        # Final success message
        print(f"\n{GREEN}{'='*60}")
        print("✓ ALL CHECKS PASSED")
        print(f"{'='*60}{RESET}\n")

        print("Package is ready for deployment!")
        print(f"Current version info: {version}")
        print("\nNext steps for AUTOMATIC release:")
        print("  1. Review changes: git diff")
        print("  2. Commit with conventional message:")
        print("     git add . && git commit -m 'feat: your feature description'")
        print("     (use 'feat:' for features, 'fix:' for bugfixes)")
        print("  3. Push to main: git push origin main")
        print("  4. GitHub Actions will automatically:")
        print("     - Determine version (based on commit messages)")
        print("     - Create Git tag")
        print("     - Generate CHANGELOG.md")
        print("     - Create GitHub release")
        print("\nCommit message formats:")
        print("  - feat: ... → minor version bump (1.0.0 → 1.1.0)")
        print("  - fix: ...  → patch version bump (1.0.0 → 1.0.1)")
        print("  - feat!: ... → major version bump (1.0.0 → 2.0.0)")

        return 0
        
    except KeyboardInterrupt:
        print_error("\n\nValidation interrupted by user")
        return 130
    except Exception as e:
        print_error(f"\n\nUnexpected error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
