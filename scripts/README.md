# Scripts

Utility scripts voor flask-rpr-oauth development en deployment.

## Pre-Deployment Validation

Valideer de code voordat je deploy naar GitHub.

### Python Script

```bash
python scripts/pre_deploy.py
```

**Checks:**
- ✅ Git status (uncommitted changes, branch check)
- ✅ Dependencies geïnstalleerd (pytest, flake8, black, build, bandit, mypy)
- ✅ Linting (flake8) - critical errors
- ✅ Security scan (bandit) - critical voor auth library!
- ✅ Type checking (mypy)
- ✅ Code formatting (black)
- ✅ Unit tests (pytest)
- ✅ Coverage report
- ✅ Version consistency (\_\_init\_\_.py, setup.py, pyproject.toml)
- ✅ CHANGELOG check
- ✅ Package build test

## Required Dependencies

Install the development dependencies before running pre-deploy:

```bash
pip install pytest pytest-cov black flake8 mypy bandit build
```

Or install all dev dependencies:

```bash
pip install -e ".[dev]"
pip install bandit build
```

## Workflow

### Development Workflow

1. **Maak wijzigingen**
   ```bash
   # Edit code
   code flask_rpr_oauth/
   ```

2. **Run pre-deploy checks**
   ```bash
   python scripts/pre_deploy.py
   ```

3. **Fix issues**
   ```bash
   # Format code
   black flask_rpr_oauth tests examples
   
   # Fix linting issues
   flake8 flask_rpr_oauth
   
   # Fix failing tests
   pytest -v
   ```

4. **Commit en push**
   ```bash
   git add .
   git commit -m "feat: your feature description"
   git push origin main
   ```

### Release Workflow

1. **Update version**
   ```bash
   # Edit version in:
   # - flask_rpr_oauth/__init__.py
   # - setup.py
   ```

2. **Run pre-deploy checks**
   ```bash
   python scripts/pre_deploy.py
   ```

3. **Update changelog**
   ```bash
   # Edit CHANGELOG.md
   ```

4. **Commit en tag**
   ```bash
   git add .
   git commit -m "chore: bump version to 1.0.1"
   git tag -a v1.0.1 -m "Release v1.0.1"
   git push origin main --tags
   ```

5. **Create GitHub release**
   - Ga naar: https://github.com/rpr-development/flask_rpr_oauth/releases/new
   - Select tag: v1.0.1
   - Copy changelog naar release notes
   - Publish release

## Requirements

```bash
pip install -e ".[dev]"
```

Dit installeert:
- pytest
- pytest-cov
- black
- flake8
- build
