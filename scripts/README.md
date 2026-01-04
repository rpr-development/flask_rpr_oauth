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
- ✅ Version info from Git tags (setuptools_scm)
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

**Note:** Versioning en releases zijn **volledig automatisch** via GitHub Actions met Semantic Release!

#### Automatische Release (Aanbevolen)

1. **Run pre-deploy checks lokaal**
   ```bash
   python scripts/pre_deploy.py
   ```

2. **Commit met conventional commit message**
   ```bash
   git add .
   git commit -m "feat: add new authentication method"
   # of
   git commit -m "fix: resolve token refresh issue"
   ```

3. **Push naar main**
   ```bash
   git push origin main
   ```

4. **GitHub Actions doet automatisch:**
   - ✅ Analyseert commit messages
   - ✅ Bepaalt nieuwe versie (major/minor/patch)
   - ✅ Maakt Git tag aan
   - ✅ Genereert CHANGELOG.md
   - ✅ Maakt GitHub release

**Commit Message Formats:**
- `feat: nieuwe feature` → Minor version bump (1.0.0 → 1.1.0)
- `fix: bugfix` → Patch version bump (1.0.0 → 1.0.1)
- `feat!: breaking change` → Major version bump (1.0.0 → 2.0.0)
- `docs:`, `style:`, `refactor:`, `test:`, `chore:` → Geen version bump

#### Handmatige Release (Fallback)

Als je toch handmatig een release wilt maken:

1. Run pre-deploy checks
2. Commit changes
3. Maak tag: `git tag -a v1.0.1 -m "Release v1.0.1"`
4. Push: `git push origin main --tags`
5. GitHub release aanmaken op: <https://github.com/rpr-development/flask_rpr_oauth/releases/new>

**Belangrijk:** De versie wordt automatisch gegenereerd. Edit NOOIT handmatig versies in code!

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
