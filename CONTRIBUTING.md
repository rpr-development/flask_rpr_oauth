# Contributing to Flask RPR OAuth

## Proprietary Software Notice

Deze software is eigendom van RPR Development en valt onder een proprietary license. 

**Externe contributions worden niet geaccepteerd.**

Dit project is closed-source en alleen bedoeld voor intern gebruik door RPR Development team leden.

## Voor RPR Development Team Members

### Development Setup

```bash
# Clone repository
git clone git@github.com:rpr-development/flask_rpr_oauth.git
cd flask_rpr_oauth

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=flask_rpr_oauth --cov-report=html

# Run specific test file
pytest tests/test_auth.py
```

### Code Quality

```bash
# Format code
black flask_rpr_oauth tests examples

# Lint code
flake8 flask_rpr_oauth tests examples

# Type checking
mypy flask_rpr_oauth
```

### Making Changes

1. Create een nieuwe branch voor je feature/fix:
   ```bash
   git checkout -b feature/mijn-feature
   ```

2. Maak je wijzigingen en test ze grondig

3. Commit met duidelijke messages:
   ```bash
   git add .
   git commit -m "feat: beschrijving van wijziging"
   ```

4. Push naar GitHub:
   ```bash
   git push origin feature/mijn-feature
   ```

5. Maak een Pull Request naar de main branch

### Commit Message Conventions

Gebruik conventional commits:

- `feat:` - Nieuwe feature
- `fix:` - Bug fix
- `docs:` - Documentatie wijzigingen
- `style:` - Code formatting
- `refactor:` - Code refactoring
- `test:` - Test wijzigingen
- `chore:` - Build/tool wijzigingen

### Release Process

1. Update version in `flask_rpr_oauth/__init__.py` en `setup.py`
2. Update `CHANGELOG.md` met nieuwe versie
3. Commit changes:
   ```bash
   git add .
   git commit -m "chore: bump version to X.Y.Z"
   ```
4. Create en push tag:
   ```bash
   git tag -a vX.Y.Z -m "Release version X.Y.Z"
   git push origin vX.Y.Z
   ```
5. Maak release notes op GitHub

## Questions?

Neem contact op met het development team via support@roleplayreality.nl
