# Quick Start: Automatische Releases

## TL;DR

```bash
# 1. Maak je wijzigingen
vim flask_rpr_oauth/auth.py

# 2. Test
python scripts/pre_deploy.py

# 3. Commit met conventional message
git add .
git commit -m "feat: your feature description"

# 4. Push
git push origin main

# 5. Klaar! GitHub maakt automatisch een release 🎉
```

## Commit Message Cheat Sheet

```bash
# Nieuwe feature → versie 1.1.6 → 1.2.0
git commit -m "feat: add refresh token rotation"

# Bug fix → versie 1.1.6 → 1.1.7
git commit -m "fix: resolve CSRF validation bug"

# Breaking change → versie 1.1.6 → 2.0.0
git commit -m "feat!: rename OAuth2Manager to RPROAuth"

# Geen versie bump
git commit -m "docs: update README"
git commit -m "chore: update dependencies"
git commit -m "style: format code with black"
```

## Wat gebeurt er automatisch?

Wanneer je pusht naar `main`:

1. ✅ GitHub Actions draait
2. ✅ Analyseert je commit messages
3. ✅ Bepaalt nieuwe versie (1.1.6 → 1.2.0)
4. ✅ Maakt Git tag `v1.2.0`
5. ✅ Genereert CHANGELOG.md
6. ✅ Maakt GitHub release
7. ✅ Build package (klaar voor PyPI)

Check de **Actions** tab op GitHub voor de voortgang.

## Meer info

Zie [RELEASE_WORKFLOW.md](RELEASE_WORKFLOW.md) voor gedetailleerde uitleg.
