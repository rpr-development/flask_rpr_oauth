# ⚠️ LEGACY BRANCH - DEPRECATED

## 🚨 Belangrijke Waarschuwing

**Deze branch bevat oude, deprecated code en wordt NIET meer onderhouden.**

### Status
- ❌ **Geen support**
- ❌ **Geen updates**
- ❌ **Geen bugfixes**
- ❌ **Niet geschikt voor productie**

### Wat is dit?

Deze `legacy` branch bevat de oorspronkelijke implementatie van de RPR OAuth package voordat deze werd gerefactored naar een professionele Flask extensie met volledige OAuth 2.0 / OpenID Connect support.

**Oude implementatie** (`rpr_oauth/`):
- Basis OAuth flow met simpele decorators
- Handmatige token management
- Beperkte functionaliteit
- Geen webhooks support
- Geen 2FA integratie
- Geen proper error handling

### ✅ Gebruik in plaats daarvan: Main Branch

De **main branch** bevat de nieuwe, productie-ready implementatie:

```bash
# Installeer de officiële package
pip install git+https://github.com/rpr-development/flask_rpr_oauth.git@v1.0.0
```

**Nieuwe implementatie** (`flask_rpr_oauth/`):
- ✅ Volledige OAuth 2.0 / OpenID Connect support
- ✅ Authlib integratie (industry standard)
- ✅ 2FA (Two-Factor Authentication) support
- ✅ Webhook support (token revocation, user deletion)
- ✅ Permission & group decorators
- ✅ Proper error handling en logging
- ✅ Unit tests & CI/CD
- ✅ Comprehensive documentation
- ✅ Production-ready

### Documentatie

Voor de huidige, ondersteunde versie:
- 📖 [README.md op main branch](https://github.com/rpr-development/flask_rpr_oauth/blob/main/README.md)
- 📋 [CHANGELOG.md](https://github.com/rpr-development/flask_rpr_oauth/blob/main/CHANGELOG.md)
- 🤝 [CONTRIBUTING.md](https://github.com/rpr-development/flask_rpr_oauth/blob/main/CONTRIBUTING.md)

### Migratie

Als je nog de oude `rpr_oauth` package gebruikt, **migreer dan naar de nieuwe `flask_rpr_oauth`**:

#### Voor (legacy):
```python
from rpr_oauth import oauth_required, oauth_2fa_required
from rpr_oauth.routes import oauth

app.register_blueprint(oauth)

@app.route('/protected')
@oauth_required
def protected():
    return "Protected"
```

#### Na (nieuwe package):
```python
from flask_rpr_oauth import RPRAuth, login_required, require_2fa

# Initialize
auth = RPRAuth(app)

@app.route('/protected')
@login_required
def protected():
    return "Protected"

@app.route('/admin')
@login_required
@require_2fa
def admin():
    return "Admin area"
```

### Support

Voor vragen over de **nieuwe package**:
- 📧 Email: support@roleplayreality.nl
- 🐛 Issues: [GitHub Issues](https://github.com/rpr-development/flask_rpr_oauth/issues)
- 📦 Package: [flask_rpr_oauth v1.0.0](https://github.com/rpr-development/flask_rpr_oauth)

### Waarom bestaat deze branch nog?

Deze legacy branch wordt bewaard voor:
- 🔍 **Historische referentie** - om te zien hoe de package is geëvolueerd
- 📚 **Architectuur inzichten** - om beslissingen te documenteren
- ⚠️ **Legacy compatibility** - tijdelijke ondersteuning voor oude projecten (geen updates!)

### Timeline

| Datum | Event |
|-------|-------|
| 2024-2025 | Legacy implementatie in gebruik |
| Nov 2025 | Nieuwe flask_rpr_oauth v1.0.0 released |
| Nov 2025 | Legacy branch marked as deprecated |
| **Heden** | ⚠️ **Gebruik alleen main branch** |

---

## 🎯 Samenvatting

**GEBRUIK DEZE CODE NIET IN PRODUCTIE!**

Switch naar de main branch voor de moderne, ondersteunde implementatie met volledige OAuth 2.0, 2FA, webhooks, en professionele error handling.

```bash
# Clone de juiste versie
git clone https://github.com/rpr-development/flask_rpr_oauth.git
cd flask_rpr_oauth
git checkout main

# Of installeer direct
pip install git+https://github.com/rpr-development/flask_rpr_oauth.git@v1.0.0
```

---

*Laatste update: November 2025*
