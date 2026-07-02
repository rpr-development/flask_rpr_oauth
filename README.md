# Flask RPR OAuth

Een Flask extensie voor OAuth 2.0 / OpenID Connect authenticatie met [auth.roleplayreality.nl](https://auth.roleplayreality.nl).

## Features

- 🔐 **OAuth 2.0 / OpenID Connect** - Volledige OAuth flow (authorization code flow)
- 👤 **User Management** - Automatische gebruiker synchronisatie met permissions en groepen
- 🔒 **Session-based Auth** - Pure Flask sessions voor web applicaties
- 🚀 **Stateless API Mode** - Bearer token support voor REST APIs en M2M
- 🤖 **M2M Token Support** - Client credentials flow voor server-to-server
- 🎫 **Token Management** - Automatische token refresh en validatie
- 🔑 **Two-Factor Authentication** - Volledige 2FA integratie met `@require_2fa` decorator
- 🪝 **Webhook Support** - Real-time token revocation en gebruiker updates
- ⚡ **Redis Sessions** - Optionele server-side session storage
- 🛡️ **Decorators** - Session-based én stateless permission checks

## Gebruik Cases

### Session-Based (Web Applicaties)

```python
from flask_rpr_oauth import RPRAuth, login_required, permission_required

app = Flask(__name__)
auth = RPRAuth(app)  # Auto-registreert /auth/login, /auth/callback

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')
```

### Stateless (REST APIs & M2M)

```python
from flask_rpr_oauth import permission_required

app = Flask(__name__)
app.config['OAUTH_BASE_URL'] = 'https://auth.roleplayreality.nl'

@app.route('/api/kick-player', methods=['POST'])
@permission_required('fivem.player.kick')
def kick_player(userinfo):
    # Werkt voor M2M tokens EN user tokens!
    return {'status': 'success'}
```

## Installatie

### Via GitHub (aanbevolen)

```bash
pip install git+https://github.com/rpr-development/flask-rpr-oauth.git
```

### Specifieke versie

```bash
pip install git+https://github.com/rpr-development/flask-rpr-oauth.git@v1.0.0
```

### Met Redis support

```bash
pip install "git+https://github.com/rpr-development/flask-rpr-oauth.git[redis]"
```

### In requirements.txt

```txt
flask-rpr-oauth @ git+https://github.com/rpr-development/flask-rpr-oauth.git@v1.0.0
```

## Quick Start

### 1. Basis Setup

```python
from flask import Flask
from flask_rpr_oauth import RPRAuth

app = Flask(__name__)

# Configuratie
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['OAUTH_BASE_URL'] = 'https://auth.roleplayreality.nl'
app.config['OAUTH_CLIENT_ID'] = 'your-client-id'
app.config['OAUTH_CLIENT_SECRET'] = 'your-client-secret'
app.config['OAUTH_REDIRECT_URI'] = 'http://localhost:5000/auth/callback'

# Initialiseer OAuth
auth = RPRAuth(app)

if __name__ == '__main__':
    app.run()
```

### 2. Protected Routes

```python
from flask_rpr_oauth import login_required, current_user

@app.route('/dashboard')
@login_required
def dashboard():
    return f"Welkom {current_user.voornaam} {current_user.achternaam}!"
```

### 3. Permission Checks

```python
from flask_rpr_oauth import permission_required

@app.route('/admin')
@permission_required('admin')
def admin_panel():
    return "Admin panel"

@app.route('/moderator')
@any_permission_required('moderator', 'admin')
def moderator_panel():
    return "Moderator panel"
```

### 4. Group Checks

```python
from flask_rpr_oauth import group_required

@app.route('/staff')
@group_required('staff')
def staff_area():
    return "Staff area"
```

## Configuratie

### Verplichte Settings

```python
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['OAUTH_BASE_URL'] = 'https://auth.roleplayreality.nl'
app.config['OAUTH_CLIENT_ID'] = 'your-client-id'
app.config['OAUTH_CLIENT_SECRET'] = 'your-client-secret'
app.config['OAUTH_REDIRECT_URI'] = 'http://yourdomain.com/auth/callback'
```

### Optionele Settings

```python
# OAuth scope (default: 'openid profile email')
app.config['OAUTH_SCOPE'] = 'openid profile email'

# Auto validate tokens (default: True)
app.config['OAUTH_AUTO_VALIDATE'] = True

# Webhook secret voor validatie
app.config['WEBHOOK_SECRET'] = 'your-webhook-secret'

# Partitioned cookies voor iframe/CHIPS ondersteuning (default: True)
# Aanbevolen aan te laten voor applicaties die in iframe kunnen draaien
app.config['OAUTH_PARTITIONED_COOKIES'] = True

# Session bootstrap-route /auth/session-bootstrap (default: True)
# Schakelt een route in die een normale first-party sessie opzet vanuit een
# vooraf gemunt access token (het resultaat van een RFC 8693 Token Exchange,
# scoped op de audience van deze app), ZONDER de gebruikelijke /auth/login
# redirect. Bedoeld voor een FiveM phone NUI die de app in een iframe laadt en
# auto-ingelogd moet worden.
#
# Het access token wordt aangeleverd via (in volgorde van voorkeur):
#   - POST form-veld `access_token` (voorkeur)
#   - query-parameter `access_token` (GET)
#   - `Authorization: Bearer <token>` header
# Het is een ACCESS TOKEN (bearer), GEEN code: er wordt niets ingewisseld bij
# /oauth/token en er is geen client secret nodig. Het token wordt gevalideerd
# door /oauth/userinfo aan te roepen; bij falen volgt een redirect naar login.
# Optioneel kan `id_token` worden meegestuurd (POST form) en `next` (form/query).
# Standaard AAN zodat onze apps direct in FiveM beschikbaar zijn; zet expliciet
# op False als je deze flow niet wilt aanbieden.
app.config['OAUTH_ENABLE_SESSION_BOOTSTRAP'] = True
# Back-compat: de oude vlag werkt nog en activeert dezelfde route + alias.
app.config['OAUTH_ENABLE_FIVEM_BOOTSTRAP'] = False

# Session configuration (voor Redis sessions)
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.from_url('redis://localhost:6379')
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 uur
```

## Routes

De package registreert automatisch de volgende routes:

- `GET /auth/login` - Start OAuth flow
- `GET /auth/callback` - OAuth callback endpoint
- `GET /auth/logout` - Logout en clear session
- `GET /auth/refresh` - Refresh access token
- `GET, POST /auth/session-bootstrap` - Bearer-based auto-login: zet een first-party sessie op vanuit een aangeleverd access token (via POST `access_token` (voorkeur) / GET-query / `Authorization: Bearer`), NIET een code. Alleen actief als `OAUTH_ENABLE_SESSION_BOOTSTRAP=True` (of de oude `OAUTH_ENABLE_FIVEM_BOOTSTRAP=True`).
- `GET, POST /auth/fivem-bootstrap` - **Deprecated** alias voor `/auth/session-bootstrap` (zelfde handler), behouden voor bestaande configs.
- `POST /auth/webhook/token-revoked` - Webhook voor token revocation
- `POST /auth/webhook/user-deleted` - Webhook voor user deletion

## Current User

De `current_user` proxy geeft toegang tot de ingelogde gebruiker:

```python
from flask_rpr_oauth import current_user

@app.route('/profile')
@login_required
def profile():
    return {
        'id': current_user.id,
        'email': current_user.email,
        'voornaam': current_user.voornaam,
        'achternaam': current_user.achternaam,
        'permissions': current_user._permissions,
        'groups': current_user._groups,
        'is_authenticated': current_user.is_authenticated,
        'twofa_validated': current_user.twofa_validated
    }
```

### User Properties

```python
current_user.id               # OAuth user ID (alias voor oauth_id)
current_user.oauth_id         # OAuth user ID
current_user.email            # Email adres
current_user.voornaam         # Voornaam
current_user.achternaam       # Achternaam
current_user._permissions     # List van permission strings
current_user._groups          # List van group strings
current_user.is_authenticated # Boolean
current_user.is_active        # Boolean
current_user.is_anonymous     # Boolean
current_user.twofa_validated  # Boolean - 2FA status
```

### User Methods

```python
# Check permissions
current_user.has_permission('admin')                 # Single permission
current_user.has_any_permission('mod', 'admin')      # Any permission (OR)

# Check groups  
current_user.in_group('staff')                       # Single group
current_user.in_any_group('staff', 'mod')            # Any group (OR)

# Get permissions/groups
current_user.get_permissions()                       # Returns list
current_user.get_groups()                            # Returns list
```

## Decorators

### @login_required

```python
from flask_rpr_oauth import login_required

@app.route('/protected')
@login_required
def protected():
    return "Only for logged in users"
```

### @permission_required

```python
from flask_rpr_oauth import permission_required

# Single permission
@app.route('/admin')
@permission_required('admin')
def admin():
    return "Admin only"

# Multiple permissions (any)
@app.route('/moderator')
@permission_required(['moderator', 'admin'])
def moderator():
    return "Moderator or admin"
```

### @any_permission_required

```python
from flask_rpr_oauth import any_permission_required

@app.route('/content')
@any_permission_required('create_post', 'edit_post', 'delete_post')
def content_management():
    return "Any content permission"
```

### @group_required

```python
from flask_rpr_oauth import group_required

# Single group
@app.route('/staff')
@group_required('staff')
def staff_area():
    return "Staff only"

# Multiple groups (any)
@app.route('/team')
@group_required(['staff', 'moderator'])
def team_area():
    return "Staff or moderator"
```

### @any_group_required

```python
from flask_rpr_oauth import any_group_required

@app.route('/vip')
@any_group_required('premium', 'vip', 'admin')
def vip_content():
    return "VIP content"
```

### @require_2fa

```python
from flask_rpr_oauth import require_2fa

@app.route('/sensitive')
@require_2fa
def sensitive_data():
    return "Highly sensitive information"
```

De `@require_2fa` decorator:

- Checkt of gebruiker is ingelogd
- Valideert `acr`-claim in session (`"mfa"` of `"phr"` = voldaan)
- Passkey-inlog (`acr="phr"`) voldoet automatisch — geen extra 2FA prompt
- 2FA gedaan bij een andere app op dezelfde auth server voldoet ook
- Redirect naar auth server met `acr_values=mfa` als 2FA ontbreekt (step-up)
- Auth server toont alleen het 2FA-scherm, geen wachtwoord opnieuw vragen
- Redirect terug naar originele URL na 2FA voltooiing

## Two-Factor Authentication (2FA)

### 2FA Status

De package houdt automatisch de 2FA validatie status bij:

```python
from flask_rpr_oauth import current_user

@app.route('/profile')
def profile():
    if current_user.twofa_validated:
        return "2FA is voltooid"
    else:
        return "2FA niet voltooid"
```

### 2FA Validatie Flow

1. User logt in via OAuth (eventueel zonder 2FA)
2. Token bevat `acr`-claim (`"pwd"`, `"mfa"` of `"phr"`) en `twofa_validated` status
3. Status wordt opgeslagen in session
4. `@require_2fa` decorator checkt de `acr`-claim in de session
5. Bij ontbrekende 2FA: OIDC step-up redirect naar auth server met `acr_values=mfa`
   - Auth server controleert de **bestaande sessie** op de auth server:
     - Passkey-inlog (`auth_method=passkey`) → voldoet direct, geen extra stap
     - Al eerder 2FA gedaan (ook bij een andere app) → voldoet direct
     - Nog geen 2FA → auth server toont uitsluitend het 2FA-scherm (geen wachtwoord opnieuw)
6. User voltooit 2FA op auth server (indien nodig)
7. Na 2FA: redirect terug naar app callback met nieuw token (`acr="mfa"` of `"phr"`)
8. Redirect naar de originele beveiligde URL

### Handmatige 2FA Check

```python
@app.route('/api/check-2fa')
def check_2fa():
    rpr_auth = current_app.extensions['rpr_auth']
    
    if rpr_auth.validate_2fa():
        return {'status': '2FA validated'}
    else:
        return {'status': '2FA not validated'}, 403
```

### 2FA Redirect URL

```python
@app.route('/force-2fa')
def force_2fa():
    rpr_auth = current_app.extensions['rpr_auth']
    # Start nieuwe OAuth flow met 2FA requirement
    return rpr_auth.require_2fa_reauth()
```

**Note:** De `require_2fa_reauth()` methode start een OIDC step-up OAuth flow met `acr_values=mfa`. De auth server controleert de bestaande sessie: passkey of al eerder 2FA gedaan voldoen direct zonder extra prompt. Alleen als 2FA nog ontbreekt toont de auth server het 2FA-scherm. Gebruik `require_fresh_2fa()` als je altijd verse 2FA wil afdwingen (bijv. voor gevoelige handelingen).

## OAuth in iFrame Context (CHIPS Support)

### Het Probleem: CSRF State Mismatch in iFrames

Bij het uitvoeren van een OAuth login flow in een iframe context (bijvoorbeeld FiveM NUI, embedded widgets) kan de volgende fout optreden:

```text
mismatching_state: CSRF Warning! State not equal in request and response
```

**Oorzaak:**

- Moderne browsers blokkeren third-party cookies in iframes, zelfs met `SameSite=None; Secure`
- De OAuth state parameter wordt opgeslagen in de Flask sessie cookie
- Bij de redirect naar de OAuth server en terug naar de callback wordt de sessie cookie niet meegestuurd in iframe context
- Hierdoor kan de state niet worden gevalideerd en faalt de OAuth flow

### De Oplossing: CHIPS (Cookies Having Independent Partitioned State)

De package ondersteunt het `Partitioned` cookie attribuut dat third-party cookies mogelijk maakt in iframe context met proper partitioning.

**Standaard ingeschakeld vanaf v1.1.0** - De functionaliteit is automatisch actief voor alle applicaties.

```python
# Standaard: True (aanbevolen)
app.config['OAUTH_PARTITIONED_COOKIES'] = True

# Alleen uitzetten als je zeker weet dat je app NOOIT in iframe draait
app.config['OAUTH_PARTITIONED_COOKIES'] = False
```

**Hoe het werkt:**

1. Voegt het `Partitioned` attribuut toe aan sessie cookies
2. Browsers ondersteunen dan third-party cookies in iframe context met CHIPS
3. OAuth state validatie werkt correct omdat de sessie cookie wordt meegestuurd
4. Cookie wordt gepartitioneerd per top-level site voor privacy

**Waarom standaard aan?**

- Applicaties zoals MEOS kunnen zowel in iframe (FiveM NUI) als normaal draaien
- Geen nadelen voor normale (niet-iframe) gebruik
- Voorkomt CSRF State Mismatch errors in iframe context
- Vereist wel HTTPS en Secure cookies (production best practice)

### Voorbeeld FiveM NUI Setup

```python
from flask import Flask
from flask_rpr_oauth import RPRAuth

app = Flask(__name__)

# Basis OAuth configuratie
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['OAUTH_BASE_URL'] = 'https://auth.roleplayreality.nl'
app.config['OAUTH_CLIENT_ID'] = 'your-client-id'
app.config['OAUTH_CLIENT_SECRET'] = 'your-client-secret'
app.config['OAUTH_REDIRECT_URI'] = 'https://yourdomain.com/auth/callback'

# BELANGRIJK: Enable Partitioned cookies voor iframe support
app.config['OAUTH_PARTITIONED_COOKIES'] = True

# BELANGRIJK: Configureer Flask session cookies als Secure
# (Partitioned vereist Secure attribuut)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'None'

auth = RPRAuth(app)
```

### Vereisten voor Partitioned Cookies

1. **HTTPS vereist**: Partitioned cookies werken alleen over HTTPS
2. **Secure attribuut**: Sessie cookies moeten het `Secure` attribuut hebben
3. **Browser support**: Chromium 114+, Safari 16.4+, Firefox experimenteel

### Browser Compatibiliteit

| Browser | Versie  | Status                         |
|---------|---------|--------------------------------|
| Chrome  | 114+    | ✅ Ondersteund                 |
| Edge    | 114+    | ✅ Ondersteund                 |
| Safari  | 16.4+   | ✅ Ondersteund                 |
| Firefox | -       | ⚠️ Experimenteel (behind flag) |

### Debugging

Om te verifiëren dat Partitioned cookies correct zijn ingesteld:

1. Open Developer Tools → Application/Storage → Cookies
2. Check de sessie cookie eigenschappen
3. Verifieer dat `Partitioned` attribuut aanwezig is naast `Secure`

Voorbeeld cookie header:

```http
Set-Cookie: session=...; Secure; HttpOnly; SameSite=None; Partitioned
```

### Referenties

- [Google CHIPS Documentation](https://developers.google.com/privacy-sandbox/3pcd/chips)
- [MDN: Partitioned Attribute](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#partitioned)

## Redis Sessions (Aanbevolen)

Voor productie omgevingen is het aanbevolen om Redis te gebruiken voor session storage:

```bash
pip install "git+https://github.com/rpr-development/flask-rpr-oauth.git[redis]"
```

```python
import redis
from flask import Flask
from flask_session import Session
from flask_rpr_oauth import RPRAuth

app = Flask(__name__)

# Redis configuratie
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.from_url('redis://localhost:6379/0')
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 uur

# Initialiseer Session en OAuth
Session(app)
auth = RPRAuth(app)
```

## Webhooks

De package ondersteunt real-time updates via webhooks:

### Token Revocation

Wanneer een token wordt ingetrokken op de OAuth server:

```json
POST /auth/webhook/token-revoked
{
  "sub": "12345"
}
```

De gebruiker wordt automatisch uitgelogd als deze ingelogd is.

### User Deletion

Wanneer een gebruiker wordt verwijderd:

```json
POST /auth/webhook/user-deleted
{
  "sub": "12345"
}
```

De gebruiker wordt automatisch uitgelogd als deze ingelogd is.

### Webhook Beveiliging

Configureer een webhook secret op de OAuth server en in je app:

```python
app.config['WEBHOOK_SECRET'] = 'your-webhook-secret'
```

De webhook wordt gevalideerd via de `X-Webhook-Secret` header.

## Error Handling

De package gooit custom exceptions die je kunt afhandelen:

```python
from flask_rpr_oauth import OAuthError, TokenExpiredError, PermissionDeniedError

@app.errorhandler(TokenExpiredError)
def handle_token_expired(e):
    return "Je sessie is verlopen", 401

@app.errorhandler(PermissionDeniedError)
def handle_permission_denied(e):
    return f"Je hebt geen toegang: {e}", 403

@app.errorhandler(OAuthError)
def handle_oauth_error(e):
    return f"OAuth fout: {e}", 500
```

## Architectuur

### Session-based Authentication

De package gebruikt pure Flask sessions voor authenticatie, zonder Flask-Login dependency:

- User data wordt opgeslagen in `session['oauth_user']`
- `current_user` proxy leest direct uit de session
- Custom `@login_required` decorator checkt session
- Geen conflicten met andere authenticatie methodes

### Token Flow

1. User klikt op login → redirect naar OAuth server
2. OAuth server → redirect terug met authorization code
3. Exchange code voor access token + refresh token
4. Haal user info op met access token
5. Sla tokens + user data op in session
6. Automatische token refresh bij bijna-expiry

### Webhook Flow

1. OAuth server stuurt webhook bij token revocation of user deletion
2. Webhook signature wordt gevalideerd
3. User wordt gezocht in actieve sessions
4. Session wordt cleared
5. User is uitgelogd

## Quick Reference

### Decorators

| Decorator | Beschrijving | Voorbeeld |
|-----------|--------------|-----------|
| `@login_required` | Vereist ingelogde gebruiker | `@login_required` |
| `@permission_required('perm')` | Vereist specifieke permission | `@permission_required('admin')` |
| `@any_permission_required('p1', 'p2')` | Vereist één van de permissions | `@any_permission_required('mod', 'admin')` |
| `@group_required('group')` | Vereist specifieke groep | `@group_required('staff')` |
| `@any_group_required('g1', 'g2')` | Vereist één van de groepen | `@any_group_required('vip', 'premium')` |
| `@require_2fa` | Vereist 2FA validatie | `@require_2fa` |

### Current User Properties

```python
current_user.id                # OAuth user ID
current_user.email             # Email adres
current_user.voornaam          # Voornaam
current_user.achternaam        # Achternaam
current_user.is_authenticated  # Boolean
current_user.twofa_validated   # Boolean - 2FA status
current_user._permissions      # List[str]
current_user._groups           # List[str]
```

### Current User Methods

```python
current_user.has_permission('admin')                    # Check single permission
current_user.has_any_permission('mod', 'admin')        # Check multiple (OR)
current_user.in_group('staff')                         # Check single group
current_user.in_any_group('staff', 'mod')              # Check multiple (OR)
current_user.get_permissions()                         # Get permission list
current_user.get_groups()                              # Get groups list
```

### RPRAuth Methods

```python
rpr_auth = app.extensions['rpr_auth']

rpr_auth.validate_token()                    # Valideer access token
rpr_auth.validate_2fa()                      # Valideer 2FA status (acr=mfa/phr)
rpr_auth.require_2fa_reauth()                # OIDC step-up: acr_values=mfa (bestaande 2FA/passkey voldoet)
rpr_auth.require_2fa_reauth(force_fresh=True) # Forceer verse 2FA (prompt=login, voor gevoelige acties)
rpr_auth.require_fresh_2fa('_key')           # Verse 2FA voor specifieke actie (per session_key)
```

## Development

### Clone Repository

```bash
git clone https://github.com/rpr-development/flask-rpr-oauth.git
cd flask-rpr-oauth
```

### Install Development Dependencies

```bash
pip install -e ".[dev]"
```

### Run Tests

```bash
pytest
pytest --cov=flask_rpr_oauth
```

### Run Examples

```bash
# Simple example
python examples/simple_app.py

# Session-based example
python examples/session_based.py

# Full-featured example
python examples/full_featured.py
```

### Code Quality

```bash
# Format code
black flask_rpr_oauth tests examples

# Lint code
flake8 flask_rpr_oauth tests examples
```

## Releases

### Nieuwe Release Maken

```bash
# Update versie in __init__.py en setup.py
# Commit changes
git add .
git commit -m "Bump version to 1.0.0"

# Create and push tag
git tag -a v1.0.0 -m "Release version 1.0.0"
git push origin v1.0.0
```

### Release Notes

Maak release notes aan op GitHub met changelog:

- **Added**: Nieuwe features
- **Changed**: Wijzigingen in bestaande features
- **Fixed**: Bug fixes
- **Security**: Security updates

## Security

- Gebruik altijd HTTPS in productie
- Sla `OAUTH_CLIENT_SECRET` veilig op (environment variables)
- Gebruik sterke `SECRET_KEY` voor Flask sessions
- Configureer `OAUTH_WEBHOOK_SECRET` voor webhook validatie
- Gebruik Redis sessions in productie (server-side storage)
- Valideer altijd permissions server-side (niet alleen in templates)

## Licentie

Proprietary License - Copyright (c) 2025 RPR Development / Roleplay Reality

Deze software is gelicenseerd voor gebruik alleen. Delen, aanpassen, of distribueren is niet toegestaan zonder expliciete toestemming. Zie LICENSE bestand voor volledige voorwaarden.

## Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/rpr-development/flask-rpr-oauth/issues)
- 📧 **Email**: support@roleplayreality.nl
- 🌐 **Website**: [roleplayreality.nl](https://roleplayreality.nl)

## Credits

Ontwikkeld door [RPR Development](https://github.com/rpr-development) voor gebruik met [auth.roleplayreality.nl](https://auth.roleplayreality.nl).
