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
- 📣 **Back-channel logout** - Centrale logout/ban werkt direct door in je app (OIDC Back-Channel Logout 1.0)
- 🔔 **Security-events (SSF)** - Ondertekende RISC/CAEP-events van de auth server (RFC 8417/8935)
- 🔁 **SCIM-provisioning** - Automatische user-sync vanuit de auth server (RFC 7643/7644, opt-in)
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

# Audience-check (RFC 8707, default: uit). De canonieke resource-URI van DEZE
# applicatie, gelijk aan applications.resource_uri op de auth-server. Indien
# gezet worden Bearer-tokens die aan een ANDERE resource gebonden zijn (aud)
# geweigerd (401). Tokens zonder aud (legacy) blijven overal geldig.
app.config['OAUTH_RESOURCE_ID'] = 'https://gms.roleplayreality.nl'

# Token-revocatie bij logout (RFC 7009, default: True). /auth/logout trekt de
# sessietokens server-naar-server in, zodat ze óók sterven als de gebruiker de
# end_session-bevestiging op de auth server nooit afmaakt. Best-effort.
app.config['OAUTH_REVOKE_ON_LOGOUT'] = True

# Signalen van de auth server (back-channel logout, security-events, SCIM):
# zie de sectie "Signalen van de auth-server" verderop voor
# OAUTH_ENABLE_BACKCHANNEL_LOGOUT, OAUTH_LOGOUT_REDIS_URL, OAUTH_ENABLE_SSF,
# OAUTH_SSF_AUDIENCE, OAUTH_ENABLE_SCIM en de OAUTH_ON_*-callbacks.

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

# Vereist een verse 2FA-login bij /auth/login zelf (stuurt acr_values=mfa mee
# op de allereerste authorize-redirect, i.p.v. pas bij een @require_2fa-route).
# Default: False.
app.config['OAUTH_REQUIRE_2FA'] = False

# DPoP (RFC 9449, sender-constrained tokens). Presenteert een client een token via
# `Authorization: DPoP <token>` + een `DPoP:`-proofheader, dan valideert de decorator-laag
# de proof lokaal (tegen deze request-URL/-methode + ath) en eist dat de proof-thumbprint
# matcht met de `cnf.jkt` uit introspectie. Zet je dit AAN, dan worden gewone Bearer-tokens
# geweigerd (401 met een `WWW-Authenticate: DPoP`-challenge) — bedoeld voor resource servers
# die uitsluitend sender-constrained API-/MCP-clients bedienen. Default UIT: Bearer blijft de
# standaard (o.a. sessie-cookie- en FiveM-consumers). De optionele jti-replaycache hergebruikt
# OAUTH_LOGOUT_REDIS_URL (of SESSION_REDIS); zonder Redis is de cache fail-open.
app.config['OAUTH_REQUIRE_DPOP'] = False

# Timeout (seconden) voor alle uitgaande HTTP-calls naar de auth-server
# (userinfo, introspectie, token-revocatie, JWKS). Default: 10.
app.config['OAUTH_TIMEOUT'] = 10

# Interval (seconden) waarop de before_request-hook het sessie-token opnieuw
# valideert bij de auth-server (/oauth/userinfo). 0 = elke request valideren.
# Default: 300.
app.config['OAUTH_TOKEN_REVALIDATE_INTERVAL'] = 300

# Waar de auth-server na RP-Initiated Logout naartoe mag redirecten
# (post_logout_redirect_uri, OIDC RP-Initiated Logout 1.0 §2). Optioneel; zonder
# deze waarde toont de auth-server zijn eigen post-logout pagina.
app.config['OAUTH_POST_LOGOUT_REDIRECT_URI'] = 'https://jouwapp.nl/'

# In-memory cache voor /oauth/userinfo- en /oauth/introspect-resultaten, om niet
# bij elke request een HTTP-round-trip naar de auth-server te maken. TTL wordt
# nooit langer dan de resterende levensduur van het token zelf. Defaults: 60s / 1000 tokens.
app.config['OAUTH_USERINFO_CACHE_TTL'] = 60
app.config['OAUTH_USERINFO_CACHE_MAXSIZE'] = 1000

# Scopes die je in het RFC 9728 protected-resource-metadata-document
# (/.well-known/oauth-protected-resource) wilt adverteren. Zonder deze waarde
# wordt OAUTH_SCOPE gebruikt.
app.config['OAUTH_RESOURCE_SCOPES_SUPPORTED'] = ['openid', 'profile', 'email']

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
- `GET, POST /auth/logout` - Logout: trekt de sessietokens in op de auth server (RFC 7009), wist de lokale sessie en start RP-Initiated Logout (`end_session`). Beide methodes gebruiken dezelfde handler; gebruik `POST` (vanuit een CSRF-beschermd formulier) als je een cross-site-triggerbare `GET`-logout wilt vermijden.
- `GET, POST /auth/session-bootstrap` - Bearer-based auto-login: zet een first-party sessie op vanuit een aangeleverd access token (via POST `access_token` (voorkeur) / GET-query / `Authorization: Bearer`), NIET een code. Alleen actief als `OAUTH_ENABLE_SESSION_BOOTSTRAP=True`.
- `POST /auth/backchannel-logout` - Ontvanger voor ondertekende logout tokens (OIDC Back-Channel Logout 1.0); default aan
- `POST /auth/ssf` - Gedeelde ontvanger voor Security Event Tokens (SSF/RISC/CAEP, RFC 8417); default aan
- `POST /scim/v2/Users` en `GET, PUT, DELETE /scim/v2/Users/<id>` - SCIM 2.0-provisioning; alleen actief met `OAUTH_ENABLE_SCIM=True`

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
        'full_name': current_user.full_name,
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
current_user.name             # Weergavenaam: voornaam + eerste letter achternaam ("Jan J.")
current_user.full_name        # Volledige naam: voornaam + name_prefix (indien gezet) + achternaam
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

## Signalen van de auth-server (back-channel logout & security-events)

De auth-server duwt belangrijke gebeurtenissen actief naar je app, buiten de browser om:
uitloggen, een ban, een verwijderd account of een gewijzigd wachtwoord werkt zo binnen
een minuut door in je applicatie. De package registreert de ontvangers automatisch; jij
configureert alleen (optioneel) callbacks. De berichten zijn **ondertekende JWT's**
(RS256, dezelfde JWKS als de id_tokens) — er is dus géén gedeeld secret nodig: de
handtekening ís de authenticatie. De package valideert handtekening, `iss` (de
discovery-issuer), `aud` en de events-claim; alles wat niet klopt wordt met 400 geweigerd.

### Back-channel logout (OIDC Back-Channel Logout 1.0)

Bij centraal uitloggen, een ban of REVIEW-status POST de auth-server een `logout_token`
naar `POST /auth/backchannel-logout`. De package beëindigt daarna álle sessies van die
gebruiker: er komt een logout-markering in Redis en elke sessie sterft bij zijn
eerstvolgende request (een `before_request`-check).

```python
# Default AAN. Redis is nodig om álle sessies te raken; zonder Redis kan alleen
# de sessie van het huidige request beëindigd worden (wordt als error gelogd).
app.config['OAUTH_ENABLE_BACKCHANNEL_LOGOUT'] = True
app.config['OAUTH_LOGOUT_REDIS_URL'] = 'redis://localhost:6379/0'
# Zonder OAUTH_LOGOUT_REDIS_URL wordt een geconfigureerde Flask-Session
# SESSION_REDIS automatisch hergebruikt.

# Levensduur van de logout-markering; moet elke sessie overleven die op het
# moment van de logout bestond (default: 86400 = 24 uur).
app.config['OAUTH_LOGOUT_MARKER_TTL'] = 86400
```

### Security-events (SSF — RFC 8417 SET's, RFC 8935 push)

`POST /auth/ssf` is de gedeelde ontvanger voor Security Event Tokens van de auth-server.
Registreer je app als **event-stream** in het admin-dashboard van de auth-server
(Events & signalen → Event-streams) met deze URL en een audience; de event-stream-worker
bezorgt elk event binnen een minuut (met retries bij storing).

| Event | Wanneer | Automatische actie |
| --- | --- | --- |
| `account-disabled` (RISC) | Account geblokkeerd (ban/REVIEW) | Alle sessies beëindigd |
| `account-purged` (RISC) | Account verwijderd (AVG) | Alle sessies beëindigd |
| `session-revoked` (CAEP) | Sessie/tokens centraal ingetrokken | Alle sessies beëindigd |
| `credential-change` (CAEP) | Wachtwoord of 2FA gewijzigd | Alle sessies beëindigd |

Sessie-beëindiging gebeurt altijd (zelfde Redis-mechanisme als back-channel logout).
Daarnaast kun je per event een callback registreren, bijvoorbeeld om lokale data op te
ruimen bij een verwijderd account:

```python
def on_account_purged(sub, payload):
    """sub = het user-id op de auth-server (string); payload = het event-object."""
    LocalUser.query.filter_by(oauth_id=sub).delete()
    db.session.commit()

app.config['OAUTH_ON_ACCOUNT_PURGED'] = on_account_purged
# Ook beschikbaar: OAUTH_ON_ACCOUNT_DISABLED, OAUTH_ON_SESSION_REVOKED,
# OAUTH_ON_CREDENTIAL_CHANGE — allemaal (sub, payload). Een exception in een
# callback wordt gelogd maar breekt de verwerking niet (fail-safe).

app.config['OAUTH_ENABLE_SSF'] = True          # default AAN
app.config['OAUTH_SSF_AUDIENCE'] = 'gms'       # verwachte `aud` in de SET;
# default = OAUTH_CLIENT_ID. Moet gelijk zijn aan de audience van de
# event-stream zoals op de auth-server geconfigureerd.
```

Onbekende event-types worden genegeerd; een geldige SET zonder enig bekend event geeft
400, zodat de verzender het merkt. Succes = `202 Accepted` (RFC 8935).

### SCIM-provisioning (RFC 7643/7644)

Met SCIM duwt de auth-server het **user-bestand** actief naar je app: aanmaken, naam-/
status-/groepswijzigingen en verwijdering, zodat lokale accounts nooit uit de pas lopen.
De package levert de endpoints (`/scim/v2/Users[/<id>]`); jouw app implementeert alleen
wat er lokaal moet gebeuren, via callbacks. **Default UIT** — zet 'm pas aan als de
callbacks er zijn.

Contract met de auth-server (de scim-worker):

| Operatie | Betekenis | Verwacht gedrag |
| --- | --- | --- |
| `PUT /Users/<id>` | User aangemaakt/gewijzigd | **Upsert**: bestaat 'ie lokaal niet, maak 'm aan |
| `POST /Users` | Create-fallback (`externalId` = user-id) | Zelfde als PUT |
| `DELETE /Users/<id>` | User verwijderd | Idempotent: al weg = ook goed (204) |
| `GET /Users/<id>` | AVG-export (privacy-worker) | Lokale data teruggeven, of 404 |

```python
app.config['OAUTH_ENABLE_SCIM'] = True
# Aanbevolen: audience-binding aanzetten (RFC 8707), zodat alleen tokens die
# voor déze app gemunt zijn worden geaccepteerd:
app.config['OAUTH_RESOURCE_ID'] = 'https://gms.roleplayreality.nl'

def scim_sync(user_id, resource):
    """User aangemaakt of gewijzigd. resource = de SCIM User-resource (dict)."""
    ...

def scim_delete(user_id):
    """User verwijderd op de auth-server. Idempotent implementeren."""
    ...

def scim_get(user_id):
    """Optioneel: lokale data voor de AVG-export. None = gebruiker onbekend (404)."""
    ...

app.config['OAUTH_ON_SCIM_SYNC'] = scim_sync
app.config['OAUTH_ON_SCIM_DELETE'] = scim_delete
app.config['OAUTH_ON_SCIM_GET'] = scim_get      # optioneel
```

Beveiliging: elk SCIM-request vereist een Bearer **M2M-token** dat via introspectie
valideert (inclusief de audience-check hierboven) én de provisioning-permissie draagt
(`OAUTH_SCIM_PERMISSION`, default `auth.scim.provision` — de permissie van de
scim-worker op de auth-server).

Foutcontract: een exception in een callback geeft `500` — de scim-worker zet de job dan
terug in de wachtrij en probeert het opnieuw (tot 5×). Een ontbrekende sync-/delete-callback
geeft `501`; een `GET` zonder callback geeft `404` (= dit systeem heeft geen exportdata).
Server-kant inschakelen: zet de SCIM-basis-URL op de applicatie in het
admin-dashboard (Resource servers → Applicaties), bijv. `https://jouw-app/scim/v2`.

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

### Signalen-flow (BCL/SSF)

1. Auth server POST een ondertekend token naar `/auth/backchannel-logout` of `/auth/ssf`
2. Package valideert handtekening (JWKS), `iss`, `aud` en de events-claim
3. Logout-markering voor die gebruiker gaat in Redis (+ optionele app-callback)
4. Elke sessie van de gebruiker sterft bij zijn eerstvolgende request
5. Antwoord aan de auth server: `200`/`202`; bij een fout `400` zodat de worker het merkt

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
current_user.name              # Weergavenaam ("Jan J.")
current_user.full_name         # Volledige naam
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
- Configureer Redis (`OAUTH_LOGOUT_REDIS_URL` of `SESSION_REDIS`) zodat back-channel logout en security-events álle sessies kunnen beëindigen
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
