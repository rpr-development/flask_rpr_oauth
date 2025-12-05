# Stateless API Mode - M2M Token Support

## Overzicht

Flask-RPR-OAuth v1.1.0+ ondersteunt nu **stateless** API endpoints die werken met Bearer tokens in de `Authorization` header. Dit is perfect voor:

- ✅ **M2M (Machine-to-Machine) tokens** - Server-to-server authenticatie via `client_credentials` flow
- ✅ **User tokens** - Reguliere user tokens via `authorization_code` of `password` flow
- ✅ **REST APIs** - Stateless endpoints zonder session management
- ✅ **Microservices** - Service-to-service communicatie

## Verschil: Session-Based vs Stateless

### Session-Based (Origineel)

```python
from flask_rpr_oauth import RPRAuth, login_required, permission_required

app = Flask(__name__)
auth = RPRAuth(app)  # Registreert /auth/login, /auth/callback routes

@app.route('/dashboard')
@login_required  # Vereist Flask session met OAuth user
def dashboard():
    # current_user is beschikbaar via session
    return render_template('dashboard.html')

@app.route('/admin')
@permission_required('admin.access')
def admin_panel():
    # Checkt permission in session
    return 'Admin panel'
```

**Gebruik:** Web applicaties met browser-based login flows

### Stateless (Nieuw)

```python
from flask_rpr_oauth import permission_required_stateless, token_required

app = Flask(__name__)
app.config['OAUTH_BASE_URL'] = 'https://auth.roleplayreality.nl'

@app.route('/api/status')
@token_required
def api_status(userinfo):
    # Userinfo komt uit /oauth/userinfo endpoint
    # Werkt voor M2M EN user tokens!
    return {'status': 'ok', 'user': userinfo.get('sub')}

@app.route('/api/kick-player', methods=['POST'])
@permission_required_stateless('fivem.player.kick')
def kick_player(userinfo):
    # Werkt voor BEIDE:
    # 1. M2M token met fivem.player.kick permission
    # 2. User token met fivem.player.kick permission
    return {'status': 'success'}
```

**Gebruik:** REST APIs, M2M communicatie, microservices

## Installatie

```bash
pip install flask-rpr-oauth>=1.1.0
```

## Quick Start

### 1. Configuratie

```python
from flask import Flask
from flask_rpr_oauth import permission_required_stateless

app = Flask(__name__)

# Minimale config voor stateless mode
app.config['OAUTH_BASE_URL'] = 'https://auth.roleplayreality.nl'
```

### 2. Endpoints Maken

```python
@app.route('/api/protected')
@permission_required_stateless('fivem.player.kick')
def protected_endpoint(userinfo):
    """
    Endpoint beschermd met permission check.

    Args:
        userinfo: Dict met token informatie (automatisch geïnjecteerd)

    Returns:
        JSON response
    """
    # Check token type
    if userinfo.get('token_type') == 'm2m':
        # M2M token
        client_id = userinfo['client_id']
        app_name = userinfo['application_name']
        print(f'M2M request from {client_id} ({app_name})')
    else:
        # User token
        email = userinfo['email']
        print(f'User request from {email}')

    return {'status': 'success', 'userinfo': userinfo}
```

### 3. Token Verkrijgen & Testen

```bash
# Verkrijg M2M token
TOKEN=$(curl -s -X POST https://auth.roleplayreality.nl/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=your-client-id" \
  -d "client_secret=your-secret" \
  -d "scope=openid profile" | jq -r '.access_token')

# Test endpoint
curl -X GET http://localhost:5000/api/protected \
  -H "Authorization: Bearer $TOKEN" | jq
```

## Decorators

### `@token_required`

Basis decorator - vereist alleen een geldig token (user of M2M).

```python
@app.route('/api/status')
@token_required
def status(userinfo):
    return {
        'status': 'ok',
        'token_type': userinfo.get('token_type'),
        'sub': userinfo.get('sub')
    }
```

### `@permission_required_stateless(permission)`

Vereist specifieke permission. **Werkt voor user EN M2M tokens!**

```python
@app.route('/api/kick')
@permission_required_stateless('fivem.player.kick')
def kick_player(userinfo):
    # Toegang als token 'fivem.player.kick' permission heeft
    # Ongeacht of het een user of M2M token is
    return {'status': 'kicked'}
```

### `@any_permission_required_stateless(*permissions)`

Vereist minimaal ÉÉN van de opgegeven permissions.

```python
@app.route('/api/moderate')
@any_permission_required_stateless('fivem.player.kick', 'fivem.player.ban')
def moderate(userinfo):
    # Toegang als token MINIMAAL ÉÉN van deze permissions heeft
    return {'status': 'moderated'}
```

### `@user_only`

Blokkeert M2M tokens - alleen user tokens toegestaan.

```python
@app.route('/api/profile')
@user_only
@permission_required_stateless('profile.view')
def get_profile(userinfo):
    # Alleen user tokens - M2M tokens krijgen 403
    return {
        'email': userinfo['email'],
        'name': userinfo['name']
    }
```

### `@m2m_only`

Blokkeert user tokens - alleen M2M tokens toegestaan.

```python
@app.route('/api/server/heartbeat', methods=['POST'])
@m2m_only
@permission_required_stateless('fivem.server.status')
def heartbeat(userinfo):
    # Alleen M2M tokens - user tokens krijgen 403
    return {
        'status': 'ok',
        'client_id': userinfo['client_id']
    }
```

### `@scope_required_stateless(scope)`

Vereist specifieke OAuth scope.

```python
@app.route('/api/admin')
@scope_required_stateless('admin')
def admin_endpoint(userinfo):
    return {'status': 'admin access granted'}
```

### `@group_required_stateless(group)`

Vereist group membership. **Alleen voor user tokens** (M2M heeft geen groups).

```python
@app.route('/api/staff')
@group_required_stateless('administrators')
def staff_panel(userinfo):
    # Alleen users in 'administrators' groep
    # M2M tokens krijgen 403
    return {'status': 'staff access'}
```

## Userinfo Object

Alle stateless decorators injecteren een `userinfo` dict parameter:

### Voor M2M Tokens:

```python
{
    "sub": "fivem-server-1",           # client_id als subject
    "client_id": "fivem-server-1",
    "token_type": "m2m",               # Indicator voor M2M
    "application_name": "fivem",
    "application_id": 5,
    "permissions": [                   # Permissions voor deze applicatie
        "fivem.player.kick",
        "fivem.player.ban",
        "fivem.vehicle.spawn"
    ],
    "groups": [],                      # Altijd leeg voor M2M
    "scopes": ["openid", "profile"]
}
```

### Voor User Tokens:

```python
{
    "sub": "12345",                    # user_id als subject
    "token_type": "user",              # Indicator voor user
    "email": "user@example.com",
    "name": "John Doe",
    "given_name": "John",
    "family_name": "Doe",
    "permissions": [                   # User permissions
        "admin.users.view",
        "admin.users.edit"
    ],
    "groups": [                        # User groups
        "administrators",
        "moderators"
    ],
    "twofa_validated": true            # 2FA status
}
```

## Voorbeeld: Mixed Token Types

```python
from flask import Flask, request
from flask_rpr_oauth import permission_required_stateless

app = Flask(__name__)
app.config['OAUTH_BASE_URL'] = 'https://auth.roleplayreality.nl'

@app.route('/api/kick-player', methods=['POST'])
@permission_required_stateless('fivem.player.kick')
def kick_player(userinfo):
    """
    Endpoint die BEIDE token types accepteert.

    M2M gebruik: FiveM server kan spelers kicken
    User gebruik: Admin kan via dashboard spelers kicken
    """
    data = request.get_json()
    player_id = data.get('player_id')

    # Detecteer token type
    token_type = userinfo.get('token_type')

    if token_type == 'm2m':
        # M2M token - server actie
        server_name = userinfo.get('client_id')
        log_message = f'Server {server_name} kicked player {player_id}'
    else:
        # User token - admin actie
        admin_email = userinfo.get('email')
        log_message = f'Admin {admin_email} kicked player {player_id}'

    # Log actie
    app.logger.info(log_message)

    # Kick logic...

    return {
        'status': 'success',
        'player_id': player_id,
        'kicked_by': userinfo.get('sub'),
        'token_type': token_type
    }
```

**Test met M2M token:**
```bash
curl -X POST http://localhost:5000/api/kick-player \
  -H "Authorization: Bearer M2M_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"player_id": 123}'
# Werkt - M2M token heeft fivem.player.kick
```

**Test met User token:**
```bash
curl -X POST http://localhost:5000/api/kick-player \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"player_id": 123}'
# Werkt - User heeft fivem.player.kick permission
```

## Caching

De stateless decorators cachen userinfo responses om herhaalde API calls te voorkomen.

### Clear Cache (Development)

```python
from flask_rpr_oauth import clear_userinfo_cache

@app.route('/api/admin/clear-cache', methods=['POST'])
def clear_cache():
    clear_userinfo_cache()
    return {'status': 'cache cleared'}
```

### Productie: Redis Caching

Voor productie, extend de `get_userinfo_from_token` functie met Redis:

```python
import redis
from flask_rpr_oauth.stateless import get_userinfo_from_token as _original

redis_client = redis.Redis(host='localhost', port=6379, db=0)

def get_userinfo_from_token(token):
    # Check Redis cache
    cache_key = f'userinfo:{token}'
    cached = redis_client.get(cache_key)

    if cached:
        return json.loads(cached)

    # Fetch via original function
    userinfo = _original(token)

    if userinfo:
        # Cache voor 5 minuten
        redis_client.setex(cache_key, 300, json.dumps(userinfo))

    return userinfo

# Monkey patch
import flask_rpr_oauth.stateless
flask_rpr_oauth.stateless.get_userinfo_from_token = get_userinfo_from_token
```

## Complete Voorbeeld

Zie [examples/stateless_api.py](examples/stateless_api.py) voor een volledig werkend voorbeeld met:
- Mixed token type endpoints
- User-only endpoints
- M2M-only endpoints
- Permission checks
- Error handling

## Migratie van Session naar Stateless

### Voor:
```python
@app.route('/api/admin/users')
@login_required
@permission_required('admin.users.view')
def list_users():
    # Uses Flask session
    return {'users': [...]}
```

### Na:
```python
@app.route('/api/admin/users')
@permission_required_stateless('admin.users.view')
def list_users(userinfo):
    # Uses Bearer token - no session needed
    # Werkt nu ook voor M2M tokens!
    return {'users': [...]}
```

## Troubleshooting

### "OAUTH_BASE_URL not configured"

```python
# Zorg dat config is ingesteld
app.config['OAUTH_BASE_URL'] = 'https://auth.roleplayreality.nl'
```

### "Invalid or expired token"

- Check of token correct is (Bearer prefix)
- Verifieer token via `/oauth/userinfo` endpoint handmatig
- Check token expiry

### "Forbidden - permission required"

- Check welke permissions je token heeft via `GET /api/whoami`
- Voor M2M: Verifieer dat OAuth client `application_id` heeft
- Voor M2M: Check dat permission bestaat voor die applicatie in database

### Permission werkt niet voor M2M

1. Check OAuth client heeft `application_id` ingesteld
2. Verifieer permission bestaat in `perm_permissions` tabel met correct `application_id`
3. Test userinfo endpoint: `curl -H "Authorization: Bearer TOKEN" https://auth.roleplayreality.nl/oauth/userinfo`

## Zie Ook

- [RPR Auth API - M2M Permissions Documentation](../RPR-API/docs/m2m-permissions.md)
- [FiveM M2M Example](../RPR-API/docs/examples/fivem-m2m-permissions.md)
- [Session-Based Examples](examples/)
