"""
Voorbeeld van 2FA (Two-Factor Authentication) gebruik met flask-rpr-oauth.

Dit voorbeeld toont hoe je endpoints kunt beveiligen met 2FA validatie.
"""

from flask import Flask, jsonify, render_template_string
from flask_rpr_oauth import RPRAuth, login_required, require_2fa, current_user

app = Flask(__name__)

# Configuratie
app.config.update(
    SECRET_KEY="your-secret-key-change-in-production",
    OAUTH_BASE_URL="https://auth.roleplayreality.nl",
    OAUTH_CLIENT_ID="your-client-id",
    OAUTH_CLIENT_SECRET="your-client-secret",
    OAUTH_REDIRECT_URI="http://localhost:5000/auth/callback",
    OAUTH_SCOPE="openid profile email",
)

# Initialiseer OAuth
auth = RPRAuth(app)

# HTML template
TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>2FA Example</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .status { padding: 10px; margin: 10px 0; border-radius: 5px; }
        .success { background: #d4edda; color: #155724; }
        .warning { background: #fff3cd; color: #856404; }
        .info { background: #d1ecf1; color: #0c5460; }
        .links { margin: 20px 0; }
        .links a { display: inline-block; padding: 10px 20px; margin: 5px; 
                   background: #007bff; color: white; text-decoration: none; border-radius: 5px; }
        .links a:hover { background: #0056b3; }
        .code { background: #f4f4f4; padding: 10px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>🔐 Flask RPR OAuth - 2FA Example</h1>
    
    {% if current_user.is_authenticated %}
        <div class="status success">
            <strong>✅ Ingelogd als:</strong> {{ current_user.email }}
        </div>
        
        {% if current_user.twofa_validated %}
            <div class="status success">
                <strong>🔒 2FA Status:</strong> Gevalideerd
            </div>
        {% else %}
            <div class="status warning">
                <strong>⚠️ 2FA Status:</strong> Niet gevalideerd
                <p>Sommige endpoints vereisen 2FA. Klik op "Sensitive Data (2FA vereist)" om naar de 2FA pagina te gaan.</p>
            </div>
        {% endif %}
        
        <div class="links">
            <a href="/profile">👤 Profile (Login vereist)</a>
            <a href="/sensitive">🔐 Sensitive Data (2FA vereist)</a>
            <a href="/api/data">📊 API Data (JSON)</a>
            <a href="/force-2fa">🔑 Force 2FA</a>
            <a href="/auth/logout">🚪 Logout</a>
        </div>
        
        <h2>User Info</h2>
        <div class="code">
            <strong>Email:</strong> {{ current_user.email }}<br>
            <strong>Naam:</strong> {{ current_user.voornaam }} {{ current_user.achternaam }}<br>
            <strong>2FA:</strong> {{ 'Ja ✅' if current_user.twofa_validated else 'Nee ❌' }}<br>
            <strong>Permissions:</strong> {{ current_user._permissions|join(', ') or 'Geen' }}<br>
            <strong>Groups:</strong> {{ current_user._groups|join(', ') or 'Geen' }}
        </div>
    {% else %}
        <div class="status info">
            <strong>ℹ️ Niet ingelogd</strong>
            <p>Log in om de 2FA functionaliteit te testen.</p>
        </div>
        
        <div class="links">
            <a href="/auth/login">🔐 Login</a>
        </div>
    {% endif %}
    
    <h2>Endpoints</h2>
    <div class="code">
        <strong>GET /</strong> - Home (public)<br>
        <strong>GET /profile</strong> - Profile page (@login_required)<br>
        <strong>GET /sensitive</strong> - Sensitive data (@require_2fa)<br>
        <strong>GET /api/data</strong> - API endpoint (@require_2fa)<br>
        <strong>GET /force-2fa</strong> - Handmatige 2FA redirect<br>
        <strong>GET /auth/login</strong> - Start OAuth flow<br>
        <strong>GET /auth/logout</strong> - Logout
    </div>
    
    <h2>Hoe werkt het?</h2>
    <ol>
        <li>Log in via de OAuth server</li>
        <li>Na login wordt de 2FA status automatisch opgeslagen</li>
        <li>Endpoints met <code>@require_2fa</code> checken de 2FA status</li>
        <li>Als 2FA niet is voltooid, redirect naar auth server</li>
        <li>Na 2FA voltooiing, redirect terug naar originele URL</li>
    </ol>
</body>
</html>
"""


@app.route("/")
def index():
    """Home page met status overview."""
    return render_template_string(TEMPLATE, current_user=current_user)


@app.route("/profile")
@login_required
def profile():
    """
    Profile page - vereist alleen login, geen 2FA.
    """
    return jsonify(
        {
            "email": current_user.email,
            "name": f"{current_user.voornaam} {current_user.achternaam}",
            "twofa_validated": current_user.twofa_validated,
            "permissions": current_user._permissions,
            "groups": current_user._groups,
        }
    )


@app.route("/sensitive")
@require_2fa
def sensitive_data():
    """
    Sensitive endpoint - vereist 2FA validatie.

    Als user geen 2FA heeft voltooid, wordt deze automatisch
    doorgestuurd naar de auth server om 2FA te voltooien.
    """
    return jsonify(
        {
            "message": "Toegang verleend tot gevoelige data",
            "user": current_user.email,
            "twofa_validated": current_user.twofa_validated,
            "data": {"secret": "This is highly sensitive information", "access_level": "maximum"},
        }
    )


@app.route("/api/data")
@require_2fa
def api_data():
    """
    API endpoint die 2FA vereist.
    """
    return jsonify(
        {
            "status": "success",
            "twofa_required": True,
            "twofa_validated": current_user.twofa_validated,
            "data": [
                {"id": 1, "value": "Secret data 1"},
                {"id": 2, "value": "Secret data 2"},
                {"id": 3, "value": "Secret data 3"},
            ],
        }
    )


@app.route("/force-2fa")
@login_required
def force_2fa():
    """
    Force 2FA validation - redirect direct naar 2FA pagina.
    """
    from flask import redirect

    # Check of 2FA al is voltooid
    if current_user.twofa_validated:
        return jsonify({"message": "2FA is al voltooid", "status": "already_validated"})

    # Haal RPRAuth instance op
    rpr_auth = app.extensions["rpr_auth"]

    # Sla de next URL op in session voor redirect na 2FA
    session["next"] = "http://localhost:5000/"

    # Start nieuwe OAuth flow met 2FA requirement
    return rpr_auth.require_2fa_reauth()


@app.route("/check-2fa")
@login_required
def check_2fa():
    """
    Check 2FA status via API call naar auth server.

    Dit endpoint valideert de actuele 2FA status bij de auth server
    en update de session.
    """
    rpr_auth = app.extensions["rpr_auth"]

    # Valideer 2FA bij auth server
    is_valid = rpr_auth.validate_2fa()

    return jsonify(
        {
            "twofa_validated": is_valid,
            "session_status": current_user.twofa_validated,
            "message": "2FA is geldig" if is_valid else "2FA validatie vereist",
        }
    )


@app.errorhandler(403)
def forbidden(e):
    """Handle 403 Forbidden errors."""
    return jsonify({"error": "Forbidden", "message": "Je hebt geen toegang tot deze resource"}), 403


@app.errorhandler(401)
def unauthorized(e):
    """Handle 401 Unauthorized errors."""
    return (
        jsonify(
            {
                "error": "Unauthorized",
                "message": "Je moet ingelogd zijn om deze resource te benaderen",
            }
        ),
        401,
    )


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("🔐 Flask RPR OAuth - 2FA Example")
    print("=" * 60)
    print("\nEndpoints:")
    print("  http://localhost:5000/           - Home page")
    print("  http://localhost:5000/profile    - Profile (@login_required)")
    print("  http://localhost:5000/sensitive  - Sensitive data (@require_2fa)")
    print("  http://localhost:5000/api/data   - API data (@require_2fa)")
    print("  http://localhost:5000/force-2fa  - Force 2FA redirect")
    print("\nAuth routes:")
    print("  http://localhost:5000/auth/login    - Login")
    print("  http://localhost:5000/auth/callback - OAuth callback")
    print("  http://localhost:5000/auth/logout   - Logout")
    print("\nZorg dat je OAUTH_CLIENT_ID en OAUTH_CLIENT_SECRET configureert!")
    print("=" * 60 + "\n")

    app.run(debug=False, port=5000)  # nosec B201
