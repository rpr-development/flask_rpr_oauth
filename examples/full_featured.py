"""
Full Featured Example
~~~~~~~~~~~~~~~~~~~~~

Volledig voorbeeld met alle features van Flask RPR OAuth.
"""

import os

from flask import Flask, render_template_string, session
from flask_session import Session
import redis
from flask_rpr_oauth import (
    RPRAuth,
    login_required,
    permission_required,
    any_permission_required,
    group_required,
    any_group_required,
    current_user,
)

app = Flask(__name__)

# Basis configuratie
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]

# OAuth configuratie
app.config["OAUTH_BASE_URL"] = "https://auth.roleplayreality.nl"
app.config["OAUTH_CLIENT_ID"] = os.environ["OAUTH_CLIENT_ID"]
app.config["OAUTH_CLIENT_SECRET"] = os.environ["OAUTH_CLIENT_SECRET"]
app.config["OAUTH_REDIRECT_URI"] = "http://localhost:5000/auth/callback"
app.config["OAUTH_SCOPE"] = "openid profile email"
app.config["OAUTH_AUTO_VALIDATE"] = True

# Redis session configuratie
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_KEY_PREFIX"] = "myapp:"
app.config["SESSION_REDIS"] = redis.from_url("redis://localhost:6379/0")

# Webhook configuratie
app.config["WEBHOOK_SECRET"] = os.environ["WEBHOOK_SECRET"]

# Initialiseer session
Session(app)

# Initialiseer OAuth
auth = RPRAuth(app)


@app.route("/")
def index():
    """Home page."""
    if current_user.is_authenticated:
        return render_template_string(
            """
            <h1>Welkom, {{ user.voornaam }}!</h1>
            <p>Email: {{ user.email }}</p>
            <ul>
                <li><a href="/profile">Mijn profiel</a></li>
                <li><a href="/users">Gebruikers lijst (users.read)</a></li>
                <li><a href="/moderate">Moderatie (moderator of admin)</a></li>
                <li><a href="/staff">Staff panel (staff groep)</a></li>
                <li><a href="/special">Special content (VIP, Premium, of Admin groep)</a></li>
                <li><a href="/admin">Admin panel (admin.access)</a></li>
            </ul>
            <p><a href="/auth/logout">Uitloggen</a></p>
        """,
            user=current_user,
        )
    else:
        return render_template_string(
            """
            <h1>Welkom!</h1>
            <p><a href="/auth/login">Inloggen met RPR Auth</a></p>
        """
        )


@app.route("/profile")
@login_required
def profile():
    """User profile page."""
    return render_template_string(
        """
        <h1>Profiel</h1>
        <p>OAuth ID: {{ user.oauth_id }}</p>
        <p>Email: {{ user.email }}</p>
        <p>Naam: {{ user.voornaam }} {{ user.achternaam }}</p>
        
        <h2>Permissions</h2>
        {% if user.get_permissions() %}
        <ul>
        {% for perm in user.get_permissions() %}
            <li>{{ perm }}</li>
        {% endfor %}
        </ul>
        {% else %}
        <p>Geen permissions</p>
        {% endif %}
        
        <h2>Groups</h2>
        {% if user.get_groups() %}
        <ul>
        {% for group in user.get_groups() %}
            <li>{{ group }}</li>
        {% endfor %}
        </ul>
        {% else %}
        <p>Geen groepen</p>
        {% endif %}
        
        <p><a href="/">Terug</a></p>
    """,
        user=current_user,
    )


@app.route("/users")
@login_required
@permission_required("users.read")
def list_users():
    """User list (requires users.read permission)."""
    return render_template_string(
        """
        <h1>Gebruikers Lijst</h1>
        <p>Je hebt de 'users.read' permission!</p>
        <p><a href="/">Terug</a></p>
    """
    )


@app.route("/moderate")
@login_required
@any_permission_required("moderator", "admin")
def moderate():
    """Moderation panel (requires moderator OR admin permission)."""
    return render_template_string(
        """
        <h1>Moderatie Panel</h1>
        <p>Je hebt 'moderator' of 'admin' permission!</p>
        <p><a href="/">Terug</a></p>
    """
    )


@app.route("/staff")
@login_required
@group_required("staff")
def staff_panel():
    """Staff panel (requires staff group membership)."""
    return render_template_string(
        """
        <h1>Staff Panel</h1>
        <p>Je bent lid van de 'staff' groep!</p>
        <p><a href="/">Terug</a></p>
    """
    )


@app.route("/special")
@login_required
@any_group_required("vip", "premium", "admin")
def special_content():
    """Special content (requires VIP, Premium, or Admin group)."""
    return render_template_string(
        """
        <h1>Special Content</h1>
        <p>Je bent lid van 'vip', 'premium', of 'admin' groep!</p>
        <p><a href="/">Terug</a></p>
    """
    )


@app.route("/admin")
@login_required
@permission_required("admin.access")
def admin():
    """Admin panel (requires admin.access permission)."""
    return render_template_string(
        """
        <h1>Admin Panel</h1>
        <p>Welkom in het admin panel, {{ user.voornaam }}!</p>
        <p><a href="/">Terug</a></p>
    """,
        user=current_user,
    )


@app.route("/debug")
@login_required
def debug():
    """Debug info (voor development)."""
    return render_template_string(
        """
        <h1>Debug Info</h1>
        <h2>Current User</h2>
        <pre>{{ user }}</pre>
        
        <h2>Session Data</h2>
        <pre>{{ session }}</pre>
        
        <p><a href="/">Terug</a></p>
    """,
        user=current_user,
        session=dict(session),
    )


if __name__ == "__main__":
    app.run(debug=False, port=5000)  # nosec B201
