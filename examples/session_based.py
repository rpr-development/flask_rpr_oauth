"""
Session-Based Example (zonder Flask-Login)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Voorbeeld van Flask RPR OAuth gebruik zonder Flask-Login dependency.
Users worden opgeslagen in session in plaats van via Flask-Login.
"""

import os

from flask import Flask, render_template_string
from flask_rpr_oauth import RPRAuth, login_required, permission_required, current_user

app = Flask(__name__)

# Configuratie
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.config["OAUTH_BASE_URL"] = "https://auth.roleplayreality.nl"
app.config["OAUTH_CLIENT_ID"] = os.environ["OAUTH_CLIENT_ID"]
app.config["OAUTH_CLIENT_SECRET"] = os.environ["OAUTH_CLIENT_SECRET"]
app.config["OAUTH_REDIRECT_URI"] = "http://localhost:5000/auth/callback"

# Initialiseer OAuth ZONDER Flask-Login
# use_flask_login=False betekent: gebruik altijd session-based auth
auth = RPRAuth(app, use_flask_login=False)


@app.route("/")
def index():
    """Home page."""
    if current_user.is_authenticated:
        return render_template_string(
            """
            <h1>Welkom, {{ user.voornaam }}!</h1>
            <p>Email: {{ user.email }}</p>
            <p>Je applicatie gebruikt <strong>session-based auth</strong> (geen Flask-Login).</p>
            <p><a href="/profile">Mijn profiel</a></p>
            <p><a href="/admin">Admin panel</a></p>
            <p><a href="/auth/logout">Uitloggen</a></p>
        """,
            user=current_user,
        )
    else:
        return render_template_string(
            """
            <h1>Welkom!</h1>
            <p>Deze app gebruikt <strong>session-based auth</strong> zonder Flask-Login.</p>
            <p><a href="/auth/login">Inloggen</a></p>
        """
        )


@app.route("/profile")
@login_required
def profile():
    """User profile page."""
    return render_template_string(
        """
        <h1>Profiel</h1>
        <p><strong>Auth Method:</strong> Session-based (geen Flask-Login)</p>
        <hr>
        <p>OAuth ID: {{ user.oauth_id }}</p>
        <p>Email: {{ user.email }}</p>
        <p>Naam: {{ user.voornaam }} {{ user.achternaam }}</p>
        <h2>Permissions</h2>
        <ul>
        {% for perm in user.get_permissions() %}
            <li>{{ perm }}</li>
        {% endfor %}
        </ul>
        <h2>Groups</h2>
        <ul>
        {% for group in user.get_groups() %}
            <li>{{ group }}</li>
        {% endfor %}
        </ul>
        <p><a href="/">Terug</a></p>
    """,
        user=current_user,
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
        <p>Je hebt de 'admin.access' permission!</p>
        <p><a href="/">Terug</a></p>
    """,
        user=current_user,
    )


if __name__ == "__main__":
    print("=" * 60)
    print("Session-Based Auth Example (zonder Flask-Login)")
    print("=" * 60)
    print("Deze app gebruikt GEEN Flask-Login dependency.")
    print("Users worden opgeslagen in Flask session.")
    print()
    print("Start de app op: http://localhost:5000")
    print("=" * 60)
    print()

    app.run(debug=False, port=5000)  # nosec B201
