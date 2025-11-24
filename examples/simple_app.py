"""
Simple Example App
~~~~~~~~~~~~~~~~~~

Basis voorbeeld van Flask RPR OAuth gebruik.
"""

from flask import Flask, render_template_string
from flask_rpr_oauth import RPRAuth, login_required, permission_required, current_user

app = Flask(__name__)

# Configuratie
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['OAUTH_BASE_URL'] = 'https://auth.roleplayreality.nl'
app.config['OAUTH_CLIENT_ID'] = 'your-client-id'
app.config['OAUTH_CLIENT_SECRET'] = 'your-client-secret'
app.config['OAUTH_REDIRECT_URI'] = 'http://localhost:5000/auth/callback'

# Initialiseer OAuth
auth = RPRAuth(app)


@app.route('/')
def index():
    """Home page."""
    if current_user.is_authenticated:
        return render_template_string('''
            <h1>Welkom, {{ user.voornaam }}!</h1>
            <p>Email: {{ user.email }}</p>
            <p><a href="/profile">Mijn profiel</a></p>
            <p><a href="/admin">Admin panel</a></p>
            <p><a href="/auth/logout">Uitloggen</a></p>
        ''', user=current_user)
    else:
        return render_template_string('''
            <h1>Welkom!</h1>
            <p><a href="/auth/login">Inloggen</a></p>
        ''')


@app.route('/profile')
@login_required
def profile():
    """User profile page."""
    return render_template_string('''
        <h1>Profiel</h1>
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
    ''', user=current_user)


@app.route('/admin')
@login_required
@permission_required('admin.access')
def admin():
    """Admin panel (requires admin.access permission)."""
    return render_template_string('''
        <h1>Admin Panel</h1>
        <p>Welkom in het admin panel, {{ user.voornaam }}!</p>
        <p><a href="/">Terug</a></p>
    ''', user=current_user)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
