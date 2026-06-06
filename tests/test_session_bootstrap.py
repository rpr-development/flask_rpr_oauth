"""
Tests voor de /auth/session-bootstrap route (bearer-based).

Mockt /oauth/userinfo zodat er geen echte HTTP-call wordt gedaan. De route
zet een first-party sessie op vanuit een aangeleverd access token; er wordt
GEEN code ingewisseld bij /oauth/token.
"""

from unittest.mock import patch, MagicMock

from flask import Flask

from flask_rpr_oauth import RPRAuth


def _make_app(enable_bootstrap=False, legacy_flag=False):
    """Create a test Flask app with optional bootstrap flag(s)."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret"
    app.config["OAUTH_BASE_URL"] = "https://auth.test.nl"
    app.config["OAUTH_CLIENT_ID"] = "test-client"
    app.config["OAUTH_CLIENT_SECRET"] = "test-secret"
    app.config["OAUTH_REDIRECT_URI"] = "http://localhost/auth/callback"
    app.config["TESTING"] = True
    if enable_bootstrap:
        app.config["OAUTH_ENABLE_SESSION_BOOTSTRAP"] = True
    if legacy_flag:
        app.config["OAUTH_ENABLE_FIVEM_BOOTSTRAP"] = True

    RPRAuth(app)

    # Eenvoudige index-route zodat redirects naar "/" een 200 kunnen geven
    @app.route("/")
    def index():
        return "home"

    return app


def _userinfo_response(user_status="ACTIVE"):
    """Mock /oauth/userinfo 200 response."""
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = {
        "sub": "user-123",
        "email": "fivem@test.nl",
        "given_name": "Five",
        "family_name": "Em",
        "acr": "pwd",
        "permissions": ["phone.use"],
        "groups": ["players"],
        "user_status": user_status,
    }
    return resp


def test_bootstrap_disabled_returns_404():
    """Zonder een enable-vlag geeft de route 404."""
    app = _make_app(enable_bootstrap=False)
    client = app.test_client()

    resp = client.get("/auth/session-bootstrap?access_token=at-123")
    assert resp.status_code == 404


def test_bootstrap_missing_token_returns_400():
    """Zonder access token geeft de route 400."""
    app = _make_app(enable_bootstrap=True)
    client = app.test_client()

    resp = client.get("/auth/session-bootstrap")
    assert resp.status_code == 400


def test_bootstrap_success_populates_session_and_redirects_to_safe_next():
    """Een geldig access token vult de sessie en redirect (303) naar een veilige next."""
    app = _make_app(enable_bootstrap=True)
    client = app.test_client()

    with patch(
        "flask_rpr_oauth.auth.requests.get", return_value=_userinfo_response()
    ) as mock_get:
        resp = client.post(
            "/auth/session-bootstrap",
            data={"access_token": "at-123", "next": "/dashboard", "id_token": "id-123"},
        )

    assert resp.status_code == 303
    assert resp.headers["Location"].endswith("/dashboard")

    # Token gevalideerd via /oauth/userinfo met de bearer
    assert mock_get.call_count == 1
    args, kwargs = mock_get.call_args
    assert args[0].endswith("/oauth/userinfo")
    assert kwargs["headers"]["Authorization"] == "Bearer at-123"

    # Sessie gevuld
    with client.session_transaction() as sess:
        assert sess["oauth_user"]["oauth_id"] == "user-123"
        assert sess["oauth_user"]["email"] == "fivem@test.nl"
        assert sess["oauth_permissions"] == ["phone.use"]
        assert sess["oauth_groups"] == ["players"]
        assert sess["oauth_token"]["access_token"] == "at-123"
        assert sess["oauth_token"]["id_token"] == "id-123"


def test_bootstrap_accepts_bearer_header():
    """Het access token mag ook via de Authorization: Bearer header komen."""
    app = _make_app(enable_bootstrap=True)
    client = app.test_client()

    with patch("flask_rpr_oauth.auth.requests.get", return_value=_userinfo_response()):
        resp = client.get(
            "/auth/session-bootstrap?next=/dashboard",
            headers={"Authorization": "Bearer header-token"},
        )

    assert resp.status_code == 303
    assert resp.headers["Location"].endswith("/dashboard")
    with client.session_transaction() as sess:
        assert sess["oauth_token"]["access_token"] == "header-token"


def test_bootstrap_unsafe_next_redirects_to_root():
    """Een onveilige next (protocol-relatief) redirect naar de app-root."""
    app = _make_app(enable_bootstrap=True)
    client = app.test_client()

    with patch("flask_rpr_oauth.auth.requests.get", return_value=_userinfo_response()):
        resp = client.get(
            "/auth/session-bootstrap?access_token=at-123&next=//evil.example.com"
        )

    assert resp.status_code == 303
    location = resp.headers["Location"]
    assert location.endswith("/") and "evil.example.com" not in location


def test_bootstrap_blocks_review_status():
    """Een REVIEW-gebruiker wordt geweigerd en doorgestuurd naar login."""
    app = _make_app(enable_bootstrap=True)
    client = app.test_client()

    with patch(
        "flask_rpr_oauth.auth.requests.get",
        return_value=_userinfo_response(user_status="REVIEW"),
    ):
        resp = client.get("/auth/session-bootstrap?access_token=at-123&next=/dashboard")

    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/auth/login")
    with client.session_transaction() as sess:
        assert "oauth_user" not in sess
        assert "oauth_blocked_message" in sess


def test_bootstrap_blocks_banned_status():
    """Een BANNED-gebruiker wordt geweigerd en doorgestuurd naar login."""
    app = _make_app(enable_bootstrap=True)
    client = app.test_client()

    with patch(
        "flask_rpr_oauth.auth.requests.get",
        return_value=_userinfo_response(user_status="BANNED"),
    ):
        resp = client.get("/auth/session-bootstrap?access_token=at-123")

    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/auth/login")
    with client.session_transaction() as sess:
        assert "oauth_user" not in sess
        assert "oauth_blocked_message" in sess


def test_bootstrap_userinfo_failure_redirects_to_login():
    """Een fout/non-200 bij userinfo leidt tot een redirect naar login (geen 500)."""
    app = _make_app(enable_bootstrap=True)
    client = app.test_client()

    failing = MagicMock()
    failing.raise_for_status.side_effect = Exception("401 Unauthorized")

    with patch("flask_rpr_oauth.auth.requests.get", return_value=failing):
        resp = client.get("/auth/session-bootstrap?access_token=bad-token")

    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/auth/login")
    with client.session_transaction() as sess:
        assert "oauth_user" not in sess


def test_fivem_bootstrap_alias_routes_to_same_handler():
    """De deprecated /auth/fivem-bootstrap alias werkt nog en deelt de handler."""
    app = _make_app(enable_bootstrap=True)
    client = app.test_client()

    with patch("flask_rpr_oauth.auth.requests.get", return_value=_userinfo_response()):
        resp = client.get("/auth/fivem-bootstrap?access_token=at-123&next=/dashboard")

    assert resp.status_code == 303
    assert resp.headers["Location"].endswith("/dashboard")
    with client.session_transaction() as sess:
        assert sess["oauth_user"]["oauth_id"] == "user-123"


def test_legacy_flag_enables_route():
    """De oude OAUTH_ENABLE_FIVEM_BOOTSTRAP vlag activeert de route nog steeds."""
    app = _make_app(enable_bootstrap=False, legacy_flag=True)
    client = app.test_client()

    with patch("flask_rpr_oauth.auth.requests.get", return_value=_userinfo_response()):
        resp = client.get("/auth/session-bootstrap?access_token=at-123")

    assert resp.status_code == 303


# ── §6 laag-2: embedded step-up signaal ──────────────────────────────────────


def test_bootstrap_marks_session_embedded():
    """Een geslaagde session-bootstrap markeert de sessie als embedded (FiveM-iframe)."""
    app = _make_app(enable_bootstrap=True)
    client = app.test_client()

    with patch("flask_rpr_oauth.auth.requests.get", return_value=_userinfo_response()):
        client.get("/auth/session-bootstrap?access_token=at-123")

    with client.session_transaction() as sess:
        assert sess.get("rpr_embedded") is True


def test_require_2fa_reauth_embedded_signals_host_nui():
    """In een embedded sessie geeft require_2fa_reauth een postMessage-signaalpagina
    terug (geen in-CEF redirect naar de auth-server)."""
    app = _make_app(enable_bootstrap=True)
    rpr = app.extensions["rpr_auth"]

    with app.test_request_context("/protected"):
        from flask import session

        session["rpr_embedded"] = True
        resp = rpr.require_2fa_reauth()
        body = resp.get_data(as_text=True)

    assert resp.status_code == 200
    assert "rpr_auth_required" in body
    assert "step_up" in body
