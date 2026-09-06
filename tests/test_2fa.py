"""
Tests voor 2FA functionaliteit in Flask RPR OAuth
"""

import time

import pytest
from flask import Flask, session
from flask_rpr_oauth import RPRAuth, require_2fa, current_user, current_token
from unittest.mock import Mock, patch


@pytest.fixture
def app():
    """Create test Flask app."""
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY="test-secret-key",
        OAUTH_BASE_URL="https://auth.test.nl",
        OAUTH_CLIENT_ID="test-client",
        OAUTH_CLIENT_SECRET="test-secret",
        OAUTH_REDIRECT_URI="http://localhost/callback",
        TESTING=True,
    )

    # Initialiseer auth
    auth = RPRAuth(app)

    # Test endpoint met 2FA — werkt voor sessie én Bearer token
    @app.route("/sensitive")
    @require_2fa
    def sensitive():
        if current_token:
            return {"message": "success", "user": current_token.get("sub", "api-user")}
        return {"message": "success", "user": current_user.email}

    # RFC 9470 max_age: recente authenticatie vereist, niet alleen acr.
    @app.route("/max-age")
    @require_2fa(max_age=300)
    def max_age_route():
        if current_token:
            return {"message": "success", "user": current_token.get("sub", "api-user")}
        return {"message": "success", "user": current_user.email}

    @app.route("/test-session")
    def test_session():
        """Helper endpoint om session te testen."""
        return {
            "authenticated": current_user.is_authenticated,
            "twofa": current_user.twofa_validated if current_user.is_authenticated else False,
        }

    # _handle_callback redirect't hierheen na een succesvolle login (geen 'next' in sessie).
    @app.route("/")
    def index():
        return "home"

    return app


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def auth_session(client):
    """Create authenticated session."""
    with client.session_transaction() as sess:
        sess["oauth_token"] = {
            "access_token": "test-token",
            "refresh_token": "test-refresh",
            "token_type": "bearer",
        }
        sess["oauth_user"] = {
            "oauth_id": "test-123",
            "email": "test@example.com",
            "voornaam": "Test",
            "achternaam": "User",
        }
        sess["oauth_permissions"] = ["read", "write"]
        sess["oauth_groups"] = ["users"]
        sess["twofa_validated"] = False
        # Vers gevalideerd token: voorkomt dat de periodieke _validate_session_token-hook
        # de auth server (netwerk) belt en de sessie wist tijdens deze 2FA-tests.
        sess["_login_at"] = time.time()
        sess["_token_validated_at"] = time.time()
    return client


@pytest.fixture
def auth_session_with_2fa(client):
    """Create authenticated session with 2FA."""
    with client.session_transaction() as sess:
        sess["oauth_token"] = {
            "access_token": "test-token",
            "refresh_token": "test-refresh",
            "token_type": "bearer",
        }
        sess["oauth_user"] = {
            "oauth_id": "test-123",
            "email": "test@example.com",
            "voornaam": "Test",
            "achternaam": "User",
        }
        sess["oauth_permissions"] = ["read", "write"]
        sess["oauth_groups"] = ["users"]
        sess["twofa_validated"] = True
        # Vers gevalideerd token: voorkomt dat de periodieke _validate_session_token-hook
        # de auth server (netwerk) belt en de sessie wist tijdens deze 2FA-tests.
        sess["_login_at"] = time.time()
        sess["_token_validated_at"] = time.time()
    return client


def test_2fa_property_without_auth(client):
    """Test 2FA property zonder authenticatie."""
    response = client.get("/test-session")
    data = response.get_json()

    assert data["authenticated"] is False
    assert data["twofa"] is False


def test_2fa_property_without_2fa(auth_session):
    """Test 2FA property met auth maar zonder 2FA."""
    response = auth_session.get("/test-session")
    data = response.get_json()

    assert data["authenticated"] is True
    assert data["twofa"] is False


def test_2fa_property_with_2fa(auth_session_with_2fa):
    """Test 2FA property met auth en 2FA."""
    response = auth_session_with_2fa.get("/test-session")
    data = response.get_json()

    assert data["authenticated"] is True
    assert data["twofa"] is True


def test_require_2fa_decorator_without_auth(client):
    """Test @require_2fa zonder authenticatie."""
    response = client.get("/sensitive", follow_redirects=False)

    # Moet redirecten naar login
    assert response.status_code == 302
    assert "/auth/login" in response.location


def test_require_2fa_decorator_without_2fa(auth_session):
    """Test @require_2fa met auth maar zonder 2FA."""
    with patch("flask_rpr_oauth.auth.RPRAuth.validate_2fa") as mock_validate:
        with patch("flask_rpr_oauth.auth.RPRAuth.require_2fa_reauth") as mock_reauth:
            from flask import redirect

            mock_validate.return_value = False
            # Mock de OAuth redirect
            mock_reauth.return_value = redirect(
                "https://auth.test.nl/oauth/authorize?acr_values=mfa"
            )

            response = auth_session.get("/sensitive", follow_redirects=False)

            # Moet redirecten naar OAuth met 2FA
            assert response.status_code == 302
            assert "acr_values=mfa" in response.location
            mock_validate.assert_called_once()
            mock_reauth.assert_called_once()


def test_require_2fa_decorator_with_2fa(auth_session_with_2fa):
    """Test @require_2fa met auth en 2FA."""
    response = auth_session_with_2fa.get("/sensitive")

    # Moet toegang geven
    assert response.status_code == 200
    data = response.get_json()
    assert data["message"] == "success"
    assert data["user"] == "test@example.com"


@patch("flask_rpr_oauth.auth.requests.get")
def test_validate_2fa_success(mock_get, app, auth_session):
    """Test validate_2fa met succesvolle validatie."""
    # Mock response - userinfo endpoint moet acr of twofa_validated returnen
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "sub": "test-123",
        "email": "test@example.com",
        "acr": "mfa",  # OAuth standaard voor 2FA
        "twofa_validated": True,
    }
    mock_get.return_value = mock_response

    with app.test_request_context():
        # Valideer 2FA
        rpr_auth = app.extensions["rpr_auth"]

        # Setup session with oauth_token
        session["oauth_token"] = {
            "access_token": "test-token",
            "token_type": "bearer",
        }
        session["twofa_validated"] = False

        result = rpr_auth.validate_2fa()

        assert result is True
        assert session.get("twofa_validated") is True


@patch("flask_rpr_oauth.auth.requests.get")
def test_validate_2fa_failure(mock_get, app, auth_session):
    """Test validate_2fa met gefaalde validatie."""
    # Mock response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"isValid": True, "twofaValidated": False}
    mock_get.return_value = mock_response

    with app.test_request_context():
        rpr_auth = app.extensions["rpr_auth"]

        # Setup session with oauth_token
        session["oauth_token"] = {
            "access_token": "test-token",
            "token_type": "bearer",
        }
        session["twofa_validated"] = False

        result = rpr_auth.validate_2fa()

        assert result is False
        assert session.get("twofa_validated") is False


@patch("flask_rpr_oauth.helpers.get_userinfo_from_token")
def test_require_2fa_bearer_mfa(mock_userinfo, client):
    """Bearer user token met acr=mfa geeft toegang."""
    mock_userinfo.return_value = {
        "sub": "42",
        "token_type": "user",
        "acr": "mfa",
        "email": "test@example.com",
        "permissions": [],
    }
    response = client.get("/sensitive", headers={"Authorization": "Bearer some-token"})
    assert response.status_code == 200
    assert response.get_json()["message"] == "success"


@patch("flask_rpr_oauth.helpers.get_userinfo_from_token")
def test_require_2fa_bearer_phr(mock_userinfo, client):
    """Bearer user token met acr=phr (passkey) geeft toegang."""
    mock_userinfo.return_value = {
        "sub": "42",
        "token_type": "user",
        "acr": "phr",
        "email": "test@example.com",
        "permissions": [],
    }
    response = client.get("/sensitive", headers={"Authorization": "Bearer some-token"})
    assert response.status_code == 200


@patch("flask_rpr_oauth.helpers.get_userinfo_from_token")
def test_require_2fa_bearer_pwd_blocked(mock_userinfo, client):
    """Bearer user token met acr=pwd (geen 2FA) krijgt een RFC 9470 step-up-challenge (401)."""
    mock_userinfo.return_value = {
        "sub": "42",
        "token_type": "user",
        "acr": "pwd",
        "email": "test@example.com",
        "permissions": [],
    }
    response = client.get("/sensitive", headers={"Authorization": "Bearer some-token"})
    # RFC 9470: geldig token, te laag niveau → 401 met step-up-challenge (niet 403).
    assert response.status_code == 401
    assert response.get_json()["error"] == "mfa_required"  # body ongewijzigd (backwards-compatibel)
    challenge = response.headers["WWW-Authenticate"]
    assert 'error="insufficient_user_authentication"' in challenge
    assert 'acr_values="mfa"' in challenge


@patch("flask_rpr_oauth.helpers.get_userinfo_from_token")
def test_require_2fa_bearer_m2m_blocked(mock_userinfo, client):
    """M2M Bearer token krijgt altijd 403 — geen 2FA-concept."""
    mock_userinfo.return_value = {
        "sub": "intranet-client",
        "token_type": "m2m",
        "permissions": ["intranet.read"],
    }
    response = client.get("/sensitive", headers={"Authorization": "Bearer some-m2m-token"})
    assert response.status_code == 403
    assert response.get_json()["error"] == "mfa_required"


@patch("flask_rpr_oauth.helpers.get_userinfo_from_token")
def test_require_2fa_bearer_invalid_token(mock_userinfo, client):
    """Ongeldig Bearer token krijgt 401."""
    mock_userinfo.return_value = None
    response = client.get("/sensitive", headers={"Authorization": "Bearer invalid-token"})
    assert response.status_code == 401


def test_callback_saves_2fa_status(app, client):
    """Test of OAuth callback de 2FA status opslaat.

    Vervangt `rpr_auth.auth_server` (i.p.v. de hele `OAuth`-klasse of een tweede
    `RPRAuth(app)` te mocken/re-initen — dat laatste botst met Flask's
    add_url_rule, dat dezelfde endpointnamen niet twee keer accepteert) door een
    kale Mock. `_handle_callback` roept alleen `authorize_access_token()` en
    `userinfo()` aan op dat object, dus dat volstaat.
    """
    rpr_auth = app.extensions["rpr_auth"]
    rpr_auth.auth_server = Mock(
        authorize_access_token=Mock(
            return_value={
                "access_token": "test-token",
                "refresh_token": "test-refresh",
                "token_type": "bearer",
                "twofa_validated": True,
            }
        ),
        userinfo=Mock(
            return_value={
                "sub": "test-123",
                "email": "test@example.com",
                "given_name": "Test",
                "family_name": "User",
                "permissions": ["read"],
                "groups": ["users"],
                "acr": "mfa",
            }
        ),
    )

    client.get("/auth/callback")

    with client.session_transaction() as sess:
        assert sess.get("twofa_validated") is True


def test_callback_saves_auth_time(app, client):
    """_populate_session slaat auth_time (RFC 9470 max_age-check) op uit de userinfo-claims."""
    rpr_auth = app.extensions["rpr_auth"]
    rpr_auth.auth_server = Mock(
        authorize_access_token=Mock(
            return_value={
                "access_token": "test-token",
                "refresh_token": "test-refresh",
                "token_type": "bearer",
            }
        ),
        userinfo=Mock(
            return_value={
                "sub": "test-123",
                "email": "test@example.com",
                "acr": "mfa",
                "auth_time": 1700000000,
            }
        ),
    )

    client.get("/auth/callback")

    with client.session_transaction() as sess:
        assert sess.get("auth_time") == 1700000000


def test_callback_saves_auth_time_missing_as_none(app, client):
    """M2M-achtige of oude auth-server-responses zonder auth_time -> None, niet ontbrekend."""
    rpr_auth = app.extensions["rpr_auth"]
    rpr_auth.auth_server = Mock(
        authorize_access_token=Mock(
            return_value={
                "access_token": "test-token",
                "refresh_token": "test-refresh",
                "token_type": "bearer",
            }
        ),
        userinfo=Mock(return_value={"sub": "test-123", "email": "test@example.com"}),
    )

    client.get("/auth/callback")

    with client.session_transaction() as sess:
        assert sess.get("auth_time") is None


# ------------------------------------------------------------------ RFC 9470 max_age (stap 14)


@patch("flask_rpr_oauth.helpers.get_userinfo_from_token")
def test_require_2fa_max_age_bearer_fresh_allowed(mock_userinfo, client):
    """Bearer user-token met acr=mfa en verse auth_time voldoet aan max_age=300."""
    mock_userinfo.return_value = {
        "sub": "42",
        "token_type": "user",
        "acr": "mfa",
        "auth_time": time.time() - 10,
        "permissions": [],
    }
    response = client.get("/max-age", headers={"Authorization": "Bearer some-token"})
    assert response.status_code == 200


@patch("flask_rpr_oauth.helpers.get_userinfo_from_token")
def test_require_2fa_max_age_bearer_stale_blocked(mock_userinfo, client):
    """auth_time ouder dan max_age -> 401 reauthentication_required, met max_age in header."""
    mock_userinfo.return_value = {
        "sub": "42",
        "token_type": "user",
        "acr": "mfa",
        "auth_time": time.time() - 1000,  # > max_age=300
        "permissions": [],
    }
    response = client.get("/max-age", headers={"Authorization": "Bearer some-token"})
    assert response.status_code == 401
    body = response.get_json()
    assert body["error"] == "reauthentication_required"
    challenge = response.headers["WWW-Authenticate"]
    assert 'error="insufficient_user_authentication"' in challenge
    assert 'max_age="300"' in challenge
    assert "acr_values=" not in challenge  # acr was zelf voldoende


@patch("flask_rpr_oauth.helpers.get_userinfo_from_token")
def test_require_2fa_max_age_bearer_missing_auth_time_blocked(mock_userinfo, client):
    """Geen auth_time-claim (M2M-stijl respons of oude auth-server) telt als te oud."""
    mock_userinfo.return_value = {
        "sub": "42",
        "token_type": "user",
        "acr": "mfa",
        "permissions": [],
    }
    response = client.get("/max-age", headers={"Authorization": "Bearer some-token"})
    assert response.status_code == 401
    assert response.get_json()["error"] == "reauthentication_required"


@patch("flask_rpr_oauth.helpers.get_userinfo_from_token")
def test_require_2fa_max_age_bearer_acr_and_auth_time_both_fail(mock_userinfo, client):
    """Onvoldoende acr én te oude auth_time -> reauthentication_required, met beide attributen
    (het volledig opnieuw inloggen dat max_age afdwingt lost ook de acr-eis op)."""
    mock_userinfo.return_value = {
        "sub": "42",
        "token_type": "user",
        "acr": "pwd",
        "permissions": [],
    }
    response = client.get("/max-age", headers={"Authorization": "Bearer some-token"})
    assert response.status_code == 401
    assert response.get_json()["error"] == "reauthentication_required"
    challenge = response.headers["WWW-Authenticate"]
    assert 'acr_values="mfa"' in challenge
    assert 'max_age="300"' in challenge


@patch("flask_rpr_oauth.helpers.get_userinfo_from_token")
def test_require_2fa_max_age_bearer_m2m_still_403(mock_userinfo, client):
    """M2M blijft 403 ongeacht max_age — geen auth_time-concept voor M2M."""
    mock_userinfo.return_value = {"sub": "worker", "token_type": "m2m"}
    response = client.get("/max-age", headers={"Authorization": "Bearer some-token"})
    assert response.status_code == 403


def test_require_2fa_max_age_session_fresh_allowed(client):
    """Sessie met verse auth_time voldoet, geen reauth nodig."""
    with client.session_transaction() as sess:
        sess["oauth_token"] = {"access_token": "test-token", "token_type": "bearer"}
        sess["oauth_user"] = {"oauth_id": "test-123", "email": "test@example.com"}
        sess["twofa_validated"] = True
        sess["auth_time"] = time.time() - 10
        sess["_login_at"] = time.time()
        sess["_token_validated_at"] = time.time()

    response = client.get("/max-age")
    assert response.status_code == 200


def test_require_2fa_max_age_session_stale_restarts_with_max_age(client):
    """Sessie met verlopen auth_time herstart de OIDC-flow mét max_age (niet enkel acr_values)."""
    with client.session_transaction() as sess:
        sess["oauth_token"] = {"access_token": "test-token", "token_type": "bearer"}
        sess["oauth_user"] = {"oauth_id": "test-123", "email": "test@example.com"}
        sess["twofa_validated"] = True
        sess["auth_time"] = time.time() - 1000
        sess["_login_at"] = time.time()
        sess["_token_validated_at"] = time.time()

    with patch("flask_rpr_oauth.auth.RPRAuth.require_2fa_reauth") as mock_reauth:
        from flask import redirect

        mock_reauth.return_value = redirect("https://auth.test.nl/oauth/authorize?max_age=300")
        response = client.get("/max-age", follow_redirects=False)

    assert response.status_code == 302
    mock_reauth.assert_called_once_with(max_age=300)


def test_require_2fa_max_age_session_missing_auth_time_restarts(client):
    """Sessie zonder auth_time (bijv. vóór deze feature ingelogd) telt als te oud."""
    with client.session_transaction() as sess:
        sess["oauth_token"] = {"access_token": "test-token", "token_type": "bearer"}
        sess["oauth_user"] = {"oauth_id": "test-123", "email": "test@example.com"}
        sess["twofa_validated"] = True
        sess["_login_at"] = time.time()
        sess["_token_validated_at"] = time.time()

    with patch("flask_rpr_oauth.auth.RPRAuth.require_2fa_reauth") as mock_reauth:
        from flask import redirect

        mock_reauth.return_value = redirect("https://auth.test.nl/oauth/authorize?max_age=300")
        response = client.get("/max-age", follow_redirects=False)

    assert response.status_code == 302
    mock_reauth.assert_called_once_with(max_age=300)


def test_callback_saves_2fa_status_false(app, client):
    """Test of OAuth callback de 2FA status opslaat als False (zie vorige test)."""
    rpr_auth = app.extensions["rpr_auth"]
    rpr_auth.auth_server = Mock(
        authorize_access_token=Mock(
            return_value={
                "access_token": "test-token",
                "refresh_token": "test-refresh",
                "token_type": "bearer",
                "twofa_validated": False,
            }
        ),
        userinfo=Mock(
            return_value={
                "sub": "test-123",
                "email": "test@example.com",
                "given_name": "Test",
                "family_name": "User",
            }
        ),
    )

    client.get("/auth/callback")

    with client.session_transaction() as sess:
        assert sess.get("twofa_validated") is False
