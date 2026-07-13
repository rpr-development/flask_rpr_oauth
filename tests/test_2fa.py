"""
Tests voor 2FA functionaliteit in Flask RPR OAuth
"""

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

    @app.route("/test-session")
    def test_session():
        """Helper endpoint om session te testen."""
        return {
            "authenticated": current_user.is_authenticated,
            "twofa": current_user.twofa_validated if current_user.is_authenticated else False,
        }

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
            mock_reauth.return_value = redirect("https://auth.test.nl/oauth/authorize?acr_values=mfa")

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


@pytest.mark.skip(reason="Complex mocking - needs refactor")
def test_callback_saves_2fa_status(app, client):
    """Test of OAuth callback de 2FA status opslaat."""
    with app.app_context():
        with patch("flask_rpr_oauth.auth.OAuth") as mock_oauth:
            # Mock OAuth response met 2FA
            mock_auth_server = Mock()
            mock_auth_server.authorize_access_token.return_value = {
                "access_token": "test-token",
                "refresh_token": "test-refresh",
                "token_type": "bearer",
                "twofa_validated": True,
            }
            mock_auth_server.userinfo.return_value = {
                "sub": "test-123",
                "email": "test@example.com",
                "given_name": "Test",
                "family_name": "User",
                "permissions": ["read"],
                "groups": ["users"],
            }

            # Setup mock
            mock_oauth_instance = Mock()
            mock_oauth_instance.register.return_value = mock_auth_server
            mock_oauth.return_value = mock_oauth_instance

            # Re-init auth met gemockte OAuth
            auth = RPRAuth(app)
            auth.auth_server = mock_auth_server

            # Trigger callback
            response = client.get("/auth/callback")

            # Check session
            with client.session_transaction() as sess:
                assert sess.get("twofa_validated") is True


@pytest.mark.skip(reason="Complex mocking - needs refactor")
def test_callback_saves_2fa_status_false(app, client):
    """Test of OAuth callback de 2FA status opslaat als False."""
    with app.app_context():
        with patch("flask_rpr_oauth.auth.OAuth") as mock_oauth:
            # Mock OAuth response zonder 2FA
            mock_auth_server = Mock()
            mock_auth_server.authorize_access_token.return_value = {
                "access_token": "test-token",
                "refresh_token": "test-refresh",
                "token_type": "bearer",
                "twofa_validated": False,
            }
            mock_auth_server.userinfo.return_value = {
                "sub": "test-123",
                "email": "test@example.com",
                "given_name": "Test",
                "family_name": "User",
            }

            # Setup mock
            mock_oauth_instance = Mock()
            mock_oauth_instance.register.return_value = mock_auth_server
            mock_oauth.return_value = mock_oauth_instance

            # Re-init auth met gemockte OAuth
            auth = RPRAuth(app)
            auth.auth_server = mock_auth_server

            # Trigger callback
            response = client.get("/auth/callback")

            # Check session
            with client.session_transaction() as sess:
                assert sess.get("twofa_validated") is False
