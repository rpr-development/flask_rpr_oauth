"""Tests voor RFC 9728 protected-resource-metadata + RFC 6750 WWW-Authenticate op 401's."""

from unittest.mock import patch
from flask import Flask, jsonify
from flask_rpr_oauth import RPRAuth, login_required


def _make_app(**extra_config):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret"
    app.config["OAUTH_BASE_URL"] = "https://auth.test.nl"
    app.config["OAUTH_CLIENT_ID"] = "test-client"
    app.config["OAUTH_CLIENT_SECRET"] = "test-secret"
    app.config["OAUTH_REDIRECT_URI"] = "http://localhost/callback"
    app.config["TESTING"] = True
    app.config.update(extra_config)
    RPRAuth(app)

    @app.route("/protected")
    @login_required
    def protected():
        return jsonify({"ok": True})

    return app


class TestProtectedResourceMetadata:
    """RFC 9728 §2 — config-gedreven metadata-document."""

    def test_metadata_uses_resource_id_when_configured(self):
        app = _make_app(OAUTH_RESOURCE_ID="https://gms.roleplayreality.nl")
        resp = app.test_client().get("/.well-known/oauth-protected-resource")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["resource"] == "https://gms.roleplayreality.nl"
        assert data["authorization_servers"] == ["https://auth.test.nl"]
        assert data["bearer_methods_supported"] == ["header"]
        assert "openid" in data["scopes_supported"]

    def test_metadata_falls_back_to_request_host(self):
        app = _make_app()  # geen OAUTH_RESOURCE_ID
        resp = app.test_client().get("/.well-known/oauth-protected-resource")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["resource"].startswith("http")
        assert not data["resource"].endswith("/")

    def test_metadata_respects_explicit_scopes(self):
        app = _make_app(OAUTH_RESOURCE_SCOPES_SUPPORTED=["openid", "gms.read"])
        resp = app.test_client().get("/.well-known/oauth-protected-resource")
        assert resp.get_json()["scopes_supported"] == ["openid", "gms.read"]


class TestWwwAuthenticateOn401:
    """RFC 6750 — 401's van bearer-beschermde routes dragen een WWW-Authenticate-challenge."""

    def test_bearer_invalid_token_has_www_authenticate(self):
        app = _make_app(OAUTH_RESOURCE_ID="https://gms.roleplayreality.nl")
        with (
            patch("flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True),
            patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="tok"),
            patch("flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=None),
        ):
            resp = app.test_client().get("/protected")
        assert resp.status_code == 401
        challenge = resp.headers.get("WWW-Authenticate", "")
        assert challenge.startswith("Bearer ")
        assert (
            'resource_metadata="https://gms.roleplayreality.nl/.well-known/oauth-protected-resource"'
            in challenge
        )
        assert 'error="invalid_token"' in challenge
