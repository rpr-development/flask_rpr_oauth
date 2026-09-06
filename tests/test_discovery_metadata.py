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

    def test_metadata_filters_offline_access(self):
        """offline_access is een refresh-scope, geen scope om voor deze resource te vragen."""
        app = _make_app(OAUTH_RESOURCE_SCOPES_SUPPORTED=["openid", "offline_access"])
        resp = app.test_client().get("/.well-known/oauth-protected-resource")
        assert resp.get_json()["scopes_supported"] == ["openid"]

    def test_metadata_resource_name_defaults_to_app_name(self):
        app = _make_app()
        resp = app.test_client().get("/.well-known/oauth-protected-resource")
        assert resp.get_json()["resource_name"] == app.name

    def test_metadata_resource_name_configurable(self):
        app = _make_app(OAUTH_RESOURCE_NAME="RPR GMS")
        resp = app.test_client().get("/.well-known/oauth-protected-resource")
        assert resp.get_json()["resource_name"] == "RPR GMS"

    def test_metadata_resource_documentation_only_when_set(self):
        app = _make_app()
        data = app.test_client().get("/.well-known/oauth-protected-resource").get_json()
        assert "resource_documentation" not in data

        app_with_docs = _make_app(OAUTH_RESOURCE_DOCUMENTATION="https://docs.example/gms")
        data = app_with_docs.test_client().get("/.well-known/oauth-protected-resource").get_json()
        assert data["resource_documentation"] == "https://docs.example/gms"

    def test_metadata_dpop_fields(self):
        app = _make_app(OAUTH_REQUIRE_DPOP=True)
        data = app.test_client().get("/.well-known/oauth-protected-resource").get_json()
        assert data["dpop_bound_access_tokens_required"] is True
        assert "ES256" in data["dpop_signing_alg_values_supported"]

    def test_metadata_dpop_fields_default_false(self):
        app = _make_app()
        data = app.test_client().get("/.well-known/oauth-protected-resource").get_json()
        assert data["dpop_bound_access_tokens_required"] is False
        assert "ES256" in data["dpop_signing_alg_values_supported"]

    def test_metadata_path_suffix_route_registered(self):
        """RFC 9728 §3.1: OAUTH_RESOURCE_ID met een pad registreert ook de pad-suffix-variant."""
        app = _make_app(OAUTH_RESOURCE_ID="https://gms.roleplayreality.nl/mcp")
        client = app.test_client()
        resp_root = client.get("/.well-known/oauth-protected-resource")
        resp_path = client.get("/.well-known/oauth-protected-resource/mcp")
        assert resp_root.status_code == 200
        assert resp_path.status_code == 200
        assert resp_root.get_json() == resp_path.get_json()

    def test_metadata_no_path_suffix_route_without_path(self):
        app = _make_app(OAUTH_RESOURCE_ID="https://gms.roleplayreality.nl")
        resp = app.test_client().get("/.well-known/oauth-protected-resource/mcp")
        assert resp.status_code == 404


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

    def test_bearer_401_points_to_path_suffix_metadata_url(self):
        """RFC 9728 §3.1: heeft OAUTH_RESOURCE_ID een pad, dan wijst de challenge daarnaar."""
        app = _make_app(OAUTH_RESOURCE_ID="https://gms.roleplayreality.nl/mcp")
        with (
            patch("flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True),
            patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="tok"),
            patch("flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=None),
        ):
            resp = app.test_client().get("/protected")
        challenge = resp.headers.get("WWW-Authenticate", "")
        assert (
            'resource_metadata="https://gms.roleplayreality.nl/.well-known/oauth-protected-resource/mcp"'
            in challenge
        )
