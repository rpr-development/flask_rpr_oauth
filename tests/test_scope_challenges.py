"""
Tests voor RFC 6750 §3 scope-challenges en de require_scope-decorator.

Dekt: de ``scope``-hint op 401/403 ``WWW-Authenticate``-challenges, het RFC 6750 §3.1
onderscheid tussen "geen token" (geen ``error``-attribuut) en "ongeldig token"
(``error="invalid_token"``), ``error="insufficient_scope"`` op de Bearer-403-paden van
``permission_required``/``group_required``, en de nieuwe ``require_scope``-decorator.
"""

import time
from unittest.mock import patch

import pytest
from flask import Flask, jsonify

from flask_rpr_oauth import (
    RPRAuth,
    login_required,
    permission_required,
    group_required,
    require_scope,
)


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

    @app.route("/perm")
    @permission_required("gms.admin")
    def perm():
        return jsonify({"ok": True})

    @app.route("/group")
    @group_required("staff")
    def group():
        return jsonify({"ok": True})

    @app.route("/mcp/deploy")
    @require_scope("gms.deploy", "gms.write")
    def deploy():
        return jsonify({"ok": True})

    return app


class TestChallengeScopeAttribute:
    """RFC 6750 §3 — de `scope`-hint op 401 WWW-Authenticate-challenges."""

    def test_default_scope_derived_from_oauth_scope(self):
        app = _make_app()  # geen OAUTH_RESOURCE_REQUIRED_SCOPES/_SUPPORTED
        with (
            patch("flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True),
            patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="tok"),
            patch("flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=None),
        ):
            resp = app.test_client().get("/protected")
        challenge = resp.headers["WWW-Authenticate"]
        assert 'scope="openid profile email"' in challenge

    def test_explicit_required_scopes_config_string(self):
        app = _make_app(OAUTH_RESOURCE_REQUIRED_SCOPES="gms.read gms.write")
        with (
            patch("flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True),
            patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="tok"),
            patch("flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=None),
        ):
            resp = app.test_client().get("/protected")
        challenge = resp.headers["WWW-Authenticate"]
        assert 'scope="gms.read gms.write"' in challenge

    def test_explicit_required_scopes_config_list(self):
        app = _make_app(OAUTH_RESOURCE_REQUIRED_SCOPES=["gms.read", "gms.write"])
        with (
            patch("flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True),
            patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="tok"),
            patch("flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=None),
        ):
            resp = app.test_client().get("/protected")
        challenge = resp.headers["WWW-Authenticate"]
        assert 'scope="gms.read gms.write"' in challenge

    def test_empty_required_scopes_omits_scope_attribute(self):
        app = _make_app(OAUTH_RESOURCE_REQUIRED_SCOPES=[])
        with (
            patch("flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True),
            patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="tok"),
            patch("flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=None),
        ):
            resp = app.test_client().get("/protected")
        challenge = resp.headers["WWW-Authenticate"]
        assert "scope=" not in challenge

    def test_offline_access_filtered_from_default_scope(self):
        app = _make_app(OAUTH_RESOURCE_SCOPES_SUPPORTED=["openid", "offline_access"])
        with (
            patch("flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True),
            patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="tok"),
            patch("flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=None),
        ):
            resp = app.test_client().get("/protected")
        challenge = resp.headers["WWW-Authenticate"]
        assert "offline_access" not in challenge
        assert 'scope="openid"' in challenge

    def test_no_token_omits_error_attribute(self):
        """RFC 6750 §3.1: draagt de request geen token, dan geen `error`-attribuut."""
        app = _make_app()
        with (
            patch("flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True),
            patch("flask_rpr_oauth.decorators._get_bearer_token", return_value=""),
            patch("flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=None),
        ):
            resp = app.test_client().get("/protected")
        challenge = resp.headers["WWW-Authenticate"]
        assert "error=" not in challenge
        assert "resource_metadata=" in challenge

    def test_invalid_token_has_error_attribute(self):
        """RFC 6750 §3.1: een aangeboden (maar ongeldig) token krijgt wel `error="invalid_token"`."""
        app = _make_app()
        with (
            patch("flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True),
            patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="tok"),
            patch("flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=None),
        ):
            resp = app.test_client().get("/protected")
        challenge = resp.headers["WWW-Authenticate"]
        assert 'error="invalid_token"' in challenge


class TestBearerForbiddenInsufficientScope:
    """RFC 6750 §3.1 — `error="insufficient_scope"` op de Bearer-403-paden."""

    def test_permission_required_403_has_insufficient_scope_header(self):
        app = _make_app()
        userinfo = {"sub": "1", "token_type": "user", "permissions": []}
        with (
            patch("flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True),
            patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="tok"),
            patch("flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo),
        ):
            resp = app.test_client().get("/perm")
        assert resp.status_code == 403
        # JSON-body blijft exact zoals voorheen.
        body = resp.get_json()
        assert body["message"] == "gms.admin permission required"
        assert body["your_permissions"] == []
        challenge = resp.headers["WWW-Authenticate"]
        assert 'error="insufficient_scope"' in challenge
        assert "resource_metadata=" in challenge

    def test_group_required_m2m_403_has_insufficient_scope_header(self):
        app = _make_app()
        userinfo = {"sub": "1", "token_type": "m2m", "permissions": [], "groups": []}
        with (
            patch("flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True),
            patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="tok"),
            patch("flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo),
        ):
            resp = app.test_client().get("/group")
        assert resp.status_code == 403
        assert "M2M tokens cannot be checked" in resp.get_json()["message"]
        assert 'error="insufficient_scope"' in resp.headers["WWW-Authenticate"]

    def test_group_required_missing_group_403_has_insufficient_scope_header(self):
        app = _make_app()
        userinfo = {"sub": "1", "token_type": "user", "groups": ["other"]}
        with (
            patch("flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True),
            patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="tok"),
            patch("flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo),
        ):
            resp = app.test_client().get("/group")
        assert resp.status_code == 403
        assert resp.get_json()["message"] == "staff group membership required"
        assert 'error="insufficient_scope"' in resp.headers["WWW-Authenticate"]


class TestRequireScope:
    """`require_scope(*scopes)` — OAuth-scope-check, los van RPR-permissies."""

    def test_bearer_with_all_scopes_allowed(self):
        app = _make_app()
        userinfo = {"sub": "1", "token_type": "user", "permissions": [], "groups": []}
        with (
            patch("flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True),
            patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="tok"),
            patch("flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo),
            patch(
                "flask_rpr_oauth.helpers.get_token_scopes",
                return_value={"gms.deploy", "gms.write", "openid"},
            ),
        ):
            resp = app.test_client().get("/mcp/deploy")
        assert resp.status_code == 200

    def test_bearer_missing_scope_returns_insufficient_scope(self):
        app = _make_app()
        userinfo = {"sub": "1", "token_type": "user", "permissions": [], "groups": []}
        with (
            patch("flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True),
            patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="tok"),
            patch("flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo),
            patch("flask_rpr_oauth.helpers.get_token_scopes", return_value={"gms.deploy"}),
        ):
            resp = app.test_client().get("/mcp/deploy")
        assert resp.status_code == 403
        body = resp.get_json()
        assert "gms.write" in body["message"]
        assert body["your_scopes"] == ["gms.deploy"]
        challenge = resp.headers["WWW-Authenticate"]
        assert 'error="insufficient_scope"' in challenge
        # Precies de scopes die deze route vereist, niet de resource-brede default.
        assert 'scope="gms.deploy gms.write"' in challenge

    def test_bearer_invalid_token_returns_401(self):
        app = _make_app()
        with (
            patch("flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True),
            patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="tok"),
            patch("flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=None),
        ):
            resp = app.test_client().get("/mcp/deploy")
        assert resp.status_code == 401

    def test_session_with_scope_allowed(self):
        app = _make_app()
        client = app.test_client()
        with client.session_transaction() as sess:
            sess["oauth_token"] = {"access_token": "tok", "scope": "gms.deploy gms.write openid"}
            sess["oauth_user"] = {"oauth_id": "1", "user_status": "ACTIVE"}
            sess["_login_at"] = time.time()
            sess["_token_validated_at"] = time.time()

        resp = client.get("/mcp/deploy")
        assert resp.status_code == 200

    def test_session_missing_scope_returns_403(self):
        app = _make_app()
        client = app.test_client()
        with client.session_transaction() as sess:
            sess["oauth_token"] = {"access_token": "tok", "scope": "gms.deploy"}
            sess["oauth_user"] = {"oauth_id": "1", "user_status": "ACTIVE"}
            sess["_login_at"] = time.time()
            sess["_token_validated_at"] = time.time()

        resp = client.get("/mcp/deploy")
        assert resp.status_code == 403
