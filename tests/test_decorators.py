"""
Tests voor method-specifieke decorator functionaliteit.
"""

import pytest
from unittest.mock import patch, MagicMock
from flask import Flask, jsonify
from flask_rpr_oauth import RPRAuth
from flask_rpr_oauth.decorators import (
    permission_required,
    any_permission_required,
    group_required,
    any_group_required,
)


@pytest.fixture
def app():
    """Create test Flask app."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret"
    app.config["OAUTH_BASE_URL"] = "https://auth.test.nl"
    app.config["OAUTH_CLIENT_ID"] = "test-client"
    app.config["OAUTH_CLIENT_SECRET"] = "test-secret"
    app.config["OAUTH_REDIRECT_URI"] = "http://localhost/callback"
    app.config["TESTING"] = True

    RPRAuth(app)

    # Register test routes with method-specific permissions
    @app.route("/melding", methods=["GET", "POST", "DELETE"])
    @permission_required(GET="melding.view", POST="melding.edit", DELETE="melding.delete")
    def melding_endpoint(userinfo=None):
        return jsonify({"status": "ok", "method": "melding"})

    @app.route("/legacy", methods=["GET", "POST"])
    @permission_required("admin.access")
    def legacy_endpoint(userinfo=None):
        return jsonify({"status": "ok", "method": "legacy"})

    @app.route("/any-perm", methods=["GET", "POST"])
    @any_permission_required(GET="view1,view2", POST="edit1,edit2")
    def any_perm_endpoint(userinfo=None):
        return jsonify({"status": "ok", "method": "any-perm"})

    @app.route("/groups", methods=["GET", "POST"])
    @group_required(GET="viewers", POST="editors")
    def groups_endpoint(userinfo=None):
        return jsonify({"status": "ok", "method": "groups"})

    @app.route("/any-groups", methods=["GET", "POST"])
    @any_group_required(GET="viewers,guests", POST="editors,admins")
    def any_groups_endpoint(userinfo=None):
        return jsonify({"status": "ok", "method": "any-groups"})

    @app.route("/partial", methods=["GET", "POST", "PUT"])
    @permission_required(GET="read", POST="write")
    def partial_endpoint(userinfo=None):
        return jsonify({"status": "ok", "method": "partial"})

    return app


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


class TestPermissionRequiredMethodSpecific:
    """Tests for permission_required with method-specific permissions."""

    def test_get_with_correct_permission(self, client):
        """Test GET request with correct permission."""
        userinfo = {"sub": "user1", "permissions": ["melding.view"], "token_type": "user"}

        with patch(
            "flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True
        ), patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="token"), patch(
            "flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo
        ):
            response = client.get("/melding")
            assert response.status_code == 200

    def test_post_with_correct_permission(self, client):
        """Test POST request with correct permission."""
        userinfo = {"sub": "user1", "permissions": ["melding.edit"], "token_type": "user"}

        with patch(
            "flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True
        ), patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="token"), patch(
            "flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo
        ):
            response = client.post("/melding")
            assert response.status_code == 200

    def test_get_with_wrong_permission(self, client):
        """Test GET request with wrong permission returns 403."""
        userinfo = {"sub": "user1", "permissions": ["melding.edit"], "token_type": "user"}

        with patch(
            "flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True
        ), patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="token"), patch(
            "flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo
        ):
            response = client.get("/melding")
            assert response.status_code == 403

    def test_post_with_wrong_permission(self, client):
        """Test POST request with wrong permission returns 403."""
        userinfo = {"sub": "user1", "permissions": ["melding.view"], "token_type": "user"}

        with patch(
            "flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True
        ), patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="token"), patch(
            "flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo
        ):
            response = client.post("/melding")
            assert response.status_code == 403

    def test_method_not_specified_allows_access(self, client):
        """Test that methods without specified permissions allow access."""
        userinfo = {"sub": "user1", "permissions": [], "token_type": "user"}

        with patch(
            "flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True
        ), patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="token"), patch(
            "flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo
        ):
            response = client.put("/partial")
            assert response.status_code == 200


class TestPermissionRequiredLegacy:
    """Tests for legacy permission_required usage (single permission)."""

    def test_legacy_single_permission_get(self, client):
        """Test legacy single permission works for GET."""
        userinfo = {"sub": "user1", "permissions": ["admin.access"], "token_type": "user"}

        with patch(
            "flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True
        ), patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="token"), patch(
            "flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo
        ):
            response = client.get("/legacy")
            assert response.status_code == 200

    def test_legacy_single_permission_post(self, client):
        """Test legacy single permission works for POST."""
        userinfo = {"sub": "user1", "permissions": ["admin.access"], "token_type": "user"}

        with patch(
            "flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True
        ), patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="token"), patch(
            "flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo
        ):
            response = client.post("/legacy")
            assert response.status_code == 200


class TestAnyPermissionRequiredMethodSpecific:
    """Tests for any_permission_required with method-specific permissions."""

    def test_get_with_one_of_required_permissions(self, client):
        """Test GET with one of the required permissions."""
        userinfo = {"sub": "user1", "permissions": ["view1"], "token_type": "user"}

        with patch(
            "flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True
        ), patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="token"), patch(
            "flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo
        ):
            response = client.get("/any-perm")
            assert response.status_code == 200

    def test_post_with_one_of_required_permissions(self, client):
        """Test POST with one of the required permissions."""
        userinfo = {"sub": "user1", "permissions": ["edit2"], "token_type": "user"}

        with patch(
            "flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True
        ), patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="token"), patch(
            "flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo
        ):
            response = client.post("/any-perm")
            assert response.status_code == 200

    def test_get_without_any_required_permissions(self, client):
        """Test GET without any of the required permissions returns 403."""
        userinfo = {"sub": "user1", "permissions": ["edit1"], "token_type": "user"}

        with patch(
            "flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True
        ), patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="token"), patch(
            "flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo
        ):
            response = client.get("/any-perm")
            assert response.status_code == 403


class TestGroupRequiredMethodSpecific:
    """Tests for group_required with method-specific groups."""

    def test_get_with_correct_group(self, client):
        """Test GET request with correct group."""
        userinfo = {"sub": "user1", "groups": ["viewers"], "token_type": "user"}

        with patch(
            "flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True
        ), patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="token"), patch(
            "flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo
        ):
            response = client.get("/groups")
            assert response.status_code == 200

    def test_post_with_correct_group(self, client):
        """Test POST request with correct group."""
        userinfo = {"sub": "user1", "groups": ["editors"], "token_type": "user"}

        with patch(
            "flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True
        ), patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="token"), patch(
            "flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo
        ):
            response = client.post("/groups")
            assert response.status_code == 200

    def test_get_with_wrong_group(self, client):
        """Test GET with wrong group returns 403."""
        userinfo = {"sub": "user1", "groups": ["editors"], "token_type": "user"}

        with patch(
            "flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True
        ), patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="token"), patch(
            "flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo
        ):
            response = client.get("/groups")
            assert response.status_code == 403


class TestAnyGroupRequiredMethodSpecific:
    """Tests for any_group_required with method-specific groups."""

    def test_get_with_one_of_required_groups(self, client):
        """Test GET with one of the required groups."""
        userinfo = {"sub": "user1", "groups": ["guests"], "token_type": "user"}

        with patch(
            "flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True
        ), patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="token"), patch(
            "flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo
        ):
            response = client.get("/any-groups")
            assert response.status_code == 200

    def test_post_with_one_of_required_groups(self, client):
        """Test POST with one of the required groups."""
        userinfo = {"sub": "user1", "groups": ["admins"], "token_type": "user"}

        with patch(
            "flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True
        ), patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="token"), patch(
            "flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo
        ):
            response = client.post("/any-groups")
            assert response.status_code == 200

    def test_get_without_any_required_groups(self, client):
        """Test GET without any of the required groups returns 403."""
        userinfo = {"sub": "user1", "groups": ["editors"], "token_type": "user"}

        with patch(
            "flask_rpr_oauth.decorators._is_bearer_token_request", return_value=True
        ), patch("flask_rpr_oauth.decorators._get_bearer_token", return_value="token"), patch(
            "flask_rpr_oauth.decorators._get_userinfo_from_token", return_value=userinfo
        ):
            response = client.get("/any-groups")
            assert response.status_code == 403
