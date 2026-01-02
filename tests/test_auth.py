"""
Tests voor Flask RPR OAuth
"""

import pytest
from flask import Flask
from flask_rpr_oauth import RPRAuth, OAuthUser


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

    return app


@pytest.fixture
def auth(app):
    """Create RPRAuth instance."""
    return RPRAuth(app)


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


def test_oauth_user_creation():
    """Test OAuthUser creation."""
    user = OAuthUser(
        oauth_id="test-123",
        email="test@example.com",
        voornaam="Test",
        achternaam="User",
        permissions=["test.read", "test.write"],
        groups=["users", "testers"],
    )

    assert user.oauth_id == "test-123"
    assert user.email == "test@example.com"
    assert user.voornaam == "Test"
    assert user.achternaam == "User"
    assert user.get_id() == "test-123"


def test_oauth_user_with_profile_claims():
    """Test OAuthUser creation with profile claims."""
    user = OAuthUser(
        oauth_id="test-123",
        email="test@example.com",
        voornaam="Test",
        achternaam="User",
        teamspeak_id="ts3_user_123",
        discord_id="discord_456",
        ingame_phone="555-1234",
        fivem_role="admin",
        permissions=["test.read"],
        groups=["users"],
    )

    assert user.teamspeak_id == "ts3_user_123"
    assert user.discord_id == "discord_456"
    assert user.ingame_phone == "555-1234"
    assert user.fivem_role == "admin"


def test_user_permissions():
    """Test user permission checks."""
    user = OAuthUser(
        oauth_id="test-123", email="test@example.com", permissions=["read", "write", "delete"]
    )

    assert user.has_permission("read")
    assert user.has_permission("write")
    assert user.has_permission("delete")
    assert not user.has_permission("admin")

    assert user.has_any_permission("read", "admin")
    assert user.has_any_permission("write", "create")
    assert not user.has_any_permission("admin", "create")


def test_user_groups():
    """Test user group checks."""
    user = OAuthUser(oauth_id="test-123", email="test@example.com", groups=["users", "moderators"])

    assert user.in_group("users")
    assert user.in_group("moderators")
    assert not user.in_group("admins")

    assert user.in_any_group("users", "admins")
    assert user.in_any_group("moderators", "staff")
    assert not user.in_any_group("admins", "staff")


def test_rpr_auth_initialization(app):
    """Test RPRAuth initialization."""
    auth = RPRAuth(app)

    assert auth.oauth is not None
    assert auth.auth_server is not None
    assert "rpr_auth" in app.extensions


def test_auth_routes_registered(app, auth):
    """Test that auth routes are registered."""
    # Just verify the app has the auth blueprint registered
    assert "auth" in app.blueprints


def test_missing_config():
    """Test that missing config raises error."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test"

    with pytest.raises(ValueError):
        RPRAuth(app)


def test_user_repr():
    """Test user string representation."""
    user = OAuthUser(oauth_id="test-123", email="test@example.com")

    assert repr(user) == "<OAuthUser test@example.com>"
