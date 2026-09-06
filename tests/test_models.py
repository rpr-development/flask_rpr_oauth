"""
Tests voor flask_rpr_oauth.models: OAuthUser-properties en de current_user/
current_token-proxies. Dit dekt properties die eerder ongetest waren maar wel
actief gebruikt worden door consumers (RPR-GMS, RPR-Intranet): `.name` en
`.full_name`.
"""

import pytest
from flask import Flask, g, session

from flask_rpr_oauth.models import OAuthUser, current_user, current_token


@pytest.fixture
def app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret"
    return app


class TestOAuthUserName:
    """`.name` = voornaam + eerste letter achternaam (of alleen voornaam)."""

    def test_name_with_achternaam(self):
        user = OAuthUser(oauth_id="1", email="a@b.nl", voornaam="Jan", achternaam="Jansen")
        assert user.name == "Jan J."

    def test_name_without_achternaam(self):
        user = OAuthUser(oauth_id="1", email="a@b.nl", voornaam="Jan", achternaam="")
        assert user.name == "Jan"


class TestOAuthUserFullName:
    """`.full_name` = voornaam + name_prefix (indien gezet) + achternaam."""

    def test_full_name_without_prefix(self):
        user = OAuthUser(oauth_id="1", email="a@b.nl", voornaam="Jan", achternaam="Jansen")
        assert user.full_name == "Jan Jansen"

    def test_full_name_with_prefix(self):
        user = OAuthUser(
            oauth_id="1", email="a@b.nl", voornaam="Jan", achternaam="Jansen", name_prefix="van"
        )
        assert user.full_name == "Jan van Jansen"

    def test_full_name_only_voornaam(self):
        user = OAuthUser(oauth_id="1", email="a@b.nl", voornaam="Jan")
        assert user.full_name == "Jan"


class TestOAuthUserPermissionsAndGroups:
    def test_get_permissions_returns_list(self):
        user = OAuthUser(oauth_id="1", email="a@b.nl", permissions=["read", "write"])
        assert user.get_permissions() == ["read", "write"]

    def test_get_permissions_defaults_to_empty_list(self):
        user = OAuthUser(oauth_id="1", email="a@b.nl")
        assert user.get_permissions() == []

    def test_get_groups_returns_list(self):
        user = OAuthUser(oauth_id="1", email="a@b.nl", groups=["staff", "mod"])
        assert user.get_groups() == ["staff", "mod"]

    def test_get_groups_defaults_to_empty_list(self):
        user = OAuthUser(oauth_id="1", email="a@b.nl")
        assert user.get_groups() == []


class TestOAuthUserStatusFlags:
    def test_is_anonymous_is_always_false(self):
        user = OAuthUser(oauth_id="1", email="a@b.nl")
        assert user.is_anonymous is False

    def test_is_active_true_for_normal_status(self):
        user = OAuthUser(oauth_id="1", email="a@b.nl", user_status="ACTIVE")
        assert user.is_active is True

    def test_is_active_false_for_review_and_banned(self):
        for status in ("REVIEW", "BANNED"):
            user = OAuthUser(oauth_id="1", email="a@b.nl", user_status=status)
            assert user.is_active is False


class TestCurrentUserProxySession:
    """current_user resolveert uit de Flask-sessie als 'oauth_user' aanwezig is."""

    def test_current_user_from_session(self, app):
        with app.test_request_context("/"):
            session["oauth_user"] = {
                "oauth_id": "user-1",
                "email": "jan@test.nl",
                "voornaam": "Jan",
                "achternaam": "Jansen",
            }
            session["oauth_permissions"] = ["read"]
            session["oauth_groups"] = ["staff"]

            assert current_user.is_authenticated is True
            assert current_user.email == "jan@test.nl"
            assert current_user.full_name == "Jan Jansen"
            assert current_user.get_permissions() == ["read"]
            assert current_user.get_groups() == ["staff"]

    def test_current_user_anonymous_without_session_or_token(self, app):
        with app.test_request_context("/"):
            assert current_user.is_authenticated is False
            assert current_user.is_anonymous is True
            assert current_user.is_active is False
            assert bool(current_user) is False

    def test_current_user_from_bearer_token_fallback(self, app):
        """Zonder sessie, maar met g._rpr_token_info (Bearer-mode), resolveert current_user alsnog."""
        with app.test_request_context("/"):
            g._rpr_token_info = {
                "sub": "api-user-1",
                "email": "api@test.nl",
                "permissions": ["melding.view"],
                "groups": [],
                "token_type": "user",
            }
            assert current_user.is_authenticated is True
            assert current_user.email == "api@test.nl"

    def test_current_user_none_for_m2m_token(self, app):
        """M2M-tokens hebben geen gebruikercontext."""
        with app.test_request_context("/"):
            g._rpr_token_info = {"sub": "client-1", "token_type": "m2m"}
            assert current_user.is_authenticated is False

    def test_current_user_setattr_stores_in_g_not_singleton(self, app):
        """Verrijkte attributen op current_user horen per-request in flask.g te staan,
        niet op de gedeelde singleton (anders lekken ze tussen requests/threads)."""
        with app.test_request_context("/"):
            current_user.extra_field = "some-value"
            assert g._user_extra["extra_field"] == "some-value"
            assert current_user.extra_field == "some-value"


class TestCurrentTokenProxy:
    def test_current_token_get_with_default(self, app):
        with app.test_request_context("/"):
            g._rpr_token_info = {"sub": "api-user-1", "token_type": "m2m"}
            assert current_token.get("sub") == "api-user-1"
            assert current_token.get("missing", "fallback") == "fallback"

    def test_current_token_contains(self, app):
        with app.test_request_context("/"):
            g._rpr_token_info = {"sub": "api-user-1"}
            assert "sub" in current_token
            assert "email" not in current_token

    def test_current_token_not_authenticated_without_bearer(self, app):
        with app.test_request_context("/"):
            assert current_token.is_authenticated is False
            assert bool(current_token) is False
            assert "sub" not in current_token

    def test_current_token_repr(self, app):
        with app.test_request_context("/"):
            assert repr(current_token) == "<CurrentToken: anonymous>"
            g._rpr_token_info = {"sub": "client-1", "token_type": "m2m"}
            assert repr(current_token) == "<CurrentToken: m2m sub=client-1>"
