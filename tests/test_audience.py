"""
Tests voor de RFC 8707 audience-check (OAUTH_RESOURCE_ID).

De auth-server geeft het `aud`-veld terug in zowel de userinfo- als de
introspectie-response. Als OAUTH_RESOURCE_ID is geconfigureerd, weigert
get_userinfo_from_token tokens die aan een ANDERE resource gebonden zijn.
"""

import pytest
from unittest.mock import patch, MagicMock
from flask import Flask

from flask_rpr_oauth.helpers import get_userinfo_from_token, clear_userinfo_cache

RESOURCE = "https://gms.test.nl"


@pytest.fixture
def app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret"
    app.config["OAUTH_BASE_URL"] = "https://auth.test.nl"
    app.config["OAUTH_CLIENT_ID"] = "test-client"
    app.config["OAUTH_CLIENT_SECRET"] = "test-secret"
    app.config["TESTING"] = True
    return app


@pytest.fixture(autouse=True)
def _clean_cache(app):
    with app.app_context():
        clear_userinfo_cache()
    yield


def _userinfo_response(aud):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"sub": "1", "token_type": "user", "aud": aud}
    return response


def _introspect_response(aud):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"active": True, "sub": "1", "token_type": "m2m", "aud": aud}
    return response


class TestAudienceCheckUserinfo:
    def test_unbound_token_accepted(self, app):
        """Token zonder aud (legacy) blijft overal geldig."""
        app.config["OAUTH_RESOURCE_ID"] = RESOURCE
        with app.app_context(), patch("requests.get", return_value=_userinfo_response(None)):
            assert get_userinfo_from_token("tok-1") is not None

    def test_matching_aud_accepted(self, app):
        app.config["OAUTH_RESOURCE_ID"] = RESOURCE
        with app.app_context(), patch("requests.get", return_value=_userinfo_response(RESOURCE)):
            assert get_userinfo_from_token("tok-2") is not None

    def test_wrong_aud_rejected(self, app):
        """Token voor een andere resource → geweigerd (leidt tot 401 in de decorators)."""
        app.config["OAUTH_RESOURCE_ID"] = RESOURCE
        with (
            app.app_context(),
            patch("requests.get", return_value=_userinfo_response("https://intranet.test.nl")),
        ):
            assert get_userinfo_from_token("tok-3") is None

    def test_no_resource_id_configured_no_enforcement(self, app):
        """Zonder OAUTH_RESOURCE_ID wordt niet gehandhaafd (opt-in)."""
        with (
            app.app_context(),
            patch("requests.get", return_value=_userinfo_response("https://intranet.test.nl")),
        ):
            assert get_userinfo_from_token("tok-4") is not None

    def test_rejected_token_not_cached(self, app):
        """Een geweigerd token mag niet uit de cache alsnog geaccepteerd worden."""
        app.config["OAUTH_RESOURCE_ID"] = RESOURCE
        with app.app_context():
            with patch("requests.get", return_value=_userinfo_response("https://intranet.test.nl")):
                assert get_userinfo_from_token("tok-5") is None
            # Tweede aanroep zonder mock zou een cache-hit zijn als hij gecachet was;
            # requests.get faalt hier bewust → None bewijst dat er niets gecachet is.
            with patch("requests.get", side_effect=Exception("geen netwerk")):
                assert get_userinfo_from_token("tok-5") is None


class TestAudienceCheckIntrospection:
    def _userinfo_403(self):
        response = MagicMock()
        response.status_code = 403
        return response

    def test_m2m_wrong_aud_rejected(self, app):
        app.config["OAUTH_RESOURCE_ID"] = RESOURCE
        with (
            app.app_context(),
            patch("requests.get", return_value=self._userinfo_403()),
            patch("requests.post", return_value=_introspect_response("https://intranet.test.nl")),
        ):
            assert get_userinfo_from_token("tok-6") is None

    def test_m2m_matching_aud_accepted(self, app):
        app.config["OAUTH_RESOURCE_ID"] = RESOURCE
        with (
            app.app_context(),
            patch("requests.get", return_value=self._userinfo_403()),
            patch("requests.post", return_value=_introspect_response(RESOURCE)),
        ):
            assert get_userinfo_from_token("tok-7") is not None
