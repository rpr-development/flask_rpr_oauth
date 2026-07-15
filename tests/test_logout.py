"""Tests voor /auth/logout: token-revocatie (RFC 7009) + RP-Initiated Logout parameters."""

import pytest
from flask import Flask, session

from flask_rpr_oauth import RPRAuth
from flask_rpr_oauth import auth as auth_module


ISSUER = "https://auth.test.nl"
CLIENT_ID = "test-client"
END_SESSION = f"{ISSUER}/oauth/end_session"
REVOCATION = f"{ISSUER}/oauth/revoke"


@pytest.fixture
def app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret"
    app.config["OAUTH_BASE_URL"] = ISSUER
    app.config["OAUTH_CLIENT_ID"] = CLIENT_ID
    app.config["OAUTH_CLIENT_SECRET"] = "test-secret"
    app.config["OAUTH_REDIRECT_URI"] = "http://localhost/callback"
    app.config["TESTING"] = True

    @app.route("/")
    def index():
        return "home"

    return app


@pytest.fixture
def auth(app, monkeypatch):
    instance = RPRAuth(app)
    monkeypatch.setattr(
        instance.auth_server,
        "load_server_metadata",
        lambda: {
            "issuer": ISSUER,
            "end_session_endpoint": END_SESSION,
            "revocation_endpoint": REVOCATION,
        },
    )
    return instance


@pytest.fixture
def client(app, auth):
    return app.test_client()


class _CapturedPost:
    """Vangt requests.post-aanroepen van de revocatie op (zonder netwerk)."""

    def __init__(self, status_code=200):
        self.calls = []
        self.status_code = status_code

    def __call__(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        resp = type("Resp", (), {"status_code": self.status_code})()
        return resp


@pytest.fixture
def captured_revoke(monkeypatch):
    captured = _CapturedPost()
    monkeypatch.setattr(auth_module.requests, "post", captured)
    return captured


def _login(client, with_refresh=True):
    """Zet een ingelogde sessie met tokens, zoals na een echte callback."""
    token = {"access_token": "at-123", "id_token": "idt-456"}
    if with_refresh:
        token["refresh_token"] = "rt-789"
    with client.session_transaction() as sess:
        sess["oauth_token"] = token
        sess["oauth_user"] = {"oauth_id": "99", "email": "test@example.com"}


def test_logout_revokes_refresh_token(client, captured_revoke):
    _login(client)
    resp = client.get("/auth/logout")

    assert resp.status_code == 200  # POST-form naar end_session
    assert len(captured_revoke.calls) == 1
    call = captured_revoke.calls[0]
    assert call["url"] == REVOCATION
    assert call["data"] == {"token": "rt-789", "token_type_hint": "refresh_token"}
    assert call["auth"] == (CLIENT_ID, "test-secret")


def test_logout_falls_back_to_access_token(client, captured_revoke):
    _login(client, with_refresh=False)
    client.get("/auth/logout")

    assert captured_revoke.calls[0]["data"] == {"token": "at-123", "token_type_hint": "access_token"}


def test_logout_clears_session_and_posts_to_end_session(app, client, captured_revoke):
    _login(client)
    resp = client.get("/auth/logout")

    body = resp.get_data(as_text=True)
    assert END_SESSION in body
    assert "idt-456" in body  # id_token_hint in het POST-formulier
    assert CLIENT_ID in body  # client_id (RP-Initiated Logout §2) gaat mee
    with client.session_transaction() as sess:
        assert "oauth_user" not in sess and "oauth_token" not in sess


def test_logout_survives_revocation_failure(client, monkeypatch):
    """Best-effort: een kapotte revocatie-endpoint mag de logout nooit blokkeren."""

    def _boom(*args, **kwargs):
        raise ConnectionError("revoke onbereikbaar")

    monkeypatch.setattr(auth_module.requests, "post", _boom)
    _login(client)
    resp = client.get("/auth/logout")

    assert resp.status_code == 200
    with client.session_transaction() as sess:
        assert "oauth_user" not in sess


def test_logout_without_tokens_skips_revocation(client, captured_revoke):
    """Geen sessie(tokens) = niets in te trekken, geen crash."""
    resp = client.get("/auth/logout")

    assert resp.status_code == 200
    assert captured_revoke.calls == []


def test_revoke_on_logout_can_be_disabled(app, client, captured_revoke):
    app.config["OAUTH_REVOKE_ON_LOGOUT"] = False
    _login(client)
    client.get("/auth/logout")

    assert captured_revoke.calls == []


def test_logout_without_end_session_redirects_home(app, client, auth, captured_revoke, monkeypatch):
    """Zonder end_session_endpoint in de discovery: alleen lokaal uitloggen + redirect."""
    monkeypatch.setattr(
        auth.auth_server,
        "load_server_metadata",
        lambda: {"issuer": ISSUER, "revocation_endpoint": REVOCATION},
    )
    _login(client)
    resp = client.get("/auth/logout")

    assert resp.status_code == 302
    assert len(captured_revoke.calls) == 1  # revocatie gebeurt ook zonder end_session
