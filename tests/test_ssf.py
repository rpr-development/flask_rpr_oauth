"""Tests voor de gedeelde Shared Signals Framework (RFC 8417 SET) ontvanger (/auth/ssf)."""

import time

import pytest
from flask import Flask

from flask_rpr_oauth import RPRAuth
from flask_rpr_oauth.auth import (
    RISC_ACCOUNT_DISABLED,
    RISC_ACCOUNT_PURGED,
    CAEP_SESSION_REVOKED,
    CAEP_CREDENTIAL_CHANGE,
)

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from authlib.jose import JsonWebKey, jwt as jose_jwt


ISSUER = "https://auth.test.nl"
CLIENT_ID = "test-client"
KID = "test-kid"
SECEVENT = "application/secevent+jwt"


@pytest.fixture
def rsa_material():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    key = JsonWebKey.import_key(private_pem, {"kty": "RSA"})
    public_jwk = key.as_dict(is_private=False)
    public_jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
    key_set = JsonWebKey.import_key_set({"keys": [public_jwk]})
    return private_pem, key_set


class _FakeRedis:
    def __init__(self):
        self.store = {}

    def setex(self, key, ttl, value):
        self.store[key] = value

    def get(self, key):
        return self.store.get(key)


def _build_set(private_pem, event_uri, *, aud=CLIENT_ID, sub="99", nonce=None, iss=ISSUER, kid=KID, sub_id=None):
    now = int(time.time())
    payload = {"iss": iss, "aud": aud, "iat": now, "exp": now + 120, "jti": "xyz", "events": {event_uri: {}}}
    if sub is not None:
        payload["sub"] = sub
    if sub_id is not None:
        payload["sub_id"] = sub_id
    if nonce:
        payload["nonce"] = nonce
    header = {"alg": "RS256", "kid": kid, "typ": "secevent+jwt"}
    tok = jose_jwt.encode(header, payload, private_pem)
    return tok.decode() if isinstance(tok, bytes) else tok


@pytest.fixture
def app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret"
    app.config["OAUTH_BASE_URL"] = ISSUER
    app.config["OAUTH_CLIENT_ID"] = CLIENT_ID
    app.config["OAUTH_CLIENT_SECRET"] = "test-secret"
    app.config["OAUTH_REDIRECT_URI"] = "http://localhost/callback"
    app.config["TESTING"] = True
    return app


@pytest.fixture
def auth(app, rsa_material, monkeypatch):
    _priv, key_set = rsa_material
    instance = RPRAuth(app)
    monkeypatch.setattr(instance, "_get_as_jwks", lambda: key_set)
    monkeypatch.setattr(instance.auth_server, "load_server_metadata", lambda: {"issuer": ISSUER})
    return instance


@pytest.fixture
def fake_redis(auth, monkeypatch):
    r = _FakeRedis()
    monkeypatch.setattr(auth, "_logout_redis", lambda: r)
    return r


@pytest.fixture
def client(app, auth):
    return app.test_client()


def test_account_disabled_marks_user(client, rsa_material, fake_redis):
    private_pem, _ = rsa_material
    token = _build_set(private_pem, RISC_ACCOUNT_DISABLED, sub="99")

    resp = client.post("/auth/ssf", data=token, content_type=SECEVENT)

    assert resp.status_code == 202
    assert resp.headers.get("Cache-Control") == "no-store"
    assert fake_redis.store.get("rpr:bcl:logout:99") is not None


def test_session_revoked_marks_user(client, rsa_material, fake_redis):
    private_pem, _ = rsa_material
    token = _build_set(private_pem, CAEP_SESSION_REVOKED, sub="42")
    resp = client.post("/auth/ssf", data=token, content_type=SECEVENT)
    assert resp.status_code == 202
    assert fake_redis.store.get("rpr:bcl:logout:42") is not None


def test_account_purged_invokes_callback(app, client, rsa_material, fake_redis):
    calls = []
    app.config["OAUTH_ON_ACCOUNT_PURGED"] = lambda sub, payload: calls.append(sub)
    private_pem, _ = rsa_material
    token = _build_set(private_pem, RISC_ACCOUNT_PURGED, sub="7")

    resp = client.post("/auth/ssf", data=token, content_type=SECEVENT)

    assert resp.status_code == 202
    assert calls == ["7"]
    assert fake_redis.store.get("rpr:bcl:logout:7") is not None


def test_credential_change_marks_user(client, rsa_material, fake_redis):
    private_pem, _ = rsa_material
    token = _build_set(private_pem, CAEP_CREDENTIAL_CHANGE, sub="99")
    resp = client.post("/auth/ssf", data=token, content_type=SECEVENT)
    assert resp.status_code == 202
    assert fake_redis.store.get("rpr:bcl:logout:99") is not None


def test_form_encoded_set_accepted(client, rsa_material, fake_redis):
    private_pem, _ = rsa_material
    token = _build_set(private_pem, RISC_ACCOUNT_DISABLED, sub="99")
    resp = client.post("/auth/ssf", data={"set": token})
    assert resp.status_code == 202
    assert fake_redis.store.get("rpr:bcl:logout:99") is not None


def test_sub_id_fallback(client, rsa_material, fake_redis):
    """Zonder top-level sub valt de ontvanger terug op RFC 9493 sub_id (iss_sub)."""
    private_pem, _ = rsa_material
    token = _build_set(
        private_pem,
        RISC_ACCOUNT_DISABLED,
        sub=None,
        sub_id={"format": "iss_sub", "iss": ISSUER, "sub": "55"},
    )
    resp = client.post("/auth/ssf", data=token, content_type=SECEVENT)
    assert resp.status_code == 202
    assert fake_redis.store.get("rpr:bcl:logout:55") is not None


def test_wrong_audience_rejected(client, rsa_material, fake_redis):
    private_pem, _ = rsa_material
    token = _build_set(private_pem, RISC_ACCOUNT_DISABLED, aud="some-other-client")
    resp = client.post("/auth/ssf", data=token, content_type=SECEVENT)
    assert resp.status_code == 400
    assert fake_redis.store == {}


def test_wrong_issuer_rejected(client, rsa_material, fake_redis):
    private_pem, _ = rsa_material
    token = _build_set(private_pem, RISC_ACCOUNT_DISABLED, iss="https://evil.example.com")
    resp = client.post("/auth/ssf", data=token, content_type=SECEVENT)
    assert resp.status_code == 400


def test_nonce_rejected(client, rsa_material, fake_redis):
    private_pem, _ = rsa_material
    token = _build_set(private_pem, RISC_ACCOUNT_DISABLED, nonce="verboden")
    resp = client.post("/auth/ssf", data=token, content_type=SECEVENT)
    assert resp.status_code == 400


def test_unknown_event_rejected(client, rsa_material, fake_redis):
    private_pem, _ = rsa_material
    token = _build_set(private_pem, "https://example.com/some/unknown-event")
    resp = client.post("/auth/ssf", data=token, content_type=SECEVENT)
    assert resp.status_code == 400
    assert fake_redis.store == {}


def test_bad_signature_rejected(client, rsa_material, fake_redis):
    private_pem, _ = rsa_material
    token = _build_set(private_pem, RISC_ACCOUNT_DISABLED)
    head, payload, _sig = token.split(".")
    tampered = f"{head}.{payload}.AAAAinvalidsignatureAAAA"
    resp = client.post("/auth/ssf", data=tampered, content_type=SECEVENT)
    assert resp.status_code == 400


def test_missing_set(client, fake_redis):
    resp = client.post("/auth/ssf", data="", content_type=SECEVENT)
    assert resp.status_code == 400


def test_disabled_returns_404(app, auth, rsa_material):
    app.config["OAUTH_ENABLE_SSF"] = False
    private_pem, _ = rsa_material
    token = _build_set(private_pem, RISC_ACCOUNT_DISABLED)
    resp = app.test_client().post("/auth/ssf", data=token, content_type=SECEVENT)
    assert resp.status_code == 404


def test_logout_token_still_works(client, rsa_material, fake_redis):
    """De bestaande /auth/backchannel-logout blijft werken na de _validate_set-refactor."""
    from flask_rpr_oauth.auth import BACKCHANNEL_LOGOUT_EVENT

    private_pem, _ = rsa_material
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "sub": "99",
        "aud": CLIENT_ID,
        "iat": now,
        "exp": now + 120,
        "jti": "abc",
        "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
    }
    header = {"alg": "RS256", "kid": KID, "typ": "logout+jwt"}
    tok = jose_jwt.encode(header, payload, private_pem)
    token = tok.decode() if isinstance(tok, bytes) else tok

    resp = client.post("/auth/backchannel-logout", data={"logout_token": token})
    assert resp.status_code == 200
    assert fake_redis.store.get("rpr:bcl:logout:99") is not None
