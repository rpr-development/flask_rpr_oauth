"""Tests voor de OIDC Back-Channel Logout 1.0 ontvanger."""

import time

import pytest
from flask import Flask

from flask_rpr_oauth import RPRAuth
from flask_rpr_oauth.auth import BACKCHANNEL_LOGOUT_EVENT

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from authlib.jose import JsonWebKey, jwt as jose_jwt

ISSUER = "https://auth.test.nl"
CLIENT_ID = "test-client"
KID = "test-kid"


@pytest.fixture
def rsa_material():
    """(private_pem, JWKS-key-set, kid) voor het bouwen/valideren van logout tokens."""
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

    def set(self, key, value, nx=False, ex=None):
        """Minimale SET NX EX-emulatie, voor de jti-replaycache (net als dpop.py's redis-client)."""
        if nx and key in self.store:
            return False
        self.store[key] = value
        return True


_UNSET = object()


def _build_logout_token(
    private_pem,
    *,
    iss=ISSUER,
    aud=CLIENT_ID,
    sub="99",
    event=True,
    nonce=None,
    kid=KID,
    jti="abc",
    typ=_UNSET,
):
    now = int(time.time())
    payload = {"iss": iss, "sub": sub, "aud": aud, "iat": now, "exp": now + 120, "jti": jti}
    if event:
        payload["events"] = {BACKCHANNEL_LOGOUT_EVENT: {}}
    if nonce:
        payload["nonce"] = nonce
    header = {"alg": "RS256", "kid": kid}
    if typ is _UNSET:
        header["typ"] = "logout+jwt"
    elif typ is not None:
        header["typ"] = typ
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
    # Bypass het netwerk: lever de test-JWKS + discovery-issuer rechtstreeks.
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


def test_valid_logout_token_marks_user(client, rsa_material, fake_redis):
    private_pem, _ = rsa_material
    token = _build_logout_token(private_pem, sub="99")

    resp = client.post("/auth/backchannel-logout", data={"logout_token": token})

    assert resp.status_code == 200
    assert resp.headers.get("Cache-Control") == "no-store"
    assert fake_redis.store.get("rpr:bcl:logout:99") is not None


def test_missing_logout_token(client, fake_redis):
    resp = client.post("/auth/backchannel-logout", data={})
    assert resp.status_code == 400


def test_wrong_audience_rejected(client, rsa_material, fake_redis):
    private_pem, _ = rsa_material
    token = _build_logout_token(private_pem, aud="some-other-client")
    resp = client.post("/auth/backchannel-logout", data={"logout_token": token})
    assert resp.status_code == 400
    assert fake_redis.store == {}


def test_wrong_issuer_rejected(client, rsa_material, fake_redis):
    private_pem, _ = rsa_material
    token = _build_logout_token(private_pem, iss="https://evil.example.com")
    resp = client.post("/auth/backchannel-logout", data={"logout_token": token})
    assert resp.status_code == 400


def test_missing_event_rejected(client, rsa_material, fake_redis):
    private_pem, _ = rsa_material
    token = _build_logout_token(private_pem, event=False)
    resp = client.post("/auth/backchannel-logout", data={"logout_token": token})
    assert resp.status_code == 400


def test_nonce_rejected(client, rsa_material, fake_redis):
    private_pem, _ = rsa_material
    token = _build_logout_token(private_pem, nonce="verboden")
    resp = client.post("/auth/backchannel-logout", data={"logout_token": token})
    assert resp.status_code == 400


def test_bad_signature_rejected(client, rsa_material, fake_redis):
    private_pem, _ = rsa_material
    token = _build_logout_token(private_pem)
    # Vermink het handtekeningsegment.
    head, payload, _sig = token.split(".")
    tampered = f"{head}.{payload}.AAAAinvalidsignatureAAAA"
    resp = client.post("/auth/backchannel-logout", data={"logout_token": tampered})
    assert resp.status_code == 400


def test_disabled_returns_404(app, auth, rsa_material):
    app.config["OAUTH_ENABLE_BACKCHANNEL_LOGOUT"] = False
    private_pem, _ = rsa_material
    token = _build_logout_token(private_pem)
    resp = app.test_client().post("/auth/backchannel-logout", data={"logout_token": token})
    assert resp.status_code == 404


# ------------------------------------------------- enforcement (before_request)


def _add_protected_route(app):
    @app.route("/protected")
    def protected():
        return "ok"


def test_session_killed_after_marker(app, auth, client, fake_redis):
    _add_protected_route(app)
    # Ingelogde sessie, ingelogd VÓÓR de logout-marker. _token_validated_at recent zodat de
    # (netwerk-)token-hervalidatie niet meespeelt — we testen puur de BCL-handhaving.
    with client.session_transaction() as sess:
        sess["oauth_user"] = {"oauth_id": "99", "email": "x@test.nl"}
        sess["_login_at"] = time.time() - 100
        sess["_token_validated_at"] = time.time()
    fake_redis.store["rpr:bcl:logout:99"] = str(time.time())

    resp = client.get("/protected")
    # Sessie beëindigd → redirect naar login (geen 200 'ok').
    assert resp.status_code == 302
    assert "/auth/login" in resp.headers["Location"]


def test_session_survives_marker_before_login(app, auth, client, fake_redis):
    _add_protected_route(app)
    # Marker is ouder dan het login-moment → sessie blijft geldig.
    fake_redis.store["rpr:bcl:logout:99"] = str(time.time() - 100)
    with client.session_transaction() as sess:
        sess["oauth_user"] = {"oauth_id": "99", "email": "x@test.nl"}
        sess["_login_at"] = time.time()
        sess["_token_validated_at"] = time.time()

    resp = client.get("/protected")
    assert resp.status_code == 200
    assert resp.data == b"ok"


def test_session_survives_without_marker(app, auth, client, fake_redis):
    _add_protected_route(app)
    with client.session_transaction() as sess:
        sess["oauth_user"] = {"oauth_id": "99", "email": "x@test.nl"}
        sess["_login_at"] = time.time()
        sess["_token_validated_at"] = time.time()

    resp = client.get("/protected")
    assert resp.status_code == 200


# ------------------------------------------------------------------ typ-header (OIDC BCL §2.4)


def test_wrong_typ_rejected(client, rsa_material, fake_redis):
    private_pem, _ = rsa_material
    token = _build_logout_token(private_pem, typ="secevent+jwt")
    resp = client.post("/auth/backchannel-logout", data={"logout_token": token})
    assert resp.status_code == 400


def test_missing_typ_rejected(client, rsa_material, fake_redis):
    private_pem, _ = rsa_material
    token = _build_logout_token(private_pem, typ=None)
    resp = client.post("/auth/backchannel-logout", data={"logout_token": token})
    assert resp.status_code == 400


# ------------------------------------------------------------------ jti-replaycache (RFC 8417 §2.2)


def test_replay_rejected(client, rsa_material, fake_redis):
    private_pem, _ = rsa_material
    token = _build_logout_token(private_pem, sub="99")
    resp1 = client.post("/auth/backchannel-logout", data={"logout_token": token})
    assert resp1.status_code == 200
    resp2 = client.post("/auth/backchannel-logout", data={"logout_token": token})
    assert resp2.status_code == 400


def test_replay_check_fail_open_without_redis(client, rsa_material):
    """Zonder Redis (geen fake_redis-fixture) blijft de logout werken (fail-open)."""
    private_pem, _ = rsa_material
    token = _build_logout_token(private_pem, sub="99")
    resp = client.post("/auth/backchannel-logout", data={"logout_token": token})
    assert resp.status_code == 200


# ------------------------------------------------------------------ JWKS-herlaad bij onbekende kid


@pytest.fixture(autouse=True)
def _reset_jwks_force_reload_state():
    """De rate-limit-state is module-level (gedeeld tussen issuers/tests) — isoleren."""
    import flask_rpr_oauth.auth as auth_module

    auth_module._jwks_force_reload_at.clear()
    yield
    auth_module._jwks_force_reload_at.clear()


def test_jwks_reload_on_unknown_kid(app, rsa_material, monkeypatch):
    """Een SET met een kid die niet in de gecachete JWKS zit triggert één geforceerde herlaad."""
    _priv, key_set = rsa_material
    priv2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem2 = priv2.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    key2 = JsonWebKey.import_key(private_pem2, {"kty": "RSA"})
    public_jwk2 = key2.as_dict(is_private=False)
    new_kid = "rotated-kid"
    public_jwk2.update({"kid": new_kid, "use": "sig", "alg": "RS256"})
    new_key_set = JsonWebKey.import_key_set({"keys": [public_jwk2]})

    instance = RPRAuth(app)
    calls = {"count": 0}

    def fake_get_as_jwks(force=False):
        if force:
            calls["count"] += 1
            return new_key_set
        return key_set  # de "oude", gecachete set (kent new_kid niet)

    monkeypatch.setattr(instance, "_get_as_jwks", fake_get_as_jwks)
    monkeypatch.setattr(instance.auth_server, "load_server_metadata", lambda: {"issuer": ISSUER})
    monkeypatch.setattr(instance, "_logout_redis", lambda: _FakeRedis())

    token = _build_logout_token(private_pem2, sub="99", kid=new_kid)
    resp = app.test_client().post("/auth/backchannel-logout", data={"logout_token": token})

    assert resp.status_code == 200
    assert calls["count"] == 1


def test_jwks_reload_rate_limited(app, rsa_material, monkeypatch):
    """Een tweede onbekende kid binnen de rate-limit-periode triggert geen nieuwe herlaad."""
    private_pem, key_set = rsa_material
    instance = RPRAuth(app)
    calls = {"count": 0}

    def fake_get_as_jwks(force=False):
        if force:
            calls["count"] += 1
        return key_set  # blijft de aangeboden kid's nooit kennen: elke poging is "onbekend"

    monkeypatch.setattr(instance, "_get_as_jwks", fake_get_as_jwks)
    monkeypatch.setattr(instance.auth_server, "load_server_metadata", lambda: {"issuer": ISSUER})
    monkeypatch.setattr(instance, "_logout_redis", lambda: _FakeRedis())
    client = app.test_client()

    token1 = _build_logout_token(private_pem, sub="99", kid="unknown-kid-1", jti="jti-1")
    resp1 = client.post("/auth/backchannel-logout", data={"logout_token": token1})
    assert resp1.status_code == 400  # blijft ongeldig (verkeerde sleutel), maar wél 1 poging
    assert calls["count"] == 1

    token2 = _build_logout_token(private_pem, sub="99", kid="unknown-kid-2", jti="jti-2")
    resp2 = client.post("/auth/backchannel-logout", data={"logout_token": token2})
    assert resp2.status_code == 400
    assert calls["count"] == 1  # rate-limited: geen tweede poging binnen 60s


# ------------------------------------------------------------------ userinfo-cache-invalidatie


def test_cache_invalidated_on_logout(client, rsa_material, fake_redis):
    import flask_rpr_oauth.core as core_module

    core_module.clear_cache()
    core_module._cache_set(
        "some-access-token", {"sub": "99", "token_type": "user"}, ttl=60, maxsize=1000
    )
    assert core_module._cache_get("some-access-token") is not None

    private_pem, _ = rsa_material
    token = _build_logout_token(private_pem, sub="99")
    resp = client.post("/auth/backchannel-logout", data={"logout_token": token})
    assert resp.status_code == 200

    assert core_module._cache_get("some-access-token") is None
