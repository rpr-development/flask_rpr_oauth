"""RFC 9449 — DPoP aan de resource-server-kant (decorators + proof-validatie).

Dekt: een geldige DPoP-request (proof + matchende cnf.jkt) krijgt toegang; ongeldige/mismatchende
proof of een niet-gebonden token via het DPoP-scheme wordt geweigerd met een
``WWW-Authenticate: DPoP``-challenge; en ``OAUTH_REQUIRE_DPOP`` weigert plain Bearer.
De introspectie wordt gemockt; de proof-JWT is echt (joserfc).
"""

import time
from unittest.mock import patch

import pytest
from flask import Flask, jsonify
from joserfc import jwt as joserfc_jwt
from joserfc.jwk import ECKey

from flask_rpr_oauth import RPRAuth
from flask_rpr_oauth.decorators import login_required
from flask_rpr_oauth.dpop import compute_ath


@pytest.fixture
def key():
    return ECKey.generate_key("P-256")


def _make_app(**config):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret"
    app.config["OAUTH_BASE_URL"] = "https://auth.test.nl"
    app.config["OAUTH_CLIENT_ID"] = "test-client"
    app.config["OAUTH_CLIENT_SECRET"] = "test-secret"
    app.config["OAUTH_REDIRECT_URI"] = "http://localhost/callback"
    app.config["TESTING"] = True
    app.config.update(config)
    RPRAuth(app)

    @app.route("/sensitive")
    @login_required
    def sensitive():
        return jsonify({"status": "ok"})

    return app


def _proof(key, token, *, htm="GET", htu="http://localhost/sensitive", jti=None, ath=None):
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": key.as_dict(private=False)}
    claims = {
        "htm": htm,
        "htu": htu,
        "jti": jti or f"jti-{time.time_ns()}",
        "iat": int(time.time()),
        "ath": compute_ath(token) if ath is None else ath,
    }
    return joserfc_jwt.encode(header, claims, key)


def _introspection(key):
    """Introspectie-respons voor een DPoP-gebonden user-token."""
    return {
        "active": True,
        "token_type": "user",
        "sub": "42",
        "permissions": [],
        "groups": [],
        "acr": "pwd",
        "cnf": {"jkt": key.thumbprint()},
    }


def test_valid_dpop_request_allowed(key):
    app = _make_app()
    token = "the-access-token"
    with patch("flask_rpr_oauth.helpers._introspect_token", return_value=_introspection(key)):
        resp = app.test_client().get(
            "/sensitive",
            headers={"Authorization": f"DPoP {token}", "DPoP": _proof(key, token)},
        )
    assert resp.status_code == 200, resp.get_data(as_text=True)


def test_dpop_missing_proof_rejected(key):
    app = _make_app()
    token = "the-access-token"
    with patch("flask_rpr_oauth.helpers._introspect_token", return_value=_introspection(key)):
        resp = app.test_client().get("/sensitive", headers={"Authorization": f"DPoP {token}"})
    assert resp.status_code == 401
    assert resp.headers.get("WWW-Authenticate", "").startswith("DPoP")


def test_dpop_jkt_mismatch_rejected(key):
    app = _make_app()
    token = "the-access-token"
    # Introspectie bindt aan een ANDERE sleutel dan de proof → mismatch.
    other = ECKey.generate_key("P-256")
    with patch("flask_rpr_oauth.helpers._introspect_token", return_value=_introspection(other)):
        resp = app.test_client().get(
            "/sensitive",
            headers={"Authorization": f"DPoP {token}", "DPoP": _proof(key, token)},
        )
    assert resp.status_code == 401
    assert resp.headers.get("WWW-Authenticate", "").startswith("DPoP")


def test_dpop_scheme_with_unbound_token_rejected(key):
    """Een gewoon (niet-gebonden) token aangeboden via het DPoP-scheme moet geweigerd worden."""
    app = _make_app()
    token = "the-access-token"
    unbound = {"active": True, "token_type": "user", "sub": "42", "permissions": [], "groups": []}
    with patch("flask_rpr_oauth.helpers._introspect_token", return_value=unbound):
        resp = app.test_client().get(
            "/sensitive",
            headers={"Authorization": f"DPoP {token}", "DPoP": _proof(key, token)},
        )
    assert resp.status_code == 401


def test_dpop_wrong_ath_rejected(key):
    app = _make_app()
    token = "the-access-token"
    with patch("flask_rpr_oauth.helpers._introspect_token", return_value=_introspection(key)):
        resp = app.test_client().get(
            "/sensitive",
            headers={"Authorization": f"DPoP {token}", "DPoP": _proof(key, token, ath="wrong")},
        )
    assert resp.status_code == 401


def test_require_dpop_rejects_plain_bearer(key):
    app = _make_app(OAUTH_REQUIRE_DPOP=True)
    # Zelfs met een geldige userinfo-respons: plain Bearer is niet toegestaan als DPoP verplicht is.
    with patch("flask_rpr_oauth.helpers.get_userinfo_from_token", return_value=_introspection(key)):
        resp = app.test_client().get("/sensitive", headers={"Authorization": "Bearer some-token"})
    assert resp.status_code == 401
    challenge = resp.headers.get("WWW-Authenticate", "")
    assert challenge.startswith("DPoP")
    assert "algs=" in challenge


def test_bearer_still_works_without_require_dpop(key):
    """Zonder OAUTH_REQUIRE_DPOP blijft een gewoon Bearer-token werken (ongewijzigd gedrag)."""
    app = _make_app()
    with patch("flask_rpr_oauth.helpers.get_userinfo_from_token", return_value=_introspection(key)):
        resp = app.test_client().get("/sensitive", headers={"Authorization": "Bearer some-token"})
    assert resp.status_code == 200
