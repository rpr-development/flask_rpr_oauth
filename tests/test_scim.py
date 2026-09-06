"""Tests voor de SCIM 2.0-ontvanger (RFC 7644) op /scim/v2/Users."""

import pytest
from flask import Flask

from flask_rpr_oauth import RPRAuth
import flask_rpr_oauth.helpers as helpers_module

ISSUER = "https://auth.test.nl"
CLIENT_ID = "test-client"
SCIM_JSON = "application/scim+json"
PERMISSION = "auth.scim.provision"

RESOURCE = {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "externalId": "42",
    "userName": "piet@example.com",
    "active": True,
}


@pytest.fixture
def app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret"
    app.config["OAUTH_BASE_URL"] = ISSUER
    app.config["OAUTH_CLIENT_ID"] = CLIENT_ID
    app.config["OAUTH_CLIENT_SECRET"] = "test-secret"
    app.config["OAUTH_REDIRECT_URI"] = "http://localhost/callback"
    app.config["OAUTH_ENABLE_SCIM"] = True
    app.config["TESTING"] = True
    return app


@pytest.fixture
def auth(app):
    return RPRAuth(app)


@pytest.fixture
def client(app, auth):
    return app.test_client()


@pytest.fixture
def valid_token(monkeypatch):
    """Laat elke Bearer-token valideren als M2M-token mét de provisioning-permissie."""
    monkeypatch.setattr(
        helpers_module,
        "get_userinfo_from_token",
        lambda token: {"sub": "scim-worker-internal", "permissions": [PERMISSION]},
    )


def _headers():
    return {"Authorization": "Bearer test-token"}


# ------------------------------------------------------------------ toegang


def test_scim_disabled_geeft_404(app, auth, valid_token):
    app.config["OAUTH_ENABLE_SCIM"] = False
    client = app.test_client()
    resp = client.put("/scim/v2/Users/42", json=RESOURCE, headers=_headers())
    assert resp.status_code == 404


def test_scim_zonder_token_geeft_401(client):
    resp = client.put("/scim/v2/Users/42", json=RESOURCE)
    assert resp.status_code == 401
    assert "invalid_token" in resp.headers.get("WWW-Authenticate", "")
    assert resp.mimetype == SCIM_JSON


def test_scim_ongeldig_token_geeft_401(client, monkeypatch):
    monkeypatch.setattr(helpers_module, "get_userinfo_from_token", lambda token: None)
    resp = client.put("/scim/v2/Users/42", json=RESOURCE, headers=_headers())
    assert resp.status_code == 401


def test_scim_zonder_permissie_geeft_403(client, monkeypatch):
    monkeypatch.setattr(
        helpers_module,
        "get_userinfo_from_token",
        lambda token: {"sub": "andere-client", "permissions": ["iets.anders"]},
    )
    resp = client.put("/scim/v2/Users/42", json=RESOURCE, headers=_headers())
    assert resp.status_code == 403


def test_scim_require_dpop_rejects_plain_bearer(app, auth, valid_token):
    """OAUTH_REQUIRE_DPOP beschermt ook /scim/v2/*: een plain Bearer-token wordt geweigerd,
    ook al zou de (gemockte) userinfo-lookup een geldig M2M-token teruggeven."""
    app.config["OAUTH_REQUIRE_DPOP"] = True
    client = app.test_client()
    resp = client.put("/scim/v2/Users/42", json=RESOURCE, headers=_headers())
    assert resp.status_code == 401


# ------------------------------------------------------------------ sync (PUT/POST)


def test_put_upsert_roept_sync_callback(app, client, valid_token):
    calls = []
    app.config["OAUTH_ON_SCIM_SYNC"] = lambda user_id, resource: calls.append((user_id, resource))

    resp = client.put("/scim/v2/Users/42", json=RESOURCE, headers=_headers())

    assert resp.status_code == 200
    assert resp.mimetype == SCIM_JSON
    assert resp.get_json()["id"] == "42"
    assert calls == [("42", RESOURCE)]


def test_post_create_gebruikt_external_id(app, client, valid_token):
    calls = []
    app.config["OAUTH_ON_SCIM_SYNC"] = lambda user_id, resource: calls.append(user_id)

    resp = client.post("/scim/v2/Users", json=RESOURCE, headers=_headers())

    assert resp.status_code == 201
    assert calls == ["42"]


def test_put_zonder_body_geeft_400(app, client, valid_token):
    app.config["OAUTH_ON_SCIM_SYNC"] = lambda user_id, resource: None
    resp = client.put("/scim/v2/Users/42", data="geen json", headers=_headers())
    assert resp.status_code == 400


def test_sync_zonder_callback_geeft_501(client, valid_token):
    resp = client.put("/scim/v2/Users/42", json=RESOURCE, headers=_headers())
    assert resp.status_code == 501


def test_sync_callback_fout_geeft_500_voor_worker_retry(app, client, valid_token):
    def _boom(user_id, resource):
        raise RuntimeError("db down")

    app.config["OAUTH_ON_SCIM_SYNC"] = _boom
    resp = client.put("/scim/v2/Users/42", json=RESOURCE, headers=_headers())
    assert resp.status_code == 500


# ------------------------------------------------------------------ delete


def test_delete_roept_delete_callback(app, client, valid_token):
    calls = []
    app.config["OAUTH_ON_SCIM_DELETE"] = lambda user_id: calls.append(user_id)

    resp = client.delete("/scim/v2/Users/42", headers=_headers())

    assert resp.status_code == 204
    assert calls == ["42"]


def test_delete_zonder_callback_geeft_501(client, valid_token):
    resp = client.delete("/scim/v2/Users/42", headers=_headers())
    assert resp.status_code == 501


# ------------------------------------------------------------------ get (AVG-export)


def test_get_levert_exportdata(app, client, valid_token):
    app.config["OAUTH_ON_SCIM_GET"] = lambda user_id: {
        "userName": "piet@example.com",
        "meldingen": 3,
    }

    resp = client.get("/scim/v2/Users/42", headers=_headers())

    assert resp.status_code == 200
    assert resp.get_json()["meldingen"] == 3


def test_get_onbekende_gebruiker_geeft_404(app, client, valid_token):
    app.config["OAUTH_ON_SCIM_GET"] = lambda user_id: None
    resp = client.get("/scim/v2/Users/42", headers=_headers())
    assert resp.status_code == 404


def test_get_zonder_callback_geeft_404(client, valid_token):
    resp = client.get("/scim/v2/Users/42", headers=_headers())
    assert resp.status_code == 404
