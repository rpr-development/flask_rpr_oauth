"""Dev login without the auth server (OAUTH_DEV_LOGIN): gates, picker, session and logout."""

import pytest
from flask import Flask, redirect

from flask_rpr_oauth import RPRAuth
from flask_rpr_oauth import auth as auth_module

ISSUER = "http://auth.dev.invalid"
USERS = {
    "admin": {
        "sub": "900004",
        "email": "admin@dev.invalid",
        "given_name": "Dev",
        "family_name": "Admin",
        "user_type": "MEMBER",
        "user_status": "ACTIVE",
        "acr": "mfa",
        "permissions": ["app.thing.edit"],
        "groups": ["beheer"],
    },
    "eenheid": {
        "sub": "900002",
        "email": "eenheid@dev.invalid",
        "user_type": "MEMBER",
        "user_status": "ACTIVE",
    },
}


def _make_app(dev_login=True, debug=True, users=USERS):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY="test-secret",
        OAUTH_BASE_URL=ISSUER,
        OAUTH_CLIENT_ID="dev",
        OAUTH_CLIENT_SECRET="dev",
        OAUTH_REDIRECT_URI="http://localhost/auth/callback",
        TESTING=True,
        OAUTH_DEV_LOGIN=dev_login,
        OAUTH_DEV_USERS=users,
    )
    app.debug = debug

    @app.route("/")
    def index():
        return "home"

    @app.route("/meldkamer/")
    def meldkamer():
        return "meldkamer"

    return app


@pytest.fixture
def app():
    return _make_app()


@pytest.fixture
def auth(app, monkeypatch):
    instance = RPRAuth(app)
    # No network: the real authorize_redirect would fetch the discovery document.
    monkeypatch.setattr(
        instance.auth_server, "authorize_redirect", lambda *a, **k: redirect(f"{ISSUER}/authorize")
    )
    return instance


@pytest.fixture
def client(app, auth):
    return app.test_client()


def _nonce(client):
    """Open the picker and return the nonce it stored, like a browser would send back."""
    assert client.get("/auth/login").status_code == 200
    with client.session_transaction() as sess:
        return sess["_dev_login_nonce"]


def _login(client, key="admin"):
    return client.post(f"/auth/dev-login/{key}", data={"nonce": _nonce(client)})


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------

def test_refuses_to_start_without_debug():
    with pytest.raises(RuntimeError, match="app.debug"):
        RPRAuth(_make_app(debug=False))


@pytest.mark.parametrize("users", [{}, {"x": {"email": "no-sub@dev.invalid"}}, {"x": "not-a-dict"}])
def test_refuses_to_start_without_usable_users(users):
    with pytest.raises(RuntimeError, match="OAUTH_DEV_USERS"):
        RPRAuth(_make_app(users=users))


def test_switched_off_keeps_the_normal_flow(monkeypatch):
    app = _make_app(dev_login=False)
    instance = RPRAuth(app)
    monkeypatch.setattr(
        instance.auth_server, "authorize_redirect", lambda *a, **k: redirect(f"{ISSUER}/authorize")
    )
    client = app.test_client()

    resp = client.get("/auth/login")
    assert resp.status_code == 302 and resp.headers["Location"].startswith(ISSUER)
    assert client.post("/auth/dev-login/admin", data={"nonce": "x"}).status_code == 404


def test_route_rechecks_the_switch_per_request(app, client):
    nonce = _nonce(client)
    app.config["OAUTH_DEV_LOGIN"] = False
    assert client.post("/auth/dev-login/admin", data={"nonce": nonce}).status_code == 404


# ---------------------------------------------------------------------------
# Picker and login
# ---------------------------------------------------------------------------

def test_picker_lists_users_without_caching(client):
    resp = client.get("/auth/login")
    body = resp.get_data(as_text=True)

    assert resp.status_code == 200
    assert resp.headers["Cache-Control"] == "no-store"
    assert "DEV LOGIN" in body
    assert "/auth/dev-login/admin" in body and "/auth/dev-login/eenheid" in body


def test_unknown_user_is_404(client):
    assert client.post("/auth/dev-login/nobody", data={"nonce": _nonce(client)}).status_code == 404


def test_missing_or_wrong_nonce_is_400(client):
    assert client.post("/auth/dev-login/admin").status_code == 400
    _nonce(client)
    assert client.post("/auth/dev-login/admin", data={"nonce": "wrong"}).status_code == 400
    # A nonce is single-use: the failed attempt consumed it.
    assert client.post("/auth/dev-login/admin", data={"nonce": "wrong"}).status_code == 400


def test_login_populates_session_like_a_real_callback(client):
    resp = _login(client, "admin")

    assert resp.status_code == 303
    assert resp.headers["Location"].endswith("/")
    with client.session_transaction() as sess:
        assert sess["oauth_dev"] is True
        assert sess["oauth_user"]["oauth_id"] == "900004"
        assert sess["oauth_user"]["email"] == "admin@dev.invalid"
        assert sess["oauth_user"]["voornaam"] == "Dev"
        assert sess["oauth_user"]["user_status"] == "ACTIVE"
        assert sess["oauth_permissions"] == ["app.thing.edit"]
        assert sess["oauth_groups"] == ["beheer"]
        assert sess["oauth_token"]["token_type"] == "dev"
        assert sess["acr"] == "mfa" and sess["twofa_validated"] is True
        assert "_dev_login_nonce" not in sess

    assert client.get("/").get_data(as_text=True) == "home"


def test_next_is_honoured_and_open_redirects_are_not(client):
    with client.session_transaction() as sess:
        sess["next"] = "/meldkamer/"
    assert _login(client).headers["Location"].endswith("/meldkamer/")

    with client.session_transaction() as sess:
        sess["next"] = "https://evil.invalid/phish"
    assert _login(client).headers["Location"].endswith("/")


def test_hook_receives_the_userinfo(app, client):
    seen = []
    app.config["OAUTH_ON_DEV_LOGIN"] = seen.append

    _login(client, "eenheid")

    assert seen == [USERS["eenheid"]]


# ---------------------------------------------------------------------------
# Session revalidation and logout
# ---------------------------------------------------------------------------

def test_revalidation_skips_dev_sessions_but_not_real_ones(app, client, auth, monkeypatch):
    calls = []
    monkeypatch.setattr(auth, "validate_token", lambda: calls.append(1) or True)

    _login(client)
    with client.session_transaction() as sess:
        sess["_token_validated_at"] = 0
    assert client.get("/").status_code == 200
    assert calls == []

    with client.session_transaction() as sess:
        sess.clear()
        sess["oauth_user"] = {"oauth_id": "1", "email": "echt@example.com"}
        sess["oauth_token"] = {"access_token": "at"}
        sess["_token_validated_at"] = 0
    assert client.get("/").status_code == 200
    assert calls == [1]


def test_dev_session_is_wiped_once_the_switch_is_off(app, client):
    _login(client)
    app.config["OAUTH_DEV_LOGIN"] = False

    resp = client.get("/")

    assert resp.status_code == 302 and "/auth/login" in resp.headers["Location"]
    with client.session_transaction() as sess:
        assert "oauth_user" not in sess and "oauth_dev" not in sess


def _no_server(auth, monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("auth server must not be contacted for a dev session")

    monkeypatch.setattr(auth.auth_server, "authorize_redirect", _boom)
    monkeypatch.setattr(auth_module.requests, "get", _boom)


def test_login_sets_auth_time_to_the_moment_of_picking(client, monkeypatch):
    monkeypatch.setattr(auth_module.time, "time", lambda: 1_700_000_000)
    _login(client)
    with client.session_transaction() as sess:
        assert sess["auth_time"] == 1_700_000_000


# ---------------------------------------------------------------------------
# CSRF and 2FA step-up
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("csrf_first", [True, False])
def test_dev_login_passes_the_host_csrf_protection(csrf_first, monkeypatch):
    csrf_module = pytest.importorskip("flask_wtf.csrf")
    app = _make_app()
    csrf = csrf_module.CSRFProtect()
    if csrf_first:
        csrf.init_app(app)
    RPRAuth(app)
    if not csrf_first:
        csrf.init_app(app)
    client = app.test_client()

    assert _login(client).status_code == 303
    with client.session_transaction() as sess:
        assert sess["oauth_dev"] is True


def test_host_csrf_still_protects_other_posts():
    csrf_module = pytest.importorskip("flask_wtf.csrf")
    app = _make_app()

    @app.route("/save", methods=["POST"])
    def save():
        return "saved"

    csrf_module.CSRFProtect(app)
    RPRAuth(app)

    assert app.test_client().post("/save").status_code == 400


def _guarded_routes(app, auth):
    from flask_rpr_oauth import require_2fa

    @app.route("/admin/")
    def admin():
        return auth.require_fresh_2fa("_admin_2fa_granted") or "admin"

    @app.route("/danger/")
    @require_2fa(max_age=300)
    def danger():
        return "danger"


def test_fresh_2fa_is_granted_from_the_dev_acr(app, auth, client, monkeypatch):
    _guarded_routes(app, auth)
    _no_server(auth, monkeypatch)
    _login(client, "admin")

    assert client.get("/admin/").get_data(as_text=True) == "admin"
    assert client.get("/danger/").get_data(as_text=True) == "danger"
    with client.session_transaction() as sess:
        assert sess["_admin_2fa_granted"] is True


def test_dev_user_without_mfa_gets_403_instead_of_the_auth_server(app, auth, client, monkeypatch):
    _guarded_routes(app, auth)
    _no_server(auth, monkeypatch)
    _login(client, "eenheid")

    assert client.get("/admin/").status_code == 403
    assert client.get("/danger/").status_code == 403
    with client.session_transaction() as sess:
        assert "_admin_2fa_granted" not in sess


def test_fresh_2fa_is_not_granted_once_the_switch_is_off(app, auth, client, monkeypatch):
    _no_server(auth, monkeypatch)
    _login(client, "admin")
    app.config["OAUTH_DEV_LOGIN"] = False

    with app.test_request_context("/admin/"):
        from flask import session

        session.update(oauth_dev=True, acr="mfa", oauth_user={"oauth_id": "900004"})
        with pytest.raises(Exception) as exc:
            auth.require_fresh_2fa("_admin_2fa_granted")
        assert getattr(exc.value, "code", None) == 403
        assert "_admin_2fa_granted" not in session


def test_logout_clears_without_touching_the_server(client, auth, monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("auth server must not be contacted for a dev session")

    monkeypatch.setattr(auth_module.requests, "post", _boom)
    monkeypatch.setattr(auth.auth_server, "load_server_metadata", _boom)
    _login(client)

    resp = client.get("/auth/logout")

    assert resp.status_code == 302 and resp.headers["Location"].endswith("/")
    with client.session_transaction() as sess:
        assert "oauth_user" not in sess and "oauth_dev" not in sess
