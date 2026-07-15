"""
flask_rpr_oauth.auth
~~~~~~~~~~~~~~~~~~~~

Main OAuth authentication class.
"""

import json
import logging
import re
import threading
import time
from typing import Optional
from urllib.parse import urlparse
import requests
from flask import (
    Blueprint,
    redirect,
    url_for,
    session,
    request,
    jsonify,
    current_app,
    make_response,
    abort,
    render_template_string,
)
from markupsafe import escape
from authlib.integrations.flask_client import OAuth
from authlib.integrations.base_client.errors import MismatchingStateError
from .models import OAuthUser
from .exceptions import OAuthError, TokenExpiredError
from .helpers import get_userinfo_from_token

try:
    from flask_wtf.csrf import csrf_exempt

    CSRF_AVAILABLE = True
except ImportError:
    # flask_wtf niet aanwezig, OF flask-wtf 1.3+ waarbij csrf_exempt uit de
    # publieke API is verwijderd. CSRFProtect controleert nog steeds het
    # _csrf_exempt attribuut op de view-functie, dus dat zetten we handmatig.
    CSRF_AVAILABLE = False

    def csrf_exempt(func):
        func._csrf_exempt = True
        return func


try:
    from flask_session import Session as FlaskSession
    from flask_session.base import ServerSideSessionInterface as _ServerSideSessionInterface

    FLASK_SESSION_AVAILABLE = True
except ImportError:
    FLASK_SESSION_AVAILABLE = False
    _ServerSideSessionInterface = None

try:
    import redis as _redis_lib

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    _redis_lib = None


logger = logging.getLogger(__name__)

# OIDC Back-Channel Logout 1.0 §2.4 — het event-type dat een logout token identificeert.
BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"

# Shared Signals Framework (RFC 8417) event-type-URI's — de SET's die de auth server
# via /auth/ssf pusht (RISC = account-lifecycle, CAEP = sessie-/credential-events).
RISC_ACCOUNT_DISABLED = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
RISC_ACCOUNT_PURGED = "https://schemas.openid.net/secevent/risc/event-type/account-purged"
CAEP_SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
CAEP_CREDENTIAL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/credential-change"

# Event → optionele app-callback (Flask-config-key). Elk bekend event beëindigt de sessie
# (mark_logged_out → re-auth); een callback laat de app extra actie ondernemen (bv. lokale
# gebruiker opruimen bij account-purged). De callback krijgt (sub, event_payload).
_SSF_CALLBACK_KEYS = {
    RISC_ACCOUNT_PURGED: "OAUTH_ON_ACCOUNT_PURGED",
    RISC_ACCOUNT_DISABLED: "OAUTH_ON_ACCOUNT_DISABLED",
    CAEP_SESSION_REVOKED: "OAUTH_ON_SESSION_REVOKED",
    CAEP_CREDENTIAL_CHANGE: "OAUTH_ON_CREDENTIAL_CHANGE",
}
# Alle event-types die /auth/ssf herkent (de rest wordt genegeerd).
_SSF_KNOWN_EVENTS = set(_SSF_CALLBACK_KEYS) | {BACKCHANNEL_LOGOUT_EVENT}

# In-memory cache van de JWKS van de auth server (voor het valideren van logout tokens).
# Value = (JsonWebKey set, expiry timestamp). Beschermd door een lock: onder gevent/threads
# muteren meerdere requests hem tegelijk.
_jwks_cache: dict = {}
_jwks_lock = threading.Lock()
_JWKS_CACHE_TTL = 3600  # seconden


def _is_safe_redirect(target):
    """True als ``target`` een veilige redirect-bestemming is (open-redirect-preventie).

    Toegestaan: relatieve URLs, of absolute URLs op dezelfde host als het huidige
    request (session["next"] wordt gevuld met request.url, dus same-host absoluut
    moet blijven werken). Cross-host bestemmingen worden geweigerd.
    """
    if not target:
        return False
    candidate = target.replace("\\", "")  # browsers behandelen \ als /
    parsed = urlparse(candidate)
    if not parsed.netloc and not parsed.scheme:
        return True
    return parsed.scheme in ("http", "https") and parsed.netloc == urlparse(request.host_url).netloc


_BLOCKED_HTML = """<!doctype html>
<html lang="nl"><head><meta charset="utf-8"><title>Toegang geweigerd</title>
<style>html,body{height:100%;margin:0}body{font-family:system-ui,sans-serif;background:#0f1115;
color:#e6e6e6;display:flex;align-items:center;justify-content:center}.b{text-align:center;
max-width:480px;padding:2rem}.icon{font-size:3rem;margin-bottom:1rem}h1{font-size:1.25rem;
margin:0 0 .75rem}p{margin:0 0 1.5rem;opacity:.7;line-height:1.6}
a{color:#5865F2;text-decoration:none}</style></head>
<body><div class="b"><div class="icon">🚫</div>
<h1>Toegang geweigerd</h1>
<p>{{ message|e }}</p>
<p><a href="/auth/logout">Uitloggen</a></p>
</div></body></html>"""

# §6 laag-2: pagina die de host-NUI (FiveM-iframe) via postMessage vraagt om (her)authenticatie.
# Wordt geserveerd binnen het iframe i.p.v. een in-CEF redirect naar de auth-server.
_EMBEDDED_AUTH_SIGNAL_HTML = """<!doctype html>
<html lang="nl"><head><meta charset="utf-8"><title>Verificatie vereist</title>
<style>html,body{height:100%;margin:0}body{font-family:system-ui,sans-serif;background:#0f1115;
color:#e6e6e6;display:flex;align-items:center;justify-content:center}.b{text-align:center;opacity:.85}
.s{width:28px;height:28px;border:3px solid #333;border-top-color:#5865F2;border-radius:50%;
margin:0 auto 14px;animation:r 1s linear infinite}@keyframes r{to{transform:rotate(360deg)}}</style></head>
<body><div class="b"><div class="s"></div><p>Aanvullende verificatie vereist…</p></div>
<script>(function(){var m={{ payload_json|safe }};
try{(window.parent||window).postMessage(m,'*');}catch(e){}
try{if(window.top&&window.top!==window){window.top.postMessage(m,'*');}}catch(e){}})();</script>
</body></html>"""


def _post_logout_form(action: str, params: dict):
    """
    Render an auto-submitting HTML POST form for RP-Initiated Logout.

    Uses POST instead of a GET redirect so that large JWTs (id_token_hint)
    remain in the request body and do not exceed the server's URL length limit.
    """
    fields = "".join(
        f'<input type="hidden" name="{escape(k)}" value="{escape(v)}">' for k, v in params.items()
    )
    html = (
        "<!DOCTYPE html><html><head><title>Uitloggen...</title></head><body>"
        f'<form id="f" method="post" action="{escape(action)}">{fields}</form>'
        '<script>document.getElementById("f").submit();</script>'
        "</body></html>"
    )
    response = make_response(html)
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    return response


class RPRAuth:
    """
    Main class for RPR OAuth integration.

    Initialises OAuth 2.0 / OpenID Connect authentication with the
    Roleplay Reality Auth Server and registers all required routes.
    """

    def __init__(
        self, app=None, user_class=OAuthUser, login_view="auth.login", auto_register_routes=True
    ):
        """
        Initialize RPR OAuth.

        Args:
            app: Flask application instance
            user_class: Custom user class (moet OAuthUser extenden)
            login_view: View name for login redirect
            auto_register_routes: Automatically register auth routes
        """
        self.user_class = user_class
        self.login_view = login_view
        self.auto_register_routes = auto_register_routes
        self.oauth = None
        self.auth_server = None

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """
        Initialize extension with Flask app.

        Args:
            app: Flask application instance
        """
        # Valideer vereiste configuratie
        required_config = [
            "OAUTH_BASE_URL",
            "OAUTH_CLIENT_ID",
            "OAUTH_CLIENT_SECRET",
            "OAUTH_REDIRECT_URI",
        ]

        for key in required_config:
            if key not in app.config:
                raise ValueError(f"Missing required config: {key}")

        # Stel defaults in
        app.config.setdefault("OAUTH_SCOPE", "openid profile email")
        app.config.setdefault("OAUTH_AUTO_VALIDATE", True)
        # Trek bij /auth/logout de sessietokens server-naar-server in (RFC 7009),
        # zodat ze ook sterven als de gebruiker de end_session-bevestiging op de
        # auth server nooit afmaakt. Best-effort: falen breekt de logout niet.
        app.config.setdefault("OAUTH_REVOKE_ON_LOGOUT", True)
        app.config.setdefault("OAUTH_PARTITIONED_COOKIES", True)
        app.config.setdefault("OAUTH_TIMEOUT", 10)
        app.config.setdefault("OAUTH_TOKEN_REVALIDATE_INTERVAL", 300)
        # Session bootstrap-route (/auth/session-bootstrap): zet een first-party sessie op
        # vanuit een vooraf gemunt access token (RFC 8693 token-exchange resultaat).
        # Standaard AAN zodat onze applicaties direct in FiveM (NUI-iframe) beschikbaar zijn.
        # Zet expliciet op False als je deze trusted out-of-band bearer-flow niet wilt.
        app.config.setdefault("OAUTH_ENABLE_SESSION_BOOTSTRAP", True)
        # OIDC Back-Channel Logout 1.0 (ontvanger): registreer /auth/backchannel-logout, waar
        # de auth server een ondertekend logout token naartoe POST bij centrale logout/ban/REVIEW.
        # Vereist een Redis (OAUTH_LOGOUT_REDIS_URL of de Flask-Session SESSION_REDIS) om álle
        # sessies van een gebruiker te kunnen beëindigen (niet alleen die van het huidige request).
        app.config.setdefault("OAUTH_ENABLE_BACKCHANNEL_LOGOUT", True)
        app.config.setdefault("OAUTH_LOGOUT_REDIS_URL", None)
        # Levensduur van de "uitgelogd"-markering in Redis; moet elke sessie overleven die op het
        # moment van de logout bestond. Default: ruim boven de sessie-levensduur.
        app.config.setdefault("OAUTH_LOGOUT_MARKER_TTL", 86400)
        # Shared Signals Framework (RFC 8417 SET + RFC 8935 push): registreer /auth/ssf, de
        # gedeelde ontvanger voor ondertekende Security Event Tokens (account-disabled/-purged,
        # session-revoked, credential-change). Opvolger van de verwijderde ad-hoc /auth/webhook/*. De
        # handtekening is de auth (zelfde JWKS als de id_tokens); OAUTH_SSF_AUDIENCE is de
        # verwachte `aud` in de SET (default = OAUTH_CLIENT_ID). Optionele per-event callbacks:
        # OAUTH_ON_ACCOUNT_PURGED/_DISABLED/_SESSION_REVOKED/_CREDENTIAL_CHANGE — elk (sub, payload).
        app.config.setdefault("OAUTH_ENABLE_SSF", True)
        app.config.setdefault("OAUTH_SSF_AUDIENCE", None)
        # SCIM 2.0-ontvanger (RFC 7643/7644): registreer /scim/v2/Users[/<id>], waarop de
        # auth server user-provisioning pusht (PUT = upsert, POST = create-fallback, DELETE;
        # GET levert data voor de AVG-export). Auth: Bearer M2M-token, gevalideerd via
        # userinfo/introspectie (get_userinfo_from_token, incl. RFC 8707 audience-check) +
        # de permissie OAUTH_SCIM_PERMISSION. Standaard UIT — provisioning is pas zinvol
        # als de app de callbacks implementeert:
        #   OAUTH_ON_SCIM_SYNC(user_id: str, resource: dict)  — user aangemaakt/gewijzigd
        #   OAUTH_ON_SCIM_DELETE(user_id: str)                — user verwijderd (idempotent)
        #   OAUTH_ON_SCIM_GET(user_id: str) -> dict | None    — optioneel: AVG-exportdata
        app.config.setdefault("OAUTH_ENABLE_SCIM", False)
        app.config.setdefault("OAUTH_SCIM_PERMISSION", "auth.scim.provision")

        # DPoP (RFC 9449, sender-constrained tokens). Presenteert een client een token via het
        # `Authorization: DPoP <token>`-scheme + een `DPoP:`-proofheader, dan valideert de
        # decorator-laag de proof lokaal (tegen deze request-URL/-methode + ath) en eist dat de
        # proof-thumbprint matcht met de `cnf.jkt` uit introspectie. Staat OAUTH_REQUIRE_DPOP aan,
        # dan worden gewone Bearer-tokens geweigerd (401 met een DPoP-challenge) — bedoeld voor
        # resource servers die uitsluitend sender-constrained API-/MCP-clients bedienen. Default
        # UIT: Bearer blijft de standaard (o.a. sessie-cookie- en FiveM-consumers). De optionele
        # jti-replaycache hergebruikt de back-channel-logout-Redis (OAUTH_LOGOUT_REDIS_URL).
        app.config.setdefault("OAUTH_REQUIRE_DPOP", False)

        # Voor CHIPS/Partitioned cookie support moet de session cookie SameSite=None; Secure
        # zijn, anders wordt het niet meegestuurd bij cross-site OAuth redirects (bijv. FiveM NUI).
        # Zonder dit raakt Authlib de opgeslagen OAuth state kwijt → mismatching_state error.
        if app.config.get("OAUTH_PARTITIONED_COOKIES", True):
            app.config.setdefault("SESSION_COOKIE_SAMESITE", "None")
            app.config.setdefault("SESSION_COOKIE_SECURE", True)

        # Optionele Flask-Session integratie voor server-side sessie opslag.
        # Voorkomt te grote session cookies die de OAuth state kunnen verliezen
        # (mismatching_state). Configureer SESSION_TYPE in Flask config om in te schakelen.
        # Sla initialisatie over als de app Flask-Session al heeft geïnitialiseerd.
        if (
            FLASK_SESSION_AVAILABLE
            and app.config.get("SESSION_TYPE")
            and not isinstance(app.session_interface, _ServerSideSessionInterface)
        ):
            FlaskSession(app)
            logger.info("Flask-Session geïnitialiseerd (server-side sessie opslag actief)")

        # Initialiseer OAuth
        self.oauth = OAuth(app)
        self.auth_server = self.oauth.register(
            "auth_server",
            client_id=app.config["OAUTH_CLIENT_ID"],
            client_secret=app.config["OAUTH_CLIENT_SECRET"],
            server_metadata_url=(
                f"{app.config['OAUTH_BASE_URL']}/.well-known/openid-configuration"
            ),
            client_kwargs={
                "scope": app.config["OAUTH_SCOPE"],
                "timeout": app.config["OAUTH_TIMEOUT"],
            },
        )

        logger.info("RPR OAuth geïnitialiseerd (session-based)")

        # Registreer auth routes
        if self.auto_register_routes:
            self._register_routes(app)

        # Registreer error handlers
        self._register_error_handlers(app)

        # RFC 9728: protected-resource-metadata op root-niveau (altijd, los van
        # auto_register_routes — dit is de discovery van de resource server zelf).
        self._register_metadata_routes(app)

        # Registreer Partitioned cookie support voor iframe/CHIPS
        if app.config.get("OAUTH_PARTITIONED_COOKIES", False):
            self._register_partitioned_cookie_handler(app)

        # Registreer framing-headers voor embedded (FiveM NUI) sessies
        self._register_embedded_frame_handler(app)

        # OIDC Back-Channel Logout: beëindig de sessie bij een central logout/ban-event.
        # Vóór _validate_session_token zodat een uitgelogde sessie meteen sneuvelt.
        app.before_request(self._enforce_backchannel_logout)

        # Periodieke hervalidatie van het sessie-token bij de auth server
        app.before_request(self._validate_session_token)

        # Store instance op app
        app.extensions = getattr(app, "extensions", {})
        app.extensions["rpr_auth"] = self

    def _handle_login(self):
        """Start OAuth login flow."""
        redirect_uri = current_app.config["OAUTH_REDIRECT_URI"]

        # Check if 2FA is required for this app
        require_2fa = current_app.config.get("OAUTH_REQUIRE_2FA", False)

        # Add acr_values parameter if 2FA is required (OAuth standard)
        if require_2fa:
            return self.auth_server.authorize_redirect(
                redirect_uri, acr_values="mfa"  # Request multi-factor authentication
            )

        return self.auth_server.authorize_redirect(redirect_uri)

    @csrf_exempt
    def _handle_callback(self):
        """
        OAuth callback handler: exchanges the authorization code for tokens.

        Stores userinfo, permissions, groups and the ACR claim in the session.
        Blocks users with status REVIEW or BANNED immediately at login.
        Redirects to session['next'] or 'index' after a successful login.
        """
        try:
            # Debug: log session keys and incoming state for mismatching_state diagnosis
            incoming_state = request.args.get("state", "")
            state_key = f"_state_auth_server_{incoming_state}"
            session_keys = list(session.keys()) if session else []
            has_state_key = state_key in session
            logger.info(
                f"[callback] incoming state={incoming_state!r} "
                f"state_key_found={has_state_key} "
                f"session_keys={session_keys}"
            )

            # Haal token op
            token = self.auth_server.authorize_access_token()
            # Gebruik userinfo claims uit het ID token (al opgehaald door authorize_access_token).
            # Dit voorkomt een extra HTTP round-trip naar de userinfo endpoint die Gunicorn
            # worker timeouts kan veroorzaken als de auth server traag reageert.
            userinfo = token.get("userinfo") or self.auth_server.userinfo()

            # Blokkeer REVIEW en BANNED gebruikers direct bij login (defense-in-depth)
            user_status = userinfo.get("user_status", "")
            if user_status in ("REVIEW", "BANNED"):
                _blocked_messages = {
                    "REVIEW": "Je account is geblokkeerd. Neem zo snel mogelijk contact op met jouw teammanager voor een gesprek.",
                    "BANNED": "Je account is permanent non-actief gesteld. Neem contact op met jouw teammanager.",
                }
                logger.warning(
                    f"Login geweigerd voor {userinfo.get('email')} met status {user_status!r}"
                )
                session.clear()
                session["oauth_blocked_message"] = _blocked_messages[user_status]
                return redirect(url_for("auth.blocked"))

            # Vul de sessie met token, userinfo, permissions, groups en ACR
            self._populate_session(token, userinfo)

            # Redirect naar next of home (open-redirect-preventie). Normaliseer
            # backslashes vóór zowel de check als de redirect, zodat de gevalideerde
            # waarde exact de waarde is die naar redirect() gaat (geen \\evil.com-bypass).
            next_page = (session.pop("next", None) or "").replace("\\", "")
            if not next_page or not _is_safe_redirect(next_page):
                next_page = url_for("index")
            return redirect(next_page)

        except MismatchingStateError:
            # OAuth state mismatch — sessie verlopen, meerdere tabs, of cookie niet meegestuurd.
            # Bewaar de next-URL zodat de gebruiker na een nieuwe login op de juiste plek belandt.
            next_url = session.get("next")
            session.clear()
            logger.warning("[callback] OAuth state mismatch — sessie gecleard, opnieuw inloggen")
            if next_url:
                session["next"] = next_url
            return redirect(url_for("auth.login"))

        except Exception as e:
            logger.error(f"OAuth callback error: {e}", exc_info=True)
            session.clear()
            return redirect(url_for("auth.login"))

    def _populate_session(self, token: dict, userinfo: dict):
        """
        Populate the Flask session from an OAuth token and userinfo claims.

        Shared by `_handle_callback` and `_handle_session_bootstrap`. Stores the
        token, the mapped userinfo (with backwards compatible field mappings),
        permissions, groups and the 2FA/ACR status in the session.

        Note: this does NOT perform the REVIEW/BANNED status block — callers
        must apply that check before calling this method.

        Args:
            token: The OAuth token dict (must contain at least 'access_token').
            userinfo: The userinfo/ID-token claims dict (must contain 'sub').
        """
        # Sla token op in session
        session["oauth_token"] = token

        # Sla alle userinfo claims op, met backwards compatible mappings
        session["oauth_user"] = {
            "oauth_id": userinfo["sub"],
            "email": userinfo.get("email", ""),
            "voornaam": userinfo.get("given_name", "") or userinfo.get("firstname", ""),
            "achternaam": userinfo.get("family_name", "") or userinfo.get("lastname", ""),
            "teamspeak_id": userinfo.get("teamspeak_id", ""),
            "discord_id": userinfo.get("discord_id", ""),
            "ingame_phone": userinfo.get("ingame_phone", ""),
            "fivem_role": userinfo.get("fivem_role", ""),
            "name_prefix": userinfo.get("name_prefix", ""),
            "email_verified": userinfo.get("email_verified", False),
            "user_type": userinfo.get("user_type", ""),
            "user_status": userinfo.get("user_status", ""),
        }
        session["oauth_permissions"] = userinfo.get("permissions", [])
        session["oauth_groups"] = userinfo.get("groups", [])

        # Sla 2FA status op (check both legacy twofa_validated and new acr claim)
        twofa_validated = token.get("twofa_validated", False) or userinfo.get(
            "twofa_validated", False
        )

        # Check ACR (Authentication Context Class Reference) claim from ID token
        # This is the OAuth standard way to check authentication level
        acr = userinfo.get("acr", "pwd")
        if acr in ["mfa", "phr"]:
            twofa_validated = True

        session["twofa_validated"] = twofa_validated
        session["acr"] = acr
        session["_token_validated_at"] = time.time()
        # Stabiel login-moment (NIET herzet bij hervalidatie): de back-channel-logout-markering
        # vergelijkt hiertegen — een logout-event ná dit moment beëindigt de sessie.
        session["_login_at"] = time.time()
        session.modified = True  # Forceer sessie-opslag in Redis/filesystem

        logger.info(
            "User %s succesvol ingelogd (2FA: %s, ACR: %s)",
            userinfo.get("email"),
            twofa_validated,
            acr,
        )

    def _userinfo_from_token(self, token: dict) -> dict:
        """
        Resolve userinfo claims from an OAuth token.

        Prefers the `userinfo` claims already embedded in the token (parsed from
        the ID token) to avoid an extra HTTP round-trip. Falls back to the
        /oauth/userinfo endpoint using the access token when not present.

        Args:
            token: The OAuth token dict.

        Returns:
            dict: The userinfo claims.
        """
        userinfo = token.get("userinfo")
        if userinfo:
            return userinfo

        access_token = token.get("access_token")
        response = requests.get(
            f"{current_app.config['OAUTH_BASE_URL']}/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=current_app.config.get("OAUTH_TIMEOUT", 10),
        )
        response.raise_for_status()
        return response.json()

    @csrf_exempt
    def _handle_session_bootstrap(self):
        """
        Establish a first-party session from a pre-minted bearer access token.

        Unlike `/auth/login`, this route does NOT rely on a Flask-session
        `state`/PKCE pair: the access token is minted out-of-band by a trusted
        server (e.g. a FiveM phone backend) via RFC 8693 Token Exchange and
        scoped to this app's audience. The route validates the token at
        /oauth/userinfo and then populates a normal session — no code exchange,
        no client secret, no extra token-endpoint round-trip.

        This lets a FiveM phone NUI load the app in an iframe and be
        auto-logged-in as the correct user, without an interactive redirect.

        Enabled by default (so our apps work inside FiveM out of the box); set
        OAUTH_ENABLE_SESSION_BOOTSTRAP=False to disable.

        Registered at GET/POST /auth/session-bootstrap.

        Access token (in order of preference):
            POST form field `access_token`, then an `Authorization: Bearer <token>`
            header, then the `access_token` query param (deprecated — token in URL).

        Params:
            next: A safe relative path to redirect to afterwards (optional).
            id_token: The OIDC ID token (optional, POST form only).

        The access token is short-lived (enforced by the auth server) and IS the
        credential — it was already minted for this app's audience.
        """
        # Guard: standaard aan (default True); expliciet op False zet 'm uit.
        if not current_app.config.get("OAUTH_ENABLE_SESSION_BOOTSTRAP", True):
            abort(404)

        # Haal het access token op: POST form (voorkeur) → Bearer header → query (afgeraden)
        access_token = request.form.get("access_token")
        if not access_token:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                access_token = auth_header[len("Bearer ") :].strip()
        if not access_token:
            # Query-parameter blijft ondersteund voor bestaande consumers, maar is
            # afgeraden: een token in de URL lekt naar logs/Referer/history. Migreer
            # naar POST-form of Authorization: Bearer.
            access_token = request.args.get("access_token")
            if access_token:
                logger.warning(
                    "session-bootstrap access_token via query-parameter (afgeraden) — "
                    "gebruik POST-form of Bearer-header"
                )

        if not access_token:
            abort(400)

        next_url = request.form.get("next") or request.args.get("next")
        id_token = request.form.get("id_token")

        timeout = current_app.config.get("OAUTH_TIMEOUT", 10)

        try:
            # Valideer het token door de userinfo op te halen met de bearer.
            # Een geldige 200 bewijst dat het token bestaat, niet verlopen/gerevokeerd is.
            response = requests.get(
                f"{current_app.config['OAUTH_BASE_URL']}/oauth/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=timeout,
            )
            response.raise_for_status()
            userinfo = response.json()
        except Exception as e:
            # Wees robuust: nooit een stacktrace naar de iframe lekken.
            # Val terug op interactieve login.
            logger.error("Session bootstrap error: %s", e, exc_info=True)
            return redirect(url_for(self.login_view))

        # Blokkeer REVIEW en BANNED gebruikers direct (defense-in-depth)
        user_status = userinfo.get("user_status", "")
        if user_status in ("REVIEW", "BANNED"):
            _blocked_messages = {
                "REVIEW": "Je account is geblokkeerd. Neem zo snel mogelijk contact op met jouw teammanager voor een gesprek.",
                "BANNED": "Je account is permanent non-actief gesteld. Neem contact op met jouw teammanager.",
            }
            logger.warning(
                "Session bootstrap geweigerd voor %s met status %r",
                userinfo.get("email"),
                user_status,
            )
            session.clear()
            session["oauth_blocked_message"] = _blocked_messages[user_status]
            return redirect(url_for("auth.blocked"))

        # Bouw een minimaal token-dict en vul de sessie
        token = {"access_token": access_token}
        if id_token:
            token["id_token"] = id_token
        self._populate_session(token, userinfo)

        # Markeer deze sessie als "embedded" (draait in een FiveM NUI-iframe). Hierdoor
        # signaleert §6 laag-2 step-up/herauth via postMessage naar de host-NUI i.p.v. een
        # in-CEF redirect naar de auth-server (waar geen sessie is en passkeys niet werken).
        session["rpr_embedded"] = True
        session.modified = True

        # Redirect naar een veilige next, anders naar de app-root.
        # code=303 zodat een POST een GET wordt bij de iframe-navigatie.
        # Inline open-redirect check: CodeQL herkent de sanitizer alleen als
        # netloc+scheme op dezelfde variabele gecheckt worden die naar redirect() gaat.
        if next_url:
            next_url = next_url.replace("\\", "")  # browsers behandelen \ als /
            _p = urlparse(next_url)
            if not _p.netloc and not _p.scheme:
                return redirect(next_url, code=303)
        return redirect("/", code=303)

    def _handle_blocked(self):
        """Toon een 'account geblokkeerd' pagina en wis de sessie volledig.

        Wordt aangeroepen na een redirect naar /auth/blocked, die door
        _handle_callback en _handle_session_bootstrap wordt gestuurd wanneer
        een BANNED of REVIEW gebruiker probeert in te loggen. Leest het bericht
        uit session["oauth_blocked_message"] zodat het maar één request leven heeft.
        """
        message = session.pop(
            "oauth_blocked_message",
            "Je account heeft geen toegang. Neem contact op met jouw teammanager.",
        )
        session.clear()
        html = render_template_string(_BLOCKED_HTML, message=message)
        resp = make_response(html, 403)
        resp.headers["Cache-Control"] = "no-store"
        return resp

    def _revoke_tokens_at_server(self, token):
        """Best-effort RFC 7009-revocatie van de sessietokens bij logout.

        De browser-redirect naar end_session is niet gegarandeerd: de auth server
        toont daar eerst een bevestigingspagina, en wie die sluit laat zijn refresh
        token (30 dagen) gewoon doorleven. Door hier server-naar-server in te
        trekken zijn de tokens hoe dan ook dood zodra de gebruiker op uitloggen
        klikt. Fouten worden gelogd maar breken de logout nooit (best-effort);
        de auth server trekt na de end_session-bevestiging ook zelf in (idempotent).
        """
        if not current_app.config.get("OAUTH_REVOKE_ON_LOGOUT", True):
            return
        try:
            metadata = self.auth_server.load_server_metadata()
            revocation_endpoint = metadata.get("revocation_endpoint")
        except Exception as e:
            logger.warning("Logout: kon server metadata niet laden voor token-revocatie: %s", e)
            return
        if not revocation_endpoint:
            return

        # Eén revocatie volstaat: refresh en access token horen bij dezelfde
        # token-registratie op de auth server (revoke van de één raakt de ander).
        # Prefereer het refresh token — dat leeft het langst.
        value = token.get("refresh_token") or token.get("access_token")
        if not value:
            return
        hint = "refresh_token" if token.get("refresh_token") else "access_token"
        try:
            resp = requests.post(
                revocation_endpoint,
                data={"token": value, "token_type_hint": hint},
                auth=(
                    current_app.config["OAUTH_CLIENT_ID"],
                    current_app.config.get("OAUTH_CLIENT_SECRET") or "",
                ),
                timeout=current_app.config.get("OAUTH_TIMEOUT", 10),
            )
            if resp.status_code == 200:
                logger.info("Logout: sessietokens ingetrokken op de auth server (%s)", hint)
            else:
                # RFC 7009 §2.2: 200 is het enige succes; al het andere loggen.
                logger.warning("Logout: token-revocatie gaf HTTP %s", resp.status_code)
        except Exception as e:  # netwerkfout → logout gaat gewoon door
            logger.warning("Logout: token-revocatie mislukt: %s", e)

    def _handle_logout(self):
        """Logout: clear local session and initiate RP-Initiated Logout on the auth server."""
        # Bewaar het ID token vóór session.clear() voor de id_token_hint
        token = session.get("oauth_token", {})
        id_token = token.get("id_token")

        # Trek de tokens server-naar-server in vóór de sessie (en daarmee de
        # tokens) verdwijnt — de end_session-redirect hierna is best-effort.
        self._revoke_tokens_at_server(token)

        session.clear()
        logger.info("User uitgelogd (lokale sessie gecleard)")

        # RP-Initiated Logout (OpenID Connect): stuur gebruiker naar end_session_endpoint
        # zodat de auth server de sessie daar ook invalideert.
        try:
            metadata = self.auth_server.load_server_metadata()
            end_session_endpoint = metadata.get("end_session_endpoint")
        except Exception as e:
            logger.warning(f"Kon server metadata niet laden voor logout: {e}")
            end_session_endpoint = None

        if end_session_endpoint:
            post_logout_redirect_uri = current_app.config.get("OAUTH_POST_LOGOUT_REDIRECT_URI")
            # client_id is RECOMMENDED (OIDC RP-Initiated Logout 1.0 §2) — geeft de
            # auth server ook zonder (verlopen) id_token_hint een client-context.
            params = {"client_id": current_app.config.get("OAUTH_CLIENT_ID")}
            if id_token:
                params["id_token_hint"] = id_token
            if post_logout_redirect_uri:
                params["post_logout_redirect_uri"] = post_logout_redirect_uri

            if params:
                # Gebruik POST form submission: id_token_hint kan te groot zijn voor een GET URL
                # (JWT bevat alle claims → snel >4 KB). POST houdt de token in de body.
                logger.info(f"RP-Initiated Logout via POST naar: {end_session_endpoint}")
                return _post_logout_form(end_session_endpoint, params)

            logger.info(f"Redirect naar end_session_endpoint: {end_session_endpoint}")
            return redirect(end_session_endpoint)

        # Fallback als auth server geen end_session_endpoint heeft
        return redirect(url_for("index"))

    # ------------------------------------------------------------------
    # OIDC Back-Channel Logout 1.0 (ontvanger)
    # ------------------------------------------------------------------
    @staticmethod
    def _bcl_key(sub):
        """Redis-sleutel voor de "uitgelogd"-markering van een gebruiker (sub)."""
        return f"rpr:bcl:logout:{sub}"

    def _logout_redis(self):
        """Redis-client voor de back-channel-logout-markeringen, of None.

        Voorkeur: expliciete ``OAUTH_LOGOUT_REDIS_URL``. Anders de Flask-Session
        ``SESSION_REDIS`` (als de app server-side sessies in Redis gebruikt). Zonder
        Redis kan alleen de sessie van het huidige request worden beëindigd.
        """
        if getattr(self, "_bcl_redis_resolved", False):
            return self._bcl_redis
        self._bcl_redis_resolved = True
        self._bcl_redis = None

        url = current_app.config.get("OAUTH_LOGOUT_REDIS_URL")
        if url and REDIS_AVAILABLE:
            try:
                self._bcl_redis = _redis_lib.from_url(url)
            except Exception as e:
                logger.error("BCL: kon OAUTH_LOGOUT_REDIS_URL niet verbinden: %s", e)
        elif current_app.config.get("SESSION_REDIS") is not None:
            # Hergebruik de bestaande Flask-Session Redis-client.
            self._bcl_redis = current_app.config.get("SESSION_REDIS")
        return self._bcl_redis

    def _get_as_jwks(self):
        """Haal (en cache) de JWKS van de auth server op als authlib-key-set."""
        from authlib.jose import JsonWebKey

        base = current_app.config["OAUTH_BASE_URL"]
        now = time.time()
        with _jwks_lock:
            entry = _jwks_cache.get(base)
            if entry and entry[1] > now:
                return entry[0]

        # Buiten de lock ophalen (netwerk).
        try:
            metadata = self.auth_server.load_server_metadata()
            jwks_uri = metadata.get("jwks_uri") or f"{base}/.well-known/jwks.json"
        except Exception:
            jwks_uri = f"{base}/.well-known/jwks.json"

        resp = requests.get(jwks_uri, timeout=current_app.config.get("OAUTH_TIMEOUT", 10))
        resp.raise_for_status()
        key_set = JsonWebKey.import_key_set(resp.json())

        with _jwks_lock:
            _jwks_cache[base] = (key_set, now + _JWKS_CACHE_TTL)
        return key_set

    def _validate_set(self, token, expected_aud):
        """Valideer een Security Event Token (RFC 8417); geef de claims-dict terug of None.

        Gedeelde validatie voor OIDC Back-Channel Logout logout tokens én SSF-events (CAEP/
        RISC): geldige RS256-handtekening (auth-server-JWKS), ``iss`` = de auth server, ``aud``
        bevat ``expected_aud``, en GÉÉN ``nonce`` (verboden in een SET). Controleert NIET welk
        event erin zit — dat doet de aanroeper, afhankelijk van het endpoint.
        """
        from authlib.jose import jwt as jose_jwt
        from authlib.jose.errors import JoseError

        try:
            key_set = self._get_as_jwks()
            claims = jose_jwt.decode(token, key_set)
            claims.validate()  # exp/iat/nbf indien aanwezig
        except JoseError as e:
            logger.warning("SET ongeldig (handtekening/claims): %s", e)
            return None
        except Exception as e:
            logger.warning("SET kon niet gevalideerd worden: %s", e)
            return None

        # iss moet de auth server zijn.
        try:
            issuer = self.auth_server.load_server_metadata().get("issuer")
        except Exception:
            issuer = current_app.config.get("OAUTH_BASE_URL")
        if issuer and claims.get("iss") != issuer:
            logger.warning("SET: iss %r != verwachte issuer %r", claims.get("iss"), issuer)
            return None

        # aud moet de verwachte audience bevatten (string of lijst).
        aud = claims.get("aud")
        aud_ok = aud == expected_aud or (isinstance(aud, (list, tuple)) and expected_aud in aud)
        if not aud_ok:
            # Geen waarden loggen: de aud komt uit het (nog onvertrouwde) token en de
            # verwachte audience is een config-waarde (CodeQL: config = gevoelig).
            logger.warning(
                "SET: aud bevat de verwachte audience (OAUTH_SSF_AUDIENCE/OAUTH_CLIENT_ID) niet"
            )
            return None

        # nonce is verboden in een SET (o.a. OIDC BCL §2.4).
        if "nonce" in claims:
            logger.warning("SET bevat een nonce (verboden)")
            return None

        return dict(claims)

    def _validate_logout_token(self, logout_token):
        """Valideer een OIDC Back-Channel Logout 1.0 logout token; geef de ``sub`` terug of None.

        Gebruikt de gedeelde ``_validate_set``-validatie (handtekening/iss/aud/nonce) en
        controleert daarna het backchannel-logout-event + ``sub`` (§2.6). ``aud`` = dit client_id.
        """
        client_id = current_app.config.get("OAUTH_CLIENT_ID")
        claims = self._validate_set(logout_token, expected_aud=client_id)
        if claims is None:
            return None

        # events-claim moet het backchannel-logout event bevatten.
        events = claims.get("events")
        if not isinstance(events, dict) or BACKCHANNEL_LOGOUT_EVENT not in events:
            logger.warning("BCL: events-claim mist het backchannel-logout event")
            return None

        sub = claims.get("sub")
        if not sub:
            logger.warning("BCL: logout token mist sub (sid-only wordt niet ondersteund)")
            return None
        return str(sub)

    def _mark_logged_out(self, sub):
        """Zet de "uitgelogd"-markering in Redis. True bij succes, False zonder Redis."""
        r = self._logout_redis()
        if r is None:
            return False
        try:
            ttl = int(current_app.config.get("OAUTH_LOGOUT_MARKER_TTL", 86400))
            r.setex(self._bcl_key(sub), ttl, str(time.time()))
            return True
        except Exception as e:
            logger.error("BCL: kon logout-markering niet zetten voor sub=%s: %s", sub, e)
            return False

    def _is_backchannel_logged_out(self):
        """True als de huidige sessie ná een back-channel-logout-event is (moet sterven)."""
        if "oauth_user" not in session:
            return False
        sub = str(session["oauth_user"].get("oauth_id") or "")
        if not sub:
            return False
        r = self._logout_redis()
        if r is None:
            return False
        try:
            raw = r.get(self._bcl_key(sub))
        except Exception as e:
            logger.error("BCL: kon logout-markering niet lezen: %s", e)
            return False
        if raw is None:
            return False
        try:
            marked_at = float(raw.decode() if isinstance(raw, bytes) else raw)
        except (ValueError, AttributeError):
            return True  # onleesbare markering → veiligheidshalve uitloggen
        # Alleen beëindigen als de logout ná het login-moment van deze sessie kwam.
        return marked_at >= (session.get("_login_at", 0) or 0)

    @csrf_exempt
    def _handle_backchannel_logout(self):
        """OIDC Back-Channel Logout 1.0 §2.5 endpoint: verwerk een logout token."""
        if not current_app.config.get("OAUTH_ENABLE_BACKCHANNEL_LOGOUT", True):
            abort(404)

        logout_token = request.form.get("logout_token")
        if not logout_token:
            return self._bcl_error("missing logout_token")

        sub = self._validate_logout_token(logout_token)
        if sub is None:
            return self._bcl_error("invalid logout_token")

        # Markeer de gebruiker als uitgelogd → al zijn sessies sterven bij hun volgende request.
        marked = self._mark_logged_out(sub)

        # Is het huidige request diezelfde gebruiker, wis dan meteen die sessie (best-effort).
        try:
            if "oauth_user" in session and str(session["oauth_user"].get("oauth_id")) == sub:
                session.clear()
        except Exception as e:
            # Best-effort: de logout-markering staat al; dit mag de 200 nooit blokkeren.
            logger.debug("BCL: kon huidige sessie niet direct wissen: %s", e, exc_info=True)

        if not marked:
            logger.error(
                "BCL ontvangen voor sub=%s maar geen Redis geconfigureerd — alleen het huidige "
                "request kon worden uitgelogd. Zet OAUTH_LOGOUT_REDIS_URL (of SESSION_REDIS) voor "
                "volledige logout van alle sessies.",
                sub,
            )

        logger.info("Back-channel logout verwerkt voor sub=%s", sub)
        resp = jsonify({"status": "ok"})
        resp.headers["Cache-Control"] = "no-store"
        return resp, 200

    def _bcl_error(self, message):
        """OIDC BCL §2.6 foutrespons (400, no-store)."""
        logger.warning("Back-channel logout geweigerd: %s", message)
        resp = jsonify({"error": "invalid_request", "error_description": message})
        resp.headers["Cache-Control"] = "no-store"
        return resp, 400

    # ------------------------------------------------------------------
    # Shared Signals Framework (RFC 8417 SET + RFC 8935 push) — gedeelde ontvanger
    # ------------------------------------------------------------------
    def _ssf_dispatch_callback(self, config_key, sub, event_payload):
        """Roep een optionele app-callback aan (fail-safe — mag de SSF-afhandeling nooit breken)."""
        cb = current_app.config.get(config_key)
        if cb is None:
            return
        try:
            cb(sub, event_payload)
        except Exception as e:
            logger.error("SSF-callback %s faalde voor sub=%s: %s", config_key, sub, e)

    @csrf_exempt
    def _handle_ssf_event(self):
        """Shared Signals Framework SET-ontvanger (RFC 8935 §2.1 push).

        Accepteert een ondertekende SET (``application/secevent+jwt`` in de body; valt terug op
        een ``set``/``logout_token`` form-veld), valideert 'm via ``_validate_set`` en routeert
        op event-type: elk bekend event beëindigt de sessie(s) van de gebruiker (mark_logged_out
        → re-auth bij het volgende request); ``account-purged``/``-disabled``/``credential-change``
        roepen daarnaast een optionele app-callback aan. Opvolger van de verwijderde ad-hoc
        ``/auth/webhook/*``-endpoints.
        """
        if not current_app.config.get("OAUTH_ENABLE_SSF", True):
            abort(404)

        # RFC 8935 §2.1: de SET staat als rauwe JWT in de body (application/secevent+jwt).
        # Val voor coulante verzenders terug op een form-veld (`set` of `logout_token`).
        ctype = (request.content_type or "").split(";")[0].strip().lower()
        if ctype == "application/secevent+jwt":
            token = request.get_data(as_text=True).strip()
        else:
            token = (request.form.get("set") or request.form.get("logout_token") or "").strip()
        if not token:
            return self._ssf_error("missing SET")

        expected_aud = current_app.config.get("OAUTH_SSF_AUDIENCE") or current_app.config.get(
            "OAUTH_CLIENT_ID"
        )
        claims = self._validate_set(token, expected_aud=expected_aud)
        if claims is None:
            return self._ssf_error("invalid SET")

        events = claims.get("events")
        if not isinstance(events, dict) or not events:
            return self._ssf_error("no events")

        # Subject: top-level `sub` of RFC 9493 `sub_id` (iss_sub-formaat) als fallback.
        sub = claims.get("sub")
        if not sub:
            sub_id = claims.get("sub_id")
            if isinstance(sub_id, dict):
                sub = sub_id.get("sub")
        sub = str(sub) if sub else None

        handled = []
        for event_uri, event_payload in events.items():
            if event_uri not in _SSF_KNOWN_EVENTS:
                logger.info("SSF: onbekend event-type genegeerd: %s", event_uri)
                continue
            handled.append(event_uri)
            cb_key = _SSF_CALLBACK_KEYS.get(event_uri)
            if cb_key:
                self._ssf_dispatch_callback(
                    cb_key, sub, event_payload if isinstance(event_payload, dict) else {}
                )

        if not handled:
            # Geldige SET, maar geen enkel bekend event → 400 zodat de verzender het merkt.
            return self._ssf_error("no known events")

        # Beëindig de sessie(s): markeer de gebruiker uitgelogd → sterft bij het volgende request.
        if sub:
            self._mark_logged_out(sub)
            # Is het huidige request diezelfde gebruiker, wis dan meteen die sessie (best-effort).
            try:
                if "oauth_user" in session and str(session["oauth_user"].get("oauth_id")) == sub:
                    session.clear()
            except Exception as e:
                # Best-effort: de logout-markering staat al; dit mag de 202 nooit blokkeren.
                logger.debug("SSF: kon huidige sessie niet direct wissen: %s", e, exc_info=True)

        logger.info("SSF-event verwerkt voor sub=%s events=%s", sub, handled)
        resp = jsonify({"status": "ok"})
        resp.headers["Cache-Control"] = "no-store"
        return resp, 202  # RFC 8935 §2.2: 202 Accepted

    def _ssf_error(self, message):
        """SSF foutrespons (400, no-store)."""
        logger.warning("SSF-event geweigerd: %s", message)
        resp = jsonify({"error": "invalid_request", "error_description": message})
        resp.headers["Cache-Control"] = "no-store"
        return resp, 400

    # ------------------------------------------------------------------ SCIM 2.0 (RFC 7644)

    def _scim_response(self, body, status):
        """SCIM-respons met het juiste mediatype (RFC 7644 §3.1)."""
        resp = jsonify(body)
        resp.mimetype = "application/scim+json"
        resp.headers["Cache-Control"] = "no-store"
        return resp, status

    def _scim_error(self, status, detail):
        """SCIM-foutrespons (RFC 7644 §3.12)."""
        if status >= 500:
            logger.error("SCIM-request mislukt (%s): %s", status, detail)
        else:
            logger.warning("SCIM-request geweigerd (%s): %s", status, detail)
        return self._scim_response(
            {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "status": str(status),
                "detail": detail,
            },
            status,
        )

    def _scim_guard(self):
        """Toegangscontrole voor de SCIM-routes.

        Vereist een Bearer M2M-token dat via userinfo/introspectie valideert (inclusief de
        RFC 8707 audience-check uit ``get_userinfo_from_token``) én de provisioning-permissie
        draagt (``OAUTH_SCIM_PERMISSION``, default ``auth.scim.provision`` — de permissie van
        de scim-worker op de auth server). Returnt None als het request door mag, anders een
        foutrespons.
        """
        if not current_app.config.get("OAUTH_ENABLE_SCIM", False):
            abort(404)
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            resp, status = self._scim_error(401, "Bearer-token vereist")
            resp.headers["WWW-Authenticate"] = 'Bearer error="invalid_token"'
            return resp, status
        info = get_userinfo_from_token(auth_header[7:].strip())
        if info is None:
            resp, status = self._scim_error(
                401, "token ongeldig of voor een andere resource server"
            )
            resp.headers["WWW-Authenticate"] = 'Bearer error="invalid_token"'
            return resp, status
        permission = current_app.config.get("OAUTH_SCIM_PERMISSION", "auth.scim.provision")
        if permission not in (info.get("permissions") or []):
            # Permissienaam niet interpoleren: config-waarde in detail zou ook gelogd
            # worden (CodeQL: config = gevoelig); de sleutelnaam volstaat.
            return self._scim_error(
                403, "vereiste provisioning-permissie (OAUTH_SCIM_PERMISSION) ontbreekt"
            )
        return None

    @csrf_exempt
    def _handle_scim_users_create(self):
        """POST /scim/v2/Users — create (RFC 7644 §3.3; fallback van de PUT-upsert)."""
        denied = self._scim_guard()
        if denied is not None:
            return denied
        return self._scim_upsert(None, created=True)

    @csrf_exempt
    def _handle_scim_user(self, user_id):
        """GET/PUT/DELETE /scim/v2/Users/<user_id> — de per-user provisioning-operaties.

        Contract met de RPR-API scim-worker: PUT is een **upsert** (bestaat de gebruiker
        lokaal nog niet, maak 'm dan aan — de worker hoeft dan nooit op POST terug te
        vallen), DELETE is idempotent (al weg = ook goed) en GET voedt de AVG-export.
        """
        denied = self._scim_guard()
        if denied is not None:
            return denied
        if request.method == "PUT":
            return self._scim_upsert(str(user_id), created=False)
        if request.method == "DELETE":
            return self._scim_delete(str(user_id))
        return self._scim_get(str(user_id))

    def _scim_upsert(self, user_id, created):
        """Gedeelde verwerking van PUT (upsert) en POST (create): app-callback + echo."""
        resource = request.get_json(silent=True)
        if not isinstance(resource, dict):
            return self._scim_error(400, "JSON-body met een SCIM User-resource vereist")
        user_id = user_id or str(resource.get("externalId") or "")
        if not user_id:
            return self._scim_error(400, "externalId (POST) of /Users/<id> (PUT) vereist")
        cb = current_app.config.get("OAUTH_ON_SCIM_SYNC")
        if cb is None:
            return self._scim_error(501, "OAUTH_ON_SCIM_SYNC niet geconfigureerd")
        try:
            cb(user_id, resource)
        except Exception:
            # 5xx → de scim-worker requeuet en probeert het opnieuw; details alleen
            # server-side loggen (geen exception-informatie naar de client).
            logger.exception("SCIM sync-callback faalde voor user=%s", user_id)
            return self._scim_error(500, "verwerking mislukt in het doelsysteem")
        body = dict(resource)
        body["id"] = user_id
        logger.info("SCIM %s verwerkt voor user=%s", "create" if created else "sync", user_id)
        return self._scim_response(body, 201 if created else 200)

    def _scim_delete(self, user_id):
        """DELETE-verwerking: app-callback; idempotent per RFC 7644 §3.6."""
        cb = current_app.config.get("OAUTH_ON_SCIM_DELETE")
        if cb is None:
            return self._scim_error(501, "OAUTH_ON_SCIM_DELETE niet geconfigureerd")
        try:
            cb(user_id)
        except Exception:
            logger.exception("SCIM delete-callback faalde voor user=%s", user_id)
            return self._scim_error(500, "verwijdering mislukt in het doelsysteem")
        logger.info("SCIM delete verwerkt voor user=%s", user_id)
        return "", 204

    def _scim_get(self, user_id):
        """GET-verwerking: optionele app-callback levert de (AVG-export)data; anders 404."""
        cb = current_app.config.get("OAUTH_ON_SCIM_GET")
        if cb is None:
            return self._scim_error(404, "geen exportdata beschikbaar op dit systeem")
        try:
            data = cb(user_id)
        except Exception:
            logger.exception("SCIM get-callback faalde voor user=%s", user_id)
            return self._scim_error(500, "opvragen mislukt in het doelsysteem")
        if data is None:
            return self._scim_error(404, "gebruiker onbekend op dit systeem")
        return self._scim_response(data, 200)

    def _enforce_backchannel_logout(self):
        """before_request: beëindig de sessie als er een back-channel-logout-event was.

        Werkt voor zowel cookie- als server-side sessies: bij het volgende request van de
        gebruiker wordt de sessie gewist. Idle sessies (geen requests) doen niets kwaads en
        vervallen bij hun eigen expiry.
        """
        if not current_app.config.get("OAUTH_ENABLE_BACKCHANNEL_LOGOUT", True):
            return None
        if "oauth_user" not in session:
            return None
        # Auth-routes overslaan (voorkomt redirect-loops), net als _validate_session_token.
        if request.endpoint and request.endpoint.startswith("auth."):
            return None
        if request.headers.get("Authorization", "").startswith("Bearer "):
            return None
        if not self._is_backchannel_logged_out():
            return None
        return self._reauth_or_redirect("Sessie beëindigd door back-channel logout")

    def _register_routes(self, app):
        """
        Register auth Blueprint with routes.

        Args:
            app: Flask application instance
        """
        auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

        auth_bp.add_url_rule("/login", "login", self._handle_login)
        auth_bp.add_url_rule("/callback", "callback", self._handle_callback)
        auth_bp.add_url_rule("/logout", "logout", self._handle_logout, methods=["GET", "POST"])
        auth_bp.add_url_rule(
            "/session-bootstrap",
            "session_bootstrap",
            self._handle_session_bootstrap,
            methods=["GET", "POST"],
        )
        auth_bp.add_url_rule(
            "/backchannel-logout",
            "backchannel_logout",
            self._handle_backchannel_logout,
            methods=["POST"],
        )
        auth_bp.add_url_rule(
            "/ssf",
            "ssf_event",
            self._handle_ssf_event,
            methods=["POST"],
        )
        auth_bp.add_url_rule(
            "/blocked",
            "blocked",
            self._handle_blocked,
        )

        app.register_blueprint(auth_bp)

        # SCIM 2.0-ontvanger (RFC 7644) op /scim/v2 — altijd geregistreerd, maar de handlers
        # geven 404 zolang OAUTH_ENABLE_SCIM uit staat (zelfde patroon als /auth/ssf).
        scim_bp = Blueprint("scim", __name__, url_prefix="/scim/v2")
        scim_bp.add_url_rule(
            "/Users",
            "users_create",
            self._handle_scim_users_create,
            methods=["POST"],
        )
        scim_bp.add_url_rule(
            "/Users/<user_id>",
            "user",
            self._handle_scim_user,
            methods=["GET", "PUT", "DELETE"],
        )
        app.register_blueprint(scim_bp)

        logger.info("Auth routes geregistreerd")

    def _handle_protected_resource_metadata(self):
        """OAuth 2.0 Protected Resource Metadata (RFC 9728 §2).

        Config-gedreven discovery-document zodat een MCP-/OAuth-client bij een 401
        (zie de ``WWW-Authenticate: Bearer resource_metadata="..."``-header) ontdekt welke
        authorization server en audience bij deze resource server horen. Bevat geen secrets;
        publiek opvraagbaar.

        Velden:
            - ``resource``: ``OAUTH_RESOURCE_ID`` (canonieke resource-URI) of de request-host.
            - ``authorization_servers``: ``[OAUTH_BASE_URL]``.
            - ``scopes_supported``: ``OAUTH_RESOURCE_SCOPES_SUPPORTED`` of, bij afwezigheid,
              afgeleid uit ``OAUTH_SCOPE``.
            - ``bearer_methods_supported``: ``["header"]`` (Authorization: Bearer).
        """
        resource = current_app.config.get("OAUTH_RESOURCE_ID") or request.host_url.rstrip("/")
        scopes = current_app.config.get("OAUTH_RESOURCE_SCOPES_SUPPORTED")
        if scopes is None:
            scopes = current_app.config.get("OAUTH_SCOPE", "openid profile email").split()
        return jsonify(
            {
                "resource": resource,
                "authorization_servers": [current_app.config["OAUTH_BASE_URL"]],
                "scopes_supported": scopes,
                "bearer_methods_supported": ["header"],
            }
        )

    def _register_metadata_routes(self, app):
        """Registreer het RFC 9728-metadata-endpoint op root-niveau (buiten de /auth-prefix)."""
        app.add_url_rule(
            "/.well-known/oauth-protected-resource",
            "oauth_protected_resource",
            self._handle_protected_resource_metadata,
        )
        logger.info("Protected-resource-metadata route geregistreerd (RFC 9728)")

    def _register_partitioned_cookie_handler(self, app):
        """
        Register after_request hook for Partitioned cookie support.

        Adds the Partitioned attribute to session cookies to support CHIPS
        (Cookies Having Independent Partitioned State). Required for OAuth
        flows in iframe contexts (e.g. FiveM NUI) where third-party cookies
        would otherwise be blocked.

        Args:
            app: Flask application instance
        """

        @app.after_request
        def add_partitioned_cookie(response):
            """Add Partitioned attribute to session cookies."""
            set_cookie_headers = response.headers.getlist("Set-Cookie")
            if set_cookie_headers:
                new_cookies = []
                for cookie in set_cookie_headers:
                    # Voeg Partitioned toe aan session cookie als deze Secure is
                    # Partitioned vereist Secure om te werken
                    if (
                        "session" in cookie.lower()
                        and "Partitioned" not in cookie
                        and "Secure" in cookie
                    ):
                        # Voeg Partitioned toe na Secure attribuut
                        cookie = cookie.replace("Secure", "Secure; Partitioned")
                        logger.debug("Partitioned attribuut toegevoegd aan sessie cookie")
                    new_cookies.append(cookie)
                del response.headers["Set-Cookie"]
                for cookie in new_cookies:
                    response.headers.add("Set-Cookie", cookie)
            return response

        logger.info("Partitioned cookie handler geregistreerd (CHIPS ondersteuning)")

    def _register_embedded_frame_handler(self, app):
        """
        Register after_request hook that allows framing for embedded (FiveM NUI) sessions.

        When a session is marked as embedded (`session['rpr_embedded'] = True`), all
        responses get permissive framing headers so the page remains loadable inside a
        FiveM NUI iframe, even if the app or another middleware (e.g. Talisman) has set
        a restrictive X-Frame-Options or Content-Security-Policy.
        """

        @app.after_request
        def allow_framing_for_embedded(response):
            if not session.get("rpr_embedded"):
                return response
            response.headers["X-Frame-Options"] = "ALLOWALL"
            # Overschrijf een eventuele restrictieve frame-ancestors CSP-directive.
            # `*` dekt alleen standaard netwerkschemes (http/https/ws/wss). FiveM's NUI
            # gebruikt het `nui:` scheme — dat moet expliciet worden toegevoegd.
            csp = response.headers.get("Content-Security-Policy", "")
            if "frame-ancestors" in csp:
                csp = re.sub(r"frame-ancestors\s+[^;]+", "frame-ancestors * nui:", csp)
            else:
                csp = (csp.rstrip("; ") + "; frame-ancestors * nui:").lstrip("; ")
            response.headers["Content-Security-Policy"] = csp
            return response

        logger.info("Embedded frame handler geregistreerd (FiveM NUI iframe-ondersteuning)")

    def _register_error_handlers(self, app):
        """
        Register error handlers.

        Args:
            app: Flask application instance
        """

        @app.errorhandler(OAuthError)
        def handle_oauth_error(error):
            logger.error(f"OAuth error: {error.message}")
            return jsonify({"error": "oauth_error", "message": error.message}), error.status_code

        @app.errorhandler(TokenExpiredError)
        def handle_token_expired(error):
            logger.warning("Token expired")
            session.clear()
            return redirect(url_for(self.login_view))

    def _reauth_or_redirect(self, log_message):
        """Wis de sessie en stuur de gebruiker naar (her)authenticatie.

        Gedeeld door de token-hervalidatie en de back-channel-logout-handhaving: honoreert
        embedded (FiveM NUI) sessies (postMessage-signaal), XHR (401) en gewone navigatie
        (redirect naar login met bewaarde ``next``).
        """
        was_embedded = session.get("rpr_embedded", False)
        logger.info(log_message)
        session.clear()
        accept = request.headers.get("Accept", "")
        is_xhr = (
            request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or "application/json" in accept
        )
        if was_embedded and not is_xhr:
            return self._embedded_auth_signal("reauth")
        if is_xhr:
            return jsonify({"error": "Session expired"}), 401
        session["next"] = request.url
        session.modified = True
        return redirect(url_for(self.login_view))

    def _validate_session_token(self):
        """
        Periodieke hervalidatie van het sessie-token bij de auth server.

        Wordt uitgevoerd als before_request hook. Als het token ingetrokken of
        verlopen is, wordt de sessie gewist en de gebruiker doorgestuurd naar login.
        Het interval is instelbaar via OAUTH_TOKEN_REVALIDATE_INTERVAL (seconden).
        Stel in op 0 om bij elke request te valideren.
        """
        if "oauth_user" not in session:
            return None

        # Sla auth-routes zelf over om redirect-loops te voorkomen
        if request.endpoint and request.endpoint.startswith("auth."):
            return None

        # Bearer token requests worden volledig afgehandeld door de decorator
        # (@login_required etc.) — sessie-revalidatie hier veroorzaakt een 401
        # als het in-sessie opgeslagen token nieuwer is dan het meegestuurde
        # Bearer token (bijv. na token-refresh door rpr_core).
        if request.headers.get("Authorization", "").startswith("Bearer "):
            return None

        interval = current_app.config.get("OAUTH_TOKEN_REVALIDATE_INTERVAL", 300)

        if interval > 0:
            last_check = session.get("_token_validated_at", 0)
            if time.time() - last_check < interval:
                return None

        if not self.validate_token():
            # §6 laag-2: _reauth_or_redirect honoreert embedded (FiveM NUI) sessies via een
            # postMessage-signaal i.p.v. een in-CEF redirect naar de auth-server.
            return self._reauth_or_redirect("Sessie-token niet meer geldig, sessie gewist")

        session["_token_validated_at"] = time.time()
        session.modified = True
        return None

    def get_access_token(self) -> Optional[str]:
        """
        Return the current user's access token from the session.

        Returns:
            str: The access token, or None if not authenticated.
        """
        return session.get("oauth_token", {}).get("access_token")

    def api_request(
        self,
        method: str,
        path: str,
        access_token: Optional[str] = None,
        **kwargs,
    ) -> requests.Response:
        """
        Make an authenticated request to the auth server API.

        No token validation or expiry checking is performed — the caller is
        responsible for handling 401/403 responses. Pass ``access_token`` to
        use an externally obtained token; omit it to use the current session
        token automatically.

        Args:
            method: HTTP method (``"GET"``, ``"POST"``, ``"PUT"``, ``"DELETE"``, …).
            path: API path relative to ``OAUTH_BASE_URL``, e.g. ``"/api/v1/users/123"``.
            access_token: Bearer token to use. Defaults to the current session token.
            **kwargs: Passed directly to ``requests.request()`` (json, data, params, …).

        Returns:
            requests.Response

        Example::

            resp = rpr_auth.api_request("PUT", f"/api/v1/users/{user_id}",
                                        json={"firstname": "Jan"})
            resp.raise_for_status()

            # Of met een extern token:
            resp = rpr_auth.api_request("GET", "/api/v1/sessions",
                                        access_token=some_token)
        """
        if access_token is None:
            access_token = self.get_access_token()

        url = f"{current_app.config['OAUTH_BASE_URL']}{path}"
        headers = kwargs.pop("headers", {})
        if access_token:
            headers.setdefault("Authorization", f"Bearer {access_token}")
        timeout = kwargs.pop("timeout", current_app.config.get("OAUTH_TIMEOUT", 10))

        return requests.request(method, url, headers=headers, timeout=timeout, **kwargs)

    def validate_token(self):
        """
        Validate the current access token.

        Returns:
            bool: True if the token is valid
        """
        if "oauth_token" not in session:
            return False

        token = session["oauth_token"]
        access_token = token.get("access_token")

        if not access_token:
            return False

        try:
            # Valideer bij auth server
            response = requests.get(
                f"{current_app.config['OAUTH_BASE_URL']}/oauth/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
            )

            return response.status_code == 200

        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return False

    def validate_2fa(self):
        """
        Validate the 2FA status of the current user.

        Checks the ACR claim in the session. Both `acr="mfa"` (TOTP) and
        `acr="phr"` (passkey/WebAuthn) are accepted. Falls back to the
        userinfo endpoint if the session does not confirm 2FA.

        Returns:
            bool: True if 2FA is validated (acr in ["mfa", "phr"])
        """
        # Check session first (fastest)
        acr = session.get("acr", "pwd")
        if acr in ["mfa", "phr"]:
            return True

        if session.get("twofa_validated", False):
            return True

        # Session does not confirm 2FA — fall back to server check
        logger.info(
            f"validate_2fa: session heeft geen 2FA bevestiging "
            f"(acr={acr!r}, twofa_validated={session.get('twofa_validated')}), "
            f"server check uitvoeren"
        )

        # If not in session, check with server
        if "oauth_token" not in session:
            logger.info("validate_2fa: geen oauth_token in session, return False")
            return False

        token = session["oauth_token"]
        access_token = token.get("access_token")

        if not access_token:
            return False

        try:
            # Get userinfo to check current 2FA status
            response = requests.get(
                f"{current_app.config['OAUTH_BASE_URL']}/oauth/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
            )

            if response.status_code == 200:
                data = response.json()

                # Check ACR claim (OAuth standard)
                acr = data.get("acr", "pwd")
                logger.info(
                    f"validate_2fa: userinfo acr={acr!r}, twofa_validated={data.get('twofa_validated')}"
                )
                if acr in ["mfa", "phr"]:
                    session["acr"] = acr
                    session["twofa_validated"] = True
                    session.modified = True
                    return True

                # Check legacy twofa_validated field
                twofa_validated = data.get("twofa_validated", False)
                session["twofa_validated"] = twofa_validated
                session["acr"] = acr
                session.modified = True

                return twofa_validated

            logger.info(
                f"validate_2fa: userinfo endpoint status {response.status_code}, return False"
            )
            return False

        except Exception as e:
            logger.error(f"2FA validation error: {e}")
            return False

    def _embedded_auth_signal(self, reason: str, acr_values=None, force_fresh: bool = False):
        """§6 laag-2: signaleer de host-NUI (FiveM-iframe) dat (her)authenticatie nodig is.

        Voor een embedded sessie (`session['rpr_embedded']`) mag step-up/herauth NIET via een
        in-CEF redirect naar de auth-server (geen sessie daar, passkeys werken niet in CEF).
        In plaats daarvan rendert deze methode een minimale pagina die via `postMessage` de
        host-NUI vraagt de device-flow (eventueel met `acr_values`) opnieuw te draaien in de
        ECHTE browser en daarna het iframe te herbootstrappen.

        reason: 'step_up' (2FA-eis) of 'reauth' (sessie/token verlopen).
        """
        payload = {
            "type": "rpr_auth_required",
            "reason": reason,
            "acr_values": acr_values,
            "fresh": bool(force_fresh),
        }
        html = render_template_string(_EMBEDDED_AUTH_SIGNAL_HTML, payload_json=json.dumps(payload))
        resp = make_response(html, 200)
        resp.headers["Cache-Control"] = "no-store"
        # Sta framing vanuit elke origin toe zodat FiveM NUI-iframes dit signaal kunnen ontvangen,
        # ook als de app X-Frame-Options of een strikte CSP frame-ancestors policy instelt.
        resp.headers["X-Frame-Options"] = "ALLOWALL"
        resp.headers["Content-Security-Policy"] = "frame-ancestors * nui:"
        return resp

    def require_2fa_reauth(self, force_fresh: bool = False):
        """
        Start OIDC step-up authentication: requires the user to have completed 2FA.

        Sends the user to the auth server with acr_values=mfa. The auth server
        checks the existing session:
        - Passkey login (acr=phr) → satisfied immediately, no extra prompt
        - 2FA already done (even for a different app) → satisfied immediately
        - No 2FA yet → auth server shows only the 2FA screen (no password re-entry)

        Args:
            force_fresh: Send prompt=login so the auth server clears the existing
                         2fa_verified status and always demands fresh 2FA. Use only
                         for sensitive actions (via require_fresh_2fa), not for
                         regular @require_2fa routes.

        Returns:
            Flask redirect response to the OAuth authorize endpoint
        """
        # §6 laag-2: in een FiveM NUI-iframe nooit in-CEF redirecten — signaleer de host-NUI.
        if session.get("rpr_embedded"):
            return self._embedded_auth_signal("step_up", acr_values="mfa", force_fresh=force_fresh)

        redirect_uri = current_app.config["OAUTH_REDIRECT_URI"]

        kwargs = {"acr_values": "mfa"}
        if force_fresh:
            # prompt=login wist 2fa_verified op de auth server zodat de gebruiker
            # altijd opnieuw 2FA doorloopt, ongeacht een bestaande sessie.
            kwargs["prompt"] = "login"

        response = self.auth_server.authorize_redirect(redirect_uri, **kwargs)
        session.modified = True
        state_keys = [k for k in session.keys() if k.startswith("_state_")]
        logger.info(
            f"[require_2fa_reauth] force_fresh={force_fresh} state_keys_in_session={state_keys}"
        )
        return response

    def require_fresh_2fa(self, session_key: str = "_fresh_2fa_granted"):
        """
        Require fresh 2FA verification for a specific sensitive action.

        Unlike validate_2fa(), this method does not accept 2FA that was
        completed during login. The user must explicitly complete 2FA for
        this particular action (e.g. admin access).

        Use in a before_request:

            result = rpr_auth.require_fresh_2fa('_admin_2fa_granted')
            if result:
                return result

        The session_key is automatically cleared on logout (session.clear()).

        Args:
            session_key: Key in the Flask session used to track the status.

        Returns:
            None if 2FA has already been completed for this action.
            Flask redirect response if 2FA is still required.
        """
        # Al geautoriseerd in deze sessie voor deze actie
        if session.get(session_key, False):
            return None

        # Teruggekeerd van reauth — controleer of 2FA daadwerkelijk is voltooid
        pending_key = f"{session_key}_pending"
        if session.pop(pending_key, False):
            if self.validate_2fa():
                session[session_key] = True
                session.modified = True
                logger.info(f"[require_fresh_2fa] 2FA gevalideerd, {session_key}=True")
                return None
            else:
                logger.warning("[require_fresh_2fa] Terug van reauth maar 2FA niet gevalideerd")
                return None  # Aanroeper handelt de foutmelding af

        # Eerste keer: stuur naar 2FA en dwing verse verificatie af
        from flask import request as flask_request

        session[pending_key] = True
        session["next"] = flask_request.url
        session.modified = True
        logger.info(f"[require_fresh_2fa] Verse 2FA vereist ({session_key}), starten reauth")
        return self.require_2fa_reauth(force_fresh=True)


__all__ = ["RPRAuth"]
