"""
flask_rpr_oauth.auth
~~~~~~~~~~~~~~~~~~~~

Hoofd OAuth authenticatie class.
"""

import logging
import requests
from flask import Blueprint, redirect, url_for, session, request, jsonify, current_app, make_response
from markupsafe import escape
from authlib.integrations.flask_client import OAuth
from .models import OAuthUser, current_user
from .exceptions import OAuthError, TokenExpiredError

try:
    from flask_wtf.csrf import csrf_exempt

    CSRF_AVAILABLE = True
except ImportError:
    CSRF_AVAILABLE = False

    # Dummy decorator als flask-wtf niet beschikbaar is
    def csrf_exempt(func):
        return func

try:
    from flask_session import Session as FlaskSession
    from flask_session.base import ServerSideSessionInterface as _ServerSideSessionInterface

    FLASK_SESSION_AVAILABLE = True
except ImportError:
    FLASK_SESSION_AVAILABLE = False
    _ServerSideSessionInterface = None


logger = logging.getLogger(__name__)


def _post_logout_form(action: str, params: dict):
    """
    Render een auto-submitting HTML POST form voor RP-Initiated Logout.

    Gebruikt POST in plaats van GET redirect zodat grote JWTs (id_token_hint)
    in de request body blijven en de URL-lengtelimiet van de server niet overschrijden.
    """
    fields = ''.join(
        f'<input type="hidden" name="{escape(k)}" value="{escape(v)}">'
        for k, v in params.items()
    )
    html = (
        '<!DOCTYPE html><html><head><title>Uitloggen...</title></head><body>'
        f'<form id="f" method="post" action="{escape(action)}">{fields}</form>'
        '<script>document.getElementById("f").submit();</script>'
        '</body></html>'
    )
    response = make_response(html)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    return response


class RPRAuth:
    """
    Hoofd class voor RPR OAuth integratie.

    Deze class initialiseert OAuth 2.0 / OpenID Connect authenticatie met
    de Roleplay Reality Auth Server en registreert alle benodigde routes.
    """

    def __init__(
        self, app=None, user_class=OAuthUser, login_view="auth.login", auto_register_routes=True
    ):
        """
        Initialize RPR OAuth.

        Args:
            app: Flask application instance
            user_class: Custom user class (moet OAuthUser extenden)
            login_view: View naam voor login redirect
            auto_register_routes: Automatisch auth routes registreren
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
        Initialize extensie met Flask app.

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
        app.config.setdefault("WEBHOOK_SECRET", None)
        app.config.setdefault("OAUTH_PARTITIONED_COOKIES", True)
        app.config.setdefault("OAUTH_TIMEOUT", 10)

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

        # Registreer Partitioned cookie support voor iframe/CHIPS
        if app.config.get("OAUTH_PARTITIONED_COOKIES", False):
            self._register_partitioned_cookie_handler(app)

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
        OAuth callback handler: wisselt de authorization code in voor tokens.

        Slaat userinfo, permissions, groups en de ACR-claim op in de session.
        Blokkeert gebruikers met status REVIEW of BANNED direct bij login.
        Redirect naar de URL in session['next'] of naar 'index' na succesvolle login.
        """
        try:
            # Debug: log session keys and incoming state for mismatching_state diagnosis
            incoming_state = request.args.get('state', '')
            state_key = f'_state_auth_server_{incoming_state}'
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
                session["oauth_blocked_message"] = _blocked_messages[user_status]
                return redirect(url_for("auth.login"))

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
            session.modified = True  # Forceer sessie-opslag in Redis/filesystem

            logger.info(
                f"User {userinfo.get('email')} succesvol ingelogd (2FA: {twofa_validated}, ACR: {acr})"
            )

            # Redirect naar next of home
            next_page = session.pop("next", None) or url_for("index")
            return redirect(next_page)

        except Exception as e:
            logger.error(f"OAuth callback error: {e}", exc_info=True)
            session.clear()
            return redirect(url_for("auth.login"))

    def _handle_logout(self):
        """Logout: clear lokale session en initieer RP-Initiated Logout op de auth server."""
        # Bewaar het ID token vóór session.clear() voor de id_token_hint
        token = session.get("oauth_token", {})
        id_token = token.get("id_token")

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
            params = {}
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

    def _handle_refresh(self):
        """Refresh access token."""
        if "oauth_token" not in session:
            raise OAuthError("Geen token gevonden")

        try:
            token = session["oauth_token"]
            new_token = self.auth_server.fetch_access_token(
                refresh_token=token.get("refresh_token")
            )
            session["oauth_token"] = new_token
            logger.info("Token succesvol gerefreshed")
            return jsonify({"status": "success"})

        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            raise TokenExpiredError("Token refresh mislukt")

    def _verify_webhook_secret(self):
        """Verify webhook secret if configured."""
        if current_app.config["WEBHOOK_SECRET"]:
            provided_secret = request.headers.get("X-Webhook-Secret")
            if provided_secret != current_app.config["WEBHOOK_SECRET"]:
                return jsonify({"error": "Invalid secret"}), 401
        return None

    def _handle_webhook_token_revoked(self):
        """Webhook voor token revocation."""
        error_response = self._verify_webhook_secret()
        if error_response:
            return error_response

        data = request.get_json()
        oauth_id = data.get("sub")

        if current_user.is_authenticated and current_user.oauth_id == oauth_id:
            session.clear()
            logger.info(f"User {oauth_id} uitgelogd door token revocation")

        return jsonify({"status": "success"})

    def _handle_webhook_user_deleted(self):
        """Webhook voor user deletion."""
        error_response = self._verify_webhook_secret()
        if error_response:
            return error_response

        data = request.get_json()
        oauth_id = data.get("sub")

        if current_user.is_authenticated and current_user.oauth_id == oauth_id:
            session.clear()
            logger.info(f"User {oauth_id} uitgelogd door account deletion")

        return jsonify({"status": "success"})

    def _register_routes(self, app):
        """
        Registreer auth Blueprint met routes.

        Args:
            app: Flask application instance
        """
        auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

        auth_bp.add_url_rule("/login", "login", self._handle_login)
        auth_bp.add_url_rule("/callback", "callback", self._handle_callback)
        auth_bp.add_url_rule("/logout", "logout", self._handle_logout)
        auth_bp.add_url_rule("/refresh", "refresh", self._handle_refresh)
        auth_bp.add_url_rule(
            "/webhook/token-revoked",
            "webhook_token_revoked",
            self._handle_webhook_token_revoked,
            methods=["POST"],
        )
        auth_bp.add_url_rule(
            "/webhook/user-deleted",
            "webhook_user_deleted",
            self._handle_webhook_user_deleted,
            methods=["POST"],
        )

        app.register_blueprint(auth_bp)
        logger.info("Auth routes geregistreerd")

    def _register_partitioned_cookie_handler(self, app):
        """
        Registreer after_request hook voor Partitioned cookie support.

        Voegt het Partitioned attribuut toe aan sessie cookies om CHIPS
        (Cookies Having Independent Partitioned State) te ondersteunen.
        Dit is nodig voor OAuth flows in iframe context (bijv. FiveM NUI)
        waar third-party cookies anders geblokkeerd worden.

        Args:
            app: Flask application instance
        """

        @app.after_request
        def add_partitioned_cookie(response):
            """Voeg Partitioned attribuut toe aan sessie cookies."""
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

    def _register_error_handlers(self, app):
        """
        Registreer error handlers.

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

    def validate_token(self):
        """
        Valideer huidige access token.

        Returns:
            bool: True als token geldig is
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
        Valideer 2FA status van huidige user.

        Checkt de ACR claim uit de session. Zowel `acr="mfa"` (TOTP) als
        `acr="phr"` (passkey/WebAuthn) worden geaccepteerd. Als de session
        geen bevestiging geeft, wordt het userinfo endpoint geraadpleegd.

        Returns:
            bool: True als 2FA is gevalideerd (acr in ["mfa", "phr"])
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
                logger.info(f"validate_2fa: userinfo acr={acr!r}, twofa_validated={data.get('twofa_validated')}")
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

            logger.info(f"validate_2fa: userinfo endpoint status {response.status_code}, return False")
            return False

        except Exception as e:
            logger.error(f"2FA validation error: {e}")
            return False

    def require_2fa_reauth(self, force_fresh: bool = False):
        """
        Start OIDC step-up authenticatie: vereist dat de gebruiker 2FA heeft voltooid.

        Stuurt de gebruiker naar de auth server met acr_values=mfa. De auth server
        controleert de bestaande sessie:
        - Passkey-inlog (acr=phr) → voldoet direct, geen extra prompt
        - Al eerder 2FA gedaan (ook voor een andere app) → voldoet direct
        - Nog geen 2FA → auth server toont uitsluitend het 2FA-scherm (geen wachtwoord opnieuw)

        Args:
            force_fresh: Stuur prompt=login mee zodat de auth server de bestaande
                         2fa_verified-status wist en altijd verse 2FA vraagt. Gebruik
                         dit alleen voor gevoelige handelingen (via require_fresh_2fa),
                         niet voor gewone @require_2fa routes.

        Returns:
            Flask redirect response naar OAuth authorize endpoint
        """
        redirect_uri = current_app.config["OAUTH_REDIRECT_URI"]

        kwargs = {"acr_values": "mfa"}
        if force_fresh:
            # prompt=login wist 2fa_verified op de auth server zodat de gebruiker
            # altijd opnieuw 2FA doorloopt, ongeacht een bestaande sessie.
            kwargs["prompt"] = "login"

        response = self.auth_server.authorize_redirect(redirect_uri, **kwargs)
        session.modified = True
        state_keys = [k for k in session.keys() if k.startswith('_state_')]
        logger.info(f"[require_2fa_reauth] force_fresh={force_fresh} state_keys_in_session={state_keys}")
        return response

    def require_fresh_2fa(self, session_key: str = "_fresh_2fa_granted"):
        """
        Vereist een verse 2FA-verificatie specifiek voor een gevoelige actie.

        Anders dan validate_2fa() accepteert deze methode geen 2FA die al gedaan
        is tijdens het inloggen. De gebruiker moet expliciet 2FA voltooien voor
        deze specifieke actie (bijv. admin-toegang).

        Gebruik in een before_request:

            result = rpr_auth.require_fresh_2fa('_admin_2fa_granted')
            if result:
                return result

        De session_key wordt automatisch gewist bij uitloggen (session.clear()).

        Args:
            session_key: Sleutel in de Flask-session om de status bij te houden.

        Returns:
            None als 2FA al is voltooid voor deze actie.
            Flask redirect response als 2FA (nog) vereist is.
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
                logger.warning(f"[require_fresh_2fa] Terug van reauth maar 2FA niet gevalideerd")
                return None  # Aanroeper handelt de foutmelding af

        # Eerste keer: stuur naar 2FA en dwing verse verificatie af
        from flask import request as flask_request
        session[pending_key] = True
        session["next"] = flask_request.url
        session.modified = True
        logger.info(f"[require_fresh_2fa] Verse 2FA vereist ({session_key}), starten reauth")
        return self.require_2fa_reauth(force_fresh=True)


__all__ = ["RPRAuth"]
