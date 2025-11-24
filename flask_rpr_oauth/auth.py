"""
flask_rpr_oauth.auth
~~~~~~~~~~~~~~~~~~~~

Hoofd OAuth authenticatie class.
"""

import logging
import requests
from flask import Blueprint, redirect, url_for, session, request, jsonify, current_app
from authlib.integrations.flask_client import OAuth
from .models import OAuthUser, current_user
from .exceptions import OAuthError, TokenExpiredError

logger = logging.getLogger(__name__)


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

        # Initialiseer OAuth
        self.oauth = OAuth(app)
        self.auth_server = self.oauth.register(
            "auth_server",
            client_id=app.config["OAUTH_CLIENT_ID"],
            client_secret=app.config["OAUTH_CLIENT_SECRET"],
            server_metadata_url=f"{app.config['OAUTH_BASE_URL']}/.well-known/openid-configuration",
            client_kwargs={"scope": app.config["OAUTH_SCOPE"]},
        )

        logger.info("RPR OAuth geïnitialiseerd (session-based)")

        # Registreer auth routes
        if self.auto_register_routes:
            self._register_routes(app)

        # Registreer error handlers
        self._register_error_handlers(app)

        # Store instance op app
        app.extensions = getattr(app, "extensions", {})
        app.extensions["rpr_auth"] = self

    def _register_routes(self, app):
        """
        Registreer auth Blueprint met routes.

        Args:
            app: Flask application instance
        """
        auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

        @auth_bp.route("/login")
        def login():
            """Start OAuth login flow."""
            redirect_uri = current_app.config["OAUTH_REDIRECT_URI"]
            return self.auth_server.authorize_redirect(redirect_uri)

        @auth_bp.route("/callback")
        def callback():
            """OAuth callback handler."""
            try:
                # Haal token op
                token = self.auth_server.authorize_access_token()

                # Haal userinfo op
                userinfo = self.auth_server.userinfo()

                # Sla token op in session
                session["oauth_token"] = token
                session["oauth_user"] = {
                    "oauth_id": userinfo["sub"],
                    "email": userinfo.get("email", ""),
                    "voornaam": userinfo.get("given_name", ""),
                    "achternaam": userinfo.get("family_name", ""),
                }
                session["oauth_permissions"] = userinfo.get("permissions", [])
                session["oauth_groups"] = userinfo.get("groups", [])

                # Sla 2FA status op (van token of userinfo)
                twofa_validated = token.get("twofa_validated", False) or userinfo.get(
                    "twofa_validated", False
                )
                session["twofa_validated"] = twofa_validated

                logger.info(
                    f"User {userinfo.get('email')} succesvol ingelogd (2FA: {twofa_validated})"
                )

                # Redirect naar next of home
                next_page = session.pop("next", None) or url_for("index")
                return redirect(next_page)

            except Exception as e:
                logger.error(f"OAuth callback error: {e}")
                raise OAuthError(f"Login mislukt: {str(e)}")

        @auth_bp.route("/logout")
        def logout():
            """Logout en clear session."""
            session.clear()
            logger.info("User uitgelogd")
            return redirect(url_for("index"))

        @auth_bp.route("/refresh")
        def refresh():
            """Refresh access token."""
            if "oauth_token" not in session:
                raise OAuthError("Geen token gevonden")

            try:
                token = session["oauth_token"]

                # Refresh token
                new_token = self.auth_server.fetch_access_token(
                    refresh_token=token.get("refresh_token")
                )

                session["oauth_token"] = new_token
                logger.info("Token succesvol gerefreshed")

                return jsonify({"status": "success"})

            except Exception as e:
                logger.error(f"Token refresh error: {e}")
                raise TokenExpiredError("Token refresh mislukt")

        @auth_bp.route("/webhook/token-revoked", methods=["POST"])
        def webhook_token_revoked():
            """Webhook voor token revocation."""
            # Verify webhook secret
            if current_app.config["WEBHOOK_SECRET"]:
                provided_secret = request.headers.get("X-Webhook-Secret")
                if provided_secret != current_app.config["WEBHOOK_SECRET"]:
                    return jsonify({"error": "Invalid secret"}), 401

            data = request.get_json()
            oauth_id = data.get("sub")

            # Logout user if currently logged in
            if current_user.is_authenticated and current_user.oauth_id == oauth_id:
                session.clear()
                logger.info(f"User {oauth_id} uitgelogd door token revocation")

            return jsonify({"status": "success"})

        @auth_bp.route("/webhook/user-deleted", methods=["POST"])
        def webhook_user_deleted():
            """Webhook voor user deletion."""
            # Verify webhook secret
            if current_app.config["WEBHOOK_SECRET"]:
                provided_secret = request.headers.get("X-Webhook-Secret")
                if provided_secret != current_app.config["WEBHOOK_SECRET"]:
                    return jsonify({"error": "Invalid secret"}), 401

            data = request.get_json()
            oauth_id = data.get("sub")

            # Logout user if currently logged in
            if current_user.is_authenticated and current_user.oauth_id == oauth_id:
                session.clear()
                logger.info(f"User {oauth_id} uitgelogd door account deletion")

            return jsonify({"status": "success"})

        # Registreer blueprint
        app.register_blueprint(auth_bp)
        logger.info("Auth routes geregistreerd")

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
            )

            return response.status_code == 200

        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return False

    def validate_2fa(self):
        """
        Valideer 2FA status van huidige user.

        Checkt via de validate endpoint of de user 2FA heeft voltooid.
        Update de session met de actuele 2FA status.

        Returns:
            bool: True als 2FA is gevalideerd
        """
        if "oauth_token" not in session:
            return False

        token = session["oauth_token"]
        access_token = token.get("access_token")

        if not access_token:
            return False

        try:
            # Check 2FA status via validate endpoint
            response = requests.get(
                f"{current_app.config['OAUTH_BASE_URL']}/api/v1/validate",
                headers={"Authorization": f"Bearer {access_token}"},
            )

            if response.status_code == 200:
                data = response.json()
                twofa_validated = data.get("twofaValidated", False)

                # Update session met actuele status
                session["twofa_validated"] = twofa_validated

                return twofa_validated

            return False

        except Exception as e:
            logger.error(f"2FA validation error: {e}")
            return False

    def get_2fa_redirect_url(self, next_url=None):
        """
        Genereer redirect URL naar auth server voor 2FA.

        Args:
            next_url: URL om naar terug te keren na 2FA (optioneel)

        Returns:
            str: Volledige URL naar auth server met 2FA requirement
        """
        if next_url is None:
            next_url = request.url

        auth_base = current_app.config["OAUTH_BASE_URL"]
        return f"{auth_base}/?2fa_needed=true&next={next_url}"


__all__ = ["RPRAuth"]
