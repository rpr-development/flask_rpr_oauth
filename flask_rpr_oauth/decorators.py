"""
flask_rpr_oauth.decorators
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unified decorators that work for BOTH session-based (browser) and stateless (API) authentication.
Automatically detects Bearer tokens and falls back to session-based auth.
"""

import logging
from functools import wraps
from urllib.parse import urlparse
from flask import abort, current_app, g, session, redirect, url_for, request, jsonify
from .models import current_user
from .exceptions import PermissionDeniedError, GroupDeniedError

logger = logging.getLogger(__name__)


_BLOCKED_STATUSES = {
    "REVIEW": "Je account is geblokkeerd. Neem zo snel mogelijk contact op met jouw teammanager voor een gesprek.",
    "BANNED": "Je account is permanent non-actief gesteld. Neem contact op met jouw teammanager.",
}


def _check_user_status():
    """
    Controleer of de ingelogde gebruiker een geblokkeerde status heeft.

    Returns:
        Response | None: Een 403-response als de gebruiker geblokkeerd is, anders None.
    """
    status = session.get("oauth_user", {}).get("user_status", "")
    message = _BLOCKED_STATUSES.get(status)
    if message:
        user_id = session.get("oauth_user", {}).get("oauth_id")
        logger.warning("Toegang geweigerd voor user %s met status %r", user_id, status)
        return jsonify({"error": "account_blocked", "message": message}), 403
    return None


def _is_ajax_request():
    """Check if request is an AJAX/fetch request."""
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept


def _request_uses_dpop():
    """True als de request het token via de RFC 9449 ``DPoP``-scheme aanbiedt."""
    return request.headers.get("Authorization", "").startswith("DPoP ")


def _is_bearer_token_request():
    """Check of de request een token via de Authorization-header aanbiedt (API-mode).

    Accepteert zowel ``Bearer`` (RFC 6750) als ``DPoP`` (RFC 9449); beide nemen het API-pad in
    de decorators. De naam blijft ``_is_bearer_token_request`` voor achterwaartse compatibiliteit
    (tests en externe imports patchen deze functie).
    """
    auth_header = request.headers.get("Authorization", "")
    return auth_header.startswith("Bearer ") or auth_header.startswith("DPoP ")


def _get_bearer_token():
    """Extraheer het access token uit de Authorization-header (``Bearer``- of ``DPoP``-scheme)."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]  # Remove 'Bearer '
    if auth_header.startswith("DPoP "):
        return auth_header[5:]  # Remove 'DPoP '
    return None


def _request_htu():
    """De canonieke URL van deze request voor de DPoP ``htu``-controle (zonder query/fragment).

    Voorkeur voor ``OAUTH_RESOURCE_ID`` (de externe resource-URI van deze app) + het request-pad,
    zodat de controle klopt achter een TLS-terminerende proxy (Cloudflare) waar ``request.url``
    de interne http-URL zou geven. Zonder config: de request-host.
    """
    base = current_app.config.get("OAUTH_RESOURCE_ID") or request.host_url
    return base.rstrip("/") + request.path


def _dpop_replay_redis():
    """Optionele Redis voor de DPoP jti-replaycache. Hergebruikt de al-geconfigureerde
    back-channel-logout-client van de RPRAuth-extensie; None (fail-open) als die er niet is."""
    rpr_auth = current_app.extensions.get("rpr_auth")
    if rpr_auth is not None and hasattr(rpr_auth, "_logout_redis"):
        try:
            return rpr_auth._logout_redis()
        except Exception:
            return None
    return None


def _authenticate_dpop_token(token):
    """Valideer een DPoP-request (RFC 9449 §7.1): proof lokaal valideren + de ``cnf.jkt`` uit
    introspectie vergelijken. Returnt de introspectie-dict (permissions/groups/acr/sub) of None.
    """
    from .dpop import DPoPError, validate_dpop_proof
    from .helpers import _introspect_token

    oauth_base_url = current_app.config.get("OAUTH_BASE_URL")
    if not oauth_base_url:
        logger.error("[dpop] OAUTH_BASE_URL niet geconfigureerd")
        return None

    # De proof wordt per request gevalideerd (nooit gecachet): htm/htu/jti zijn request-gebonden.
    try:
        proof_jkt = validate_dpop_proof(
            request.headers.get("DPoP"),
            request.method,
            _request_htu(),
            token,
            redis=_dpop_replay_redis(),
        )
    except DPoPError as e:
        logger.info("[dpop] Proof geweigerd: %s", e)
        return None

    # Introspectie (client-geauthenticeerd) levert active + permissions/groups/acr én cnf.jkt.
    data = _introspect_token(token, oauth_base_url)
    if not data:
        return None

    bound_jkt = (data.get("cnf") or {}).get("jkt")
    if not bound_jkt:
        # Token is niet DPoP-gebonden maar wordt wél via de DPoP-scheme aangeboden → weiger.
        # Anders zou een gewoon Bearer-token als "DPoP" met een eigen sleutel de bindingcontrole
        # omzeilen.
        logger.warning("[dpop] Token is niet DPoP-gebonden maar aangeboden via het DPoP-scheme")
        return None
    if bound_jkt != proof_jkt:
        logger.warning("[dpop] Thumbprint-mismatch: proof=%s token=%s", proof_jkt, bound_jkt)
        return None

    return data


def _get_userinfo_from_token(token):
    """Valideer het token en geef de userinfo/introspectie-dict terug (of None).

    - **DPoP-scheme** (``Authorization: DPoP``): valideer de proof lokaal tegen deze request en
      eis dat de proof-thumbprint matcht met de ``cnf.jkt`` uit introspectie.
    - **Bearer-scheme met ``OAUTH_REQUIRE_DPOP``**: geweigerd — deze resource server accepteert
      alleen sender-constrained tokens.
    - **Bearer-scheme anders**: ongewijzigd via userinfo-first/introspectie-fallback.
    """
    from .helpers import get_userinfo_from_token

    if _request_uses_dpop():
        return _authenticate_dpop_token(token)

    if current_app.config.get("OAUTH_REQUIRE_DPOP"):
        logger.info(
            "[dpop] Bearer-token geweigerd op %s: OAUTH_REQUIRE_DPOP staat aan", request.path
        )
        return None

    return get_userinfo_from_token(token)


def _resource_metadata_url():
    """URL van het protected-resource-metadata-document van deze resource server (RFC 9728).

    Voorkeur voor ``OAUTH_RESOURCE_ID`` (de canonieke resource-URI van deze app); anders de
    host van het huidige request. Heeft ``OAUTH_RESOURCE_ID`` een pad (RFC 9728 §3.1, bijv.
    ``https://gms.example/mcp``), dan wijst dit naar de pad-suffix-variant
    (``/.well-known/oauth-protected-resource/mcp``) die ``auth.py`` in dat geval óók
    registreert naast de root-route.
    """
    resource_id = current_app.config.get("OAUTH_RESOURCE_ID")
    if resource_id:
        parsed = urlparse(resource_id)
        path = parsed.path.rstrip("/")
        return f"{parsed.scheme}://{parsed.netloc}/.well-known/oauth-protected-resource{path}"
    return f"{request.host_url.rstrip('/')}/.well-known/oauth-protected-resource"


def _default_challenge_scopes():
    """Scopes voor de ``scope``-hint op een 401/403-``WWW-Authenticate``-challenge (RFC 6750 §3).

    ``OAUTH_RESOURCE_REQUIRED_SCOPES`` (lijst of spatie-gescheiden string) indien
    geconfigureerd; anders dezelfde scopes als de protected-resource-metadata adverteert
    (``resource_scopes_supported()``, zonder ``offline_access``).
    """
    from .helpers import resource_scopes_supported

    configured = current_app.config.get("OAUTH_RESOURCE_REQUIRED_SCOPES")
    if configured is None:
        return resource_scopes_supported()
    if isinstance(configured, str):
        return [s for s in configured.split() if s]
    return list(configured)


def _bearer_unauthorized(
    payload, *, error_code="invalid_token", acr_values=None, required_scopes=None
):
    """Bouw een 401-response met een RFC 6750 ``WWW-Authenticate: Bearer``-challenge.

    De challenge draagt ``resource_metadata`` (RFC 9728) en, indien bekend, een ``scope``-hint
    (RFC 6750 §3) zodat een client (bijv. een MCP-client) bij een 401 automatisch de juiste
    authorization server, audience én scope kan ontdekken. ``error_code`` en ``acr_values``
    zijn parameters zodat een RFC 9470 step-up-challenge
    (``error="insufficient_user_authentication"``, ``acr_values="mfa"``) hier op aanhaakt.
    ``payload`` blijft het bestaande JSON-body-formaat (backwards-compatibel).

    RFC 6750 §3.1: droeg de request helemaal geen token, dan krijgt de challenge GEEN
    ``error``-attribuut (alleen ``resource_metadata``/``scope``); dat onderscheid wordt hier
    gemaakt op basis van of er daadwerkelijk een (niet-lege) token is aangeboden.
    """
    response = jsonify(payload)
    response.status_code = 401
    # RFC 9449 §7.1: gebruikte de client het DPoP-scheme (of eist deze RS DPoP), dan is de
    # challenge een DPoP-challenge met een `algs`-lijst; anders de bestaande Bearer-challenge.
    use_dpop = _request_uses_dpop() or bool(current_app.config.get("OAUTH_REQUIRE_DPOP"))
    scheme = "DPoP" if use_dpop else "Bearer"
    challenge = f'{scheme} resource_metadata="{_resource_metadata_url()}"'
    scopes = required_scopes if required_scopes is not None else _default_challenge_scopes()
    if scopes:
        challenge += f', scope="{" ".join(scopes)}"'
    if error_code and _get_bearer_token():
        challenge += f', error="{error_code}"'
    if acr_values:
        challenge += f', acr_values="{acr_values}"'
    if use_dpop:
        from .dpop import DPOP_SIGNING_ALGS

        challenge += f', algs="{" ".join(DPOP_SIGNING_ALGS)}"'
    response.headers["WWW-Authenticate"] = challenge
    return response


def _bearer_forbidden(payload, *, required_scopes=None, description=None):
    """Bouw een 403-response met een RFC 6750 §3.1 ``WWW-Authenticate: Bearer``-challenge.

    Gebruikt op de Bearer-token-403-paden van ``permission_required``/``group_required``
    (en varianten) en door ``require_scope``: de JSON-``payload`` blijft exact wat de
    aanroeper al teruggaf, alleen de header komt erbij zodat een MCP-/OAuth-client
    machinaal weet dat ``error="insufficient_scope"`` en welke scope(s) nodig zijn.
    """
    response = jsonify(payload)
    response.status_code = 403
    use_dpop = _request_uses_dpop() or bool(current_app.config.get("OAUTH_REQUIRE_DPOP"))
    scheme = "DPoP" if use_dpop else "Bearer"
    challenge = (
        f'{scheme} error="insufficient_scope", resource_metadata="{_resource_metadata_url()}"'
    )
    scopes = required_scopes if required_scopes is not None else _default_challenge_scopes()
    if scopes:
        challenge += f', scope="{" ".join(scopes)}"'
    if description:
        challenge += f', error_description="{description}"'
    response.headers["WWW-Authenticate"] = challenge
    return response


def login_required(f):
    """
    Unified decorator that requires authentication via Bearer token OR session.

    - Bearer token (API): Validates token and stores info in current_token (via flask.g)
    - Session (browser): Checks current_user and redirects to login if needed

    Usage:
        @login_required
        def my_endpoint():
            # For API calls: use current_token
            # For browser: use current_user
            from flask_rpr_oauth import current_token
            if current_token:
                user_id = current_token.sub  # API mode
            else:
                user_id = current_user.get_id()  # Browser mode
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for Bearer token (API mode)
        if _is_bearer_token_request():
            token = _get_bearer_token()
            userinfo = _get_userinfo_from_token(token)

            if not userinfo:
                return _bearer_unauthorized(
                    {"error": "invalid_token", "message": "Invalid or expired token"}
                )

            # Store token info in flask.g for current_token proxy
            g._rpr_token_info = userinfo
            return f(*args, **kwargs)

        # Session-based (browser mode)
        if not current_user.is_authenticated:
            # AJAX/fetch requests krijgen 401 JSON
            if _is_ajax_request():
                return jsonify({"error": "Authentication required"}), 401

            # Store next URL in session
            session["next"] = request.url
            session.modified = True  # Forceer sessie-opslag in Redis/filesystem
            # Redirect to login
            return redirect(url_for("auth.login"))

        blocked = _check_user_status()
        if blocked:
            return blocked

        return f(*args, **kwargs)

    return decorated_function


def permission_required(permission=None, **method_permissions):
    """
    Unified decorator that requires a specific permission via Bearer token OR session.

    Works for BOTH user tokens AND M2M tokens in API mode.
    Supports both single permission and per-method permissions.

    Args:
        permission (str): Required permission string (for all methods)
        **method_permissions: Per-method permissions (GET="view", POST="edit", etc.)

    Examples:
        # Single permission for all methods
        @app.route('/admin')
        @permission_required('admin.access')
        def admin_panel():
            return 'Admin panel'

        # Different permissions per HTTP method
        @app.route('/melding', methods=['GET', 'POST', 'DELETE'])
        @permission_required(GET="melding.view", POST="melding.edit", DELETE="melding.delete")
        def melding_endpoint():
            return 'Melding endpoint'
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Determine required permission based on HTTP method
            if method_permissions:
                method = request.method.upper()
                required_permission = method_permissions.get(method)
                if required_permission is None:
                    # No permission specified for this method - allow access
                    # Check for Bearer token to inject userinfo
                    if _is_bearer_token_request():
                        token = _get_bearer_token()
                        userinfo = _get_userinfo_from_token(token)
                        if not userinfo:
                            return _bearer_unauthorized(
                                {"error": "invalid_token", "message": "Invalid or expired token"}
                            )
                        g._rpr_token_info = userinfo
                    return f(*args, **kwargs)
            else:
                required_permission = permission

            # Check for Bearer token (API mode)
            if _is_bearer_token_request():
                token = _get_bearer_token()
                userinfo = _get_userinfo_from_token(token)

                if not userinfo:
                    return _bearer_unauthorized(
                        {"error": "invalid_token", "message": "Invalid or expired token"}
                    )

                # Check permission for API token
                permissions = userinfo.get("permissions", [])

                if required_permission not in permissions:
                    token_type = userinfo.get("token_type", "unknown")
                    subject = userinfo.get("sub", "unknown")

                    logger.warning(
                        f"Permission denied: {subject} ({token_type}) tried to access "
                        f"{required_permission}. Available permissions: {permissions}"
                    )

                    return _bearer_forbidden(
                        {
                            "error": "Forbidden",
                            "message": f"{required_permission} permission required",
                            "your_permissions": permissions,
                        },
                        description=f"{required_permission} permission required",
                    )

                # Store token info in flask.g for current_token proxy
                g._rpr_token_info = userinfo
                return f(*args, **kwargs)

            # Session-based (browser mode)
            if not current_user.is_authenticated:
                abort(401)

            blocked = _check_user_status()
            if blocked:
                return blocked

            if not hasattr(current_user, "has_permission"):
                logger.error(f"User {current_user.get_id()} heeft geen has_permission method")
                abort(403)

            if not current_user.has_permission(required_permission):
                logger.warning(
                    f"User {current_user.get_id()} heeft geen permission: {required_permission}"
                )
                raise PermissionDeniedError(permission=required_permission)

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def any_permission_required(*permissions, **method_permissions):
    """
    Unified decorator that requires ANY of the specified permissions via Bearer token OR session.

    Supports both single set of permissions and per-method permissions.

    Args:
        *permissions: Variable aantal permission strings (for all methods)
        **method_permissions: Per-method permission lists (GET="perm1,perm2", POST="perm3,perm4")

    Examples:
        # Single set of permissions for all methods
        @app.route('/moderate')
        @any_permission_required('moderator', 'admin')
        def moderate():
            return 'Moderation panel'

        # Different permission sets per HTTP method
        @app.route('/melding', methods=['GET', 'POST'])
        @any_permission_required(GET="melding.view,melding.list", POST="melding.edit,melding.create")
        def melding_endpoint():
            return 'Melding endpoint'
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Determine required permissions based on HTTP method
            if method_permissions:
                method = request.method.upper()
                method_perms_str = method_permissions.get(method)
                if method_perms_str is None:
                    # No permissions specified for this method - allow access
                    if _is_bearer_token_request():
                        token = _get_bearer_token()
                        userinfo = _get_userinfo_from_token(token)
                        if not userinfo:
                            return _bearer_unauthorized(
                                {"error": "invalid_token", "message": "Invalid or expired token"}
                            )
                        g._rpr_token_info = userinfo
                    return f(*args, **kwargs)
                # Parse comma-separated permissions
                required_permissions = [p.strip() for p in method_perms_str.split(",")]
            else:
                required_permissions = permissions

            # Check for Bearer token (API mode)
            if _is_bearer_token_request():
                token = _get_bearer_token()
                userinfo = _get_userinfo_from_token(token)

                if not userinfo:
                    return _bearer_unauthorized(
                        {"error": "invalid_token", "message": "Invalid or expired token"}
                    )

                user_permissions = userinfo.get("permissions", [])

                # Check if token has ANY of the required permissions
                if not any(perm in user_permissions for perm in required_permissions):
                    logger.warning(
                        f'Permission denied: {userinfo.get("sub")} tried to access endpoint '
                        f"requiring one of {required_permissions}. Has: {user_permissions}"
                    )

                    message = (
                        f'One of these permissions required: {", ".join(required_permissions)}'
                    )
                    return _bearer_forbidden(
                        {
                            "error": "Forbidden",
                            "message": message,
                            "your_permissions": user_permissions,
                        },
                        description=message,
                    )

                g._rpr_token_info = userinfo
                return f(*args, **kwargs)

            # Session-based (browser mode)
            if not current_user.is_authenticated:
                abort(401)

            blocked = _check_user_status()
            if blocked:
                return blocked

            if not hasattr(current_user, "has_any_permission"):
                logger.error(f"User {current_user.get_id()} heeft geen has_any_permission method")
                abort(403)

            if not current_user.has_any_permission(*required_permissions):
                logger.warning(
                    f"User {current_user.get_id()} heeft geen van de permissions: "
                    f"{required_permissions}"
                )
                raise PermissionDeniedError(
                    message=f"Een van deze rechten is vereist: {', '.join(required_permissions)}"
                )

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def group_required(group=None, **method_groups):
    """
    Unified decorator that requires group membership via Bearer token OR session.

    NOTE: Only works for user tokens (not M2M tokens).
    Supports both single group and per-method groups.

    Args:
        group (str): Required group name (for all methods)
        **method_groups: Per-method groups (GET="viewers", POST="editors", etc.)

    Examples:
        # Single group for all methods
        @app.route('/staff')
        @group_required('staff')
        def staff_panel():
            return 'Staff panel'

        # Different groups per HTTP method
        @app.route('/content', methods=['GET', 'POST', 'DELETE'])
        @group_required(GET="viewers", POST="editors", DELETE="admins")
        def content_endpoint():
            return 'Content endpoint'
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Determine required group based on HTTP method
            if method_groups:
                method = request.method.upper()
                required_group = method_groups.get(method)
                if required_group is None:
                    # No group specified for this method - allow access
                    if _is_bearer_token_request():
                        token = _get_bearer_token()
                        userinfo = _get_userinfo_from_token(token)
                        if not userinfo:
                            return _bearer_unauthorized(
                                {"error": "invalid_token", "message": "Invalid or expired token"}
                            )
                        g._rpr_token_info = userinfo
                    return f(*args, **kwargs)
            else:
                required_group = group

            # Check for Bearer token (API mode)
            if _is_bearer_token_request():
                token = _get_bearer_token()
                userinfo = _get_userinfo_from_token(token)

                if not userinfo:
                    return _bearer_unauthorized(
                        {"error": "invalid_token", "message": "Invalid or expired token"}
                    )

                # Check if M2M token (M2M tokens hebben geen groups)
                if userinfo.get("token_type") == "m2m":
                    message = "M2M tokens cannot be checked for group membership. Use permission_required instead."
                    return _bearer_forbidden(
                        {"error": "Forbidden", "message": message}, description=message
                    )

                groups = userinfo.get("groups", [])

                if required_group not in groups:
                    logger.warning(
                        f'Group denied: {userinfo.get("sub")} not in group {required_group}'
                    )

                    return _bearer_forbidden(
                        {
                            "error": "Forbidden",
                            "message": f"{required_group} group membership required",
                            "your_groups": groups,
                        },
                        description=f"{required_group} group membership required",
                    )

                g._rpr_token_info = userinfo
                return f(*args, **kwargs)

            # Session-based (browser mode)
            if not current_user.is_authenticated:
                abort(401)

            blocked = _check_user_status()
            if blocked:
                return blocked

            if not hasattr(current_user, "in_group"):
                logger.error(f"User {current_user.get_id()} heeft geen in_group method")
                abort(403)

            if not current_user.in_group(required_group):
                logger.warning(f"User {current_user.get_id()} zit niet in groep: {required_group}")
                raise GroupDeniedError(group=required_group)

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def any_group_required(*groups, **method_groups):
    """
    Unified decorator that requires membership in ANY of the specified groups via Bearer token OR session.

    NOTE: Only works for user tokens (not M2M tokens).
    Supports both single set of groups and per-method groups.

    Args:
        *groups: Variable aantal group names (for all methods)
        **method_groups: Per-method group lists (GET="group1,group2", POST="group3,group4")

    Examples:
        # Single set of groups for all methods
        @app.route('/special')
        @any_group_required('vip', 'premium', 'admin')
        def special_content():
            return 'Special content'

        # Different group sets per HTTP method
        @app.route('/content', methods=['GET', 'POST'])
        @any_group_required(GET="viewers,guests", POST="editors,admins")
        def content_endpoint():
            return 'Content endpoint'
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Determine required groups based on HTTP method
            if method_groups:
                method = request.method.upper()
                method_grps_str = method_groups.get(method)
                if method_grps_str is None:
                    # No groups specified for this method - allow access
                    if _is_bearer_token_request():
                        token = _get_bearer_token()
                        userinfo = _get_userinfo_from_token(token)
                        if not userinfo:
                            return _bearer_unauthorized(
                                {"error": "invalid_token", "message": "Invalid or expired token"}
                            )
                        g._rpr_token_info = userinfo
                    return f(*args, **kwargs)
                # Parse comma-separated groups
                required_groups = [g.strip() for g in method_grps_str.split(",")]
            else:
                required_groups = groups

            # Check for Bearer token (API mode)
            if _is_bearer_token_request():
                token = _get_bearer_token()
                userinfo = _get_userinfo_from_token(token)

                if not userinfo:
                    return _bearer_unauthorized(
                        {"error": "invalid_token", "message": "Invalid or expired token"}
                    )

                # Check if M2M token
                if userinfo.get("token_type") == "m2m":
                    message = "M2M tokens cannot be checked for group membership. Use any_permission_required instead."
                    return _bearer_forbidden(
                        {"error": "Forbidden", "message": message}, description=message
                    )

                user_groups = userinfo.get("groups", [])

                if not any(g in user_groups for g in required_groups):
                    logger.warning(
                        f'Group denied: {userinfo.get("sub")} not in any of groups '
                        f"{required_groups}"
                    )

                    message = (
                        f'Membership in one of these groups required: {", ".join(required_groups)}'
                    )
                    return _bearer_forbidden(
                        {
                            "error": "Forbidden",
                            "message": message,
                            "your_groups": user_groups,
                        },
                        description=message,
                    )

                g._rpr_token_info = userinfo
                return f(*args, **kwargs)

            # Session-based (browser mode)
            if not current_user.is_authenticated:
                abort(401)

            blocked = _check_user_status()
            if blocked:
                return blocked

            if not hasattr(current_user, "in_any_group"):
                logger.error(f"User {current_user.get_id()} heeft geen in_any_group method")
                abort(403)

            if not current_user.in_any_group(*required_groups):
                logger.warning(
                    f"User {current_user.get_id()} zit niet in een van de groepen: "
                    f"{required_groups}"
                )
                raise GroupDeniedError(
                    message=(
                        f"Lidmaatschap van een van deze groepen is vereist: "
                        f"{', '.join(required_groups)}"
                    )
                )

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def require_2fa(f):
    """
    Decorator that requires the user to have completed 2FA.

    Supports both Bearer tokens (API) and session-based (browser) authentication.

    Bearer token mode:
        - User tokens: checks the `acr` claim in the userinfo response.
          `acr="mfa"` (TOTP) and `acr="phr"` (passkey) are accepted; `acr="pwd"` returns a
          401 RFC 9470 step-up challenge (`WWW-Authenticate: Bearer
          error="insufficient_user_authentication", acr_values="mfa"`), so the client knows
          to re-authenticate at a higher level via `/oauth/authorize?acr_values=mfa`.
        - M2M tokens: always rejected with 403 — M2M has no 2FA concept and cannot step up.

    Session mode:
        - Redirects to login if the user is not authenticated.
        - Starts a new OAuth flow with acr_values=mfa if 2FA has not been completed.

    Example:
        @app.route('/admin/dashboard')
        @require_2fa
        def admin_dashboard():
            return 'Admin Dashboard - 2FA required'

    Note:
        - Passkey login (`acr="phr"`) satisfies automatically — no additional 2FA requested.
        - 2FA completed in another app on the same auth server also satisfies (session
          is reused via OIDC step-up, no re-login required).
        - Checks the session first (fast); validates with the auth server if necessary.
        - Never send `prompt=login` via `require_2fa_reauth()` for regular routes:
          that clears the auth server session. Use `require_fresh_2fa()` for that instead.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Bearer token pad (API-mode)
        if _is_bearer_token_request():
            token = _get_bearer_token()
            userinfo = _get_userinfo_from_token(token)

            if not userinfo:
                return _bearer_unauthorized(
                    {"error": "invalid_token", "message": "Invalid or expired token"}
                )

            # M2M tokens hebben geen gebruiker en daarmee geen 2FA-concept
            if userinfo.get("token_type") == "m2m":
                logger.warning(
                    "require_2fa: M2M token van %s afgewezen voor %s",
                    userinfo.get("sub"),
                    request.path,
                )
                return (
                    jsonify(
                        {
                            "error": "mfa_required",
                            "message": "M2M tokens cannot satisfy 2FA requirement",
                        }
                    ),
                    403,
                )

            acr = userinfo.get("acr", "pwd")
            if acr not in ("mfa", "phr"):
                logger.warning(
                    "require_2fa: acr=%r onvoldoende voor %s op %s",
                    acr,
                    userinfo.get("sub"),
                    request.path,
                )
                # RFC 9470 step-up-challenge: het token is geldig, maar het auth-niveau is te
                # laag. Antwoord 401 met WWW-Authenticate: Bearer
                # error="insufficient_user_authentication", acr_values="mfa" — dan weet de
                # client machinaal dat de gebruiker naar /oauth/authorize (acr_values=mfa)
                # moet. De JSON-body blijft ongewijzigd (backwards-compatibel).
                return _bearer_unauthorized(
                    {"error": "mfa_required", "message": "2FA required (acr=mfa or phr)"},
                    error_code="insufficient_user_authentication",
                    acr_values="mfa",
                )

            g._rpr_token_info = userinfo
            return f(*args, **kwargs)

        # Sessie-pad (browser-mode)
        if not current_user.is_authenticated:
            session["next"] = request.url
            session.modified = True  # Forceer sessie-opslag in Redis/filesystem
            return redirect(url_for("auth.login"))

        blocked = _check_user_status()
        if blocked:
            return blocked

        # Haal RPRAuth instance op
        rpr_auth = current_app.extensions.get("rpr_auth")
        if not rpr_auth:
            logger.error("RPRAuth niet gevonden in extensions")
            abort(500)

        # Valideer 2FA status (checkt session + server indien nodig)
        if not rpr_auth.validate_2fa():
            logger.warning(
                f"User {current_user.get_id()} heeft geen 2FA validatie voor {request.path}"
            )

            # Sla de huidige URL op in session voor redirect na 2FA
            session["next"] = request.url
            session.modified = True  # Forceer sessie-opslag in Redis/filesystem

            # Start nieuwe OAuth flow met 2FA requirement (acr_values=mfa)
            return rpr_auth.require_2fa_reauth()

        return f(*args, **kwargs)

    return decorated_function


# Extra decorators for explicit user/m2m enforcement
def user_only(f):
    """
    Decorator: only user tokens allowed (API) or session users.
    API: blocks M2M tokens. Session: always allowed.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if _is_bearer_token_request():
            token = _get_bearer_token()
            userinfo = _get_userinfo_from_token(token)
            if not userinfo:
                return _bearer_unauthorized(
                    {"error": "invalid_token", "message": "Invalid or expired token"}
                )
            if userinfo.get("token_type") == "m2m":
                return (
                    jsonify(
                        {
                            "error": "Forbidden",
                            "message": "This endpoint requires a user token, not M2M",
                        }
                    ),
                    403,
                )
            g._rpr_token_info = userinfo
            return f(*args, **kwargs)
        # Session: altijd toegestaan
        return f(*args, **kwargs)

    return decorated_function


def m2m_only(f):
    """
    Decorator: only M2M tokens allowed (API). Session users are blocked.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if _is_bearer_token_request():
            token = _get_bearer_token()
            userinfo = _get_userinfo_from_token(token)
            if not userinfo:
                return _bearer_unauthorized(
                    {"error": "invalid_token", "message": "Invalid or expired token"}
                )
            if userinfo.get("token_type") != "m2m":
                return (
                    jsonify(
                        {
                            "error": "Forbidden",
                            "message": "This endpoint requires an M2M token, not user",
                        }
                    ),
                    403,
                )
            g._rpr_token_info = userinfo
            return f(*args, **kwargs)
        # Session: nooit toegestaan
        return jsonify({"error": "Forbidden", "message": "Session users not allowed"}), 403

    return decorated_function


def require_scope(*scopes):
    """
    Decorator that requires the underlying OAuth token to carry ALL given scopes.

    This checks true OAuth ``scope`` (RFC 6749 §3.3), independent of RPR permissions
    (``permission_required``) — useful for e.g. an MCP server that gates tools by scope
    rather than by RPR permission.

    Bearer token mode:
        ``/oauth/userinfo`` doesn't return ``scope`` for user tokens, so the scope check
        uses the (cached) introspection response instead (``helpers.get_token_scopes``,
        RFC 7662). A missing scope returns 403 with ``WWW-Authenticate: Bearer
        error="insufficient_scope"`` naming exactly the scopes this route requires.

    Session mode:
        Checks the ``scope`` stored on the session's OAuth token.

    Example:
        @app.route('/mcp/tools/deploy')
        @require_scope('gms.deploy')
        def deploy_tool():
            return 'Deploy tool'
    """
    required = set(scopes)

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if _is_bearer_token_request():
                token = _get_bearer_token()
                userinfo = _get_userinfo_from_token(token)

                if not userinfo:
                    return _bearer_unauthorized(
                        {"error": "invalid_token", "message": "Invalid or expired token"}
                    )

                from .helpers import get_token_scopes

                token_scopes = get_token_scopes(token)

                if not required.issubset(token_scopes):
                    logger.warning(
                        "require_scope: %s mist scope(s) %s (heeft: %s)",
                        userinfo.get("sub", "unknown"),
                        sorted(required - token_scopes),
                        sorted(token_scopes),
                    )
                    return _bearer_forbidden(
                        {
                            "error": "Forbidden",
                            "message": f'Missing required scope(s): {", ".join(sorted(required))}',
                            "your_scopes": sorted(token_scopes),
                        },
                        required_scopes=sorted(required),
                        description=f'Missing required scope(s): {", ".join(sorted(required))}',
                    )

                g._rpr_token_info = userinfo
                return f(*args, **kwargs)

            # Session-based (browser mode): scope lives on the stored OAuth token.
            if not current_user.is_authenticated:
                abort(401)

            blocked = _check_user_status()
            if blocked:
                return blocked

            token_scopes = set(session.get("oauth_token", {}).get("scope", "").split())
            if not required.issubset(token_scopes):
                logger.warning(
                    "require_scope: user %s mist scope(s) %s",
                    current_user.get_id(),
                    sorted(required - token_scopes),
                )
                raise PermissionDeniedError(
                    message=f'Missing required scope(s): {", ".join(sorted(required))}'
                )

            return f(*args, **kwargs)

        return decorated_function

    return decorator


__all__ = [
    "login_required",
    "permission_required",
    "any_permission_required",
    "group_required",
    "any_group_required",
    "require_2fa",
    "require_scope",
    "user_only",
    "m2m_only",
]
