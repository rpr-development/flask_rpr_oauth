"""
flask_rpr_oauth.decorators
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unified decorators that work for BOTH session-based (browser) and stateless (API) authentication.
Automatically detects Bearer tokens and falls back to session-based auth.
"""

import logging
from functools import wraps
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


def _is_bearer_token_request():
    """Check if request uses Bearer token authentication (API mode)."""
    auth_header = request.headers.get("Authorization", "")
    return auth_header.startswith("Bearer ")


def _get_bearer_token():
    """Extract Bearer token from Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]  # Remove 'Bearer '
    return None


def _get_userinfo_from_token(token):
    """Get userinfo from Bearer token via OAuth server."""
    from .helpers import get_userinfo_from_token

    return get_userinfo_from_token(token)


def _resource_metadata_url():
    """URL van het protected-resource-metadata-document van deze resource server (RFC 9728).

    Voorkeur voor ``OAUTH_RESOURCE_ID`` (de canonieke resource-URI van deze app); anders de
    host van het huidige request.
    """
    base = current_app.config.get("OAUTH_RESOURCE_ID") or request.host_url
    return f"{base.rstrip('/')}/.well-known/oauth-protected-resource"


def _bearer_unauthorized(payload, *, error_code="invalid_token", acr_values=None):
    """Bouw een 401-response met een RFC 6750 ``WWW-Authenticate: Bearer``-challenge.

    De challenge draagt ``resource_metadata`` (RFC 9728), zodat een client bij een 401
    automatisch de juiste authorization server + audience kan ontdekken. ``error_code`` en
    ``acr_values`` zijn parameters zodat een RFC 9470 step-up-challenge
    (``error="insufficient_user_authentication"``, ``acr_values="mfa"``) hier later op kan
    aanhaken. ``payload`` blijft het bestaande JSON-body-formaat (backwards-compatibel).
    """
    response = jsonify(payload)
    response.status_code = 401
    challenge = f'Bearer resource_metadata="{_resource_metadata_url()}"'
    if error_code:
        challenge += f', error="{error_code}"'
    if acr_values:
        challenge += f', acr_values="{acr_values}"'
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
                return _bearer_unauthorized({"error": "Invalid or expired token"})

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
                            return _bearer_unauthorized({"error": "Invalid or expired token"})
                        g._rpr_token_info = userinfo
                    return f(*args, **kwargs)
            else:
                required_permission = permission

            # Check for Bearer token (API mode)
            if _is_bearer_token_request():
                token = _get_bearer_token()
                userinfo = _get_userinfo_from_token(token)

                if not userinfo:
                    return _bearer_unauthorized({"error": "Invalid or expired token"})

                # Check permission for API token
                permissions = userinfo.get("permissions", [])

                if required_permission not in permissions:
                    token_type = userinfo.get("token_type", "unknown")
                    subject = userinfo.get("sub", "unknown")

                    logger.warning(
                        f"Permission denied: {subject} ({token_type}) tried to access "
                        f"{required_permission}. Available permissions: {permissions}"
                    )

                    return (
                        jsonify(
                            {
                                "error": "Forbidden",
                                "message": f"{required_permission} permission required",
                                "your_permissions": permissions,
                            }
                        ),
                        403,
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
                            return _bearer_unauthorized({"error": "Invalid or expired token"})
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
                    return _bearer_unauthorized({"error": "Invalid or expired token"})

                user_permissions = userinfo.get("permissions", [])

                # Check if token has ANY of the required permissions
                if not any(perm in user_permissions for perm in required_permissions):
                    logger.warning(
                        f'Permission denied: {userinfo.get("sub")} tried to access endpoint '
                        f"requiring one of {required_permissions}. Has: {user_permissions}"
                    )

                    return (
                        jsonify(
                            {
                                "error": "Forbidden",
                                "message": (
                                    f'One of these permissions required: '
                                    f'{", ".join(required_permissions)}'
                                ),
                                "your_permissions": user_permissions,
                            }
                        ),
                        403,
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
                            return _bearer_unauthorized({"error": "Invalid or expired token"})
                        g._rpr_token_info = userinfo
                    return f(*args, **kwargs)
            else:
                required_group = group

            # Check for Bearer token (API mode)
            if _is_bearer_token_request():
                token = _get_bearer_token()
                userinfo = _get_userinfo_from_token(token)

                if not userinfo:
                    return _bearer_unauthorized({"error": "Invalid or expired token"})

                # Check if M2M token (M2M tokens hebben geen groups)
                if userinfo.get("token_type") == "m2m":
                    return (
                        jsonify(
                            {
                                "error": "Forbidden",
                                "message": (
                                    "M2M tokens cannot be checked for group membership. "
                                    "Use permission_required instead."
                                ),
                            }
                        ),
                        403,
                    )

                groups = userinfo.get("groups", [])

                if required_group not in groups:
                    logger.warning(
                        f'Group denied: {userinfo.get("sub")} not in group {required_group}'
                    )

                    return (
                        jsonify(
                            {
                                "error": "Forbidden",
                                "message": f"{required_group} group membership required",
                                "your_groups": groups,
                            }
                        ),
                        403,
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
                            return _bearer_unauthorized({"error": "Invalid or expired token"})
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
                    return _bearer_unauthorized({"error": "Invalid or expired token"})

                # Check if M2M token
                if userinfo.get("token_type") == "m2m":
                    return (
                        jsonify(
                            {
                                "error": "Forbidden",
                                "message": (
                                    "M2M tokens cannot be checked for group membership. "
                                    "Use any_permission_required instead."
                                ),
                            }
                        ),
                        403,
                    )

                user_groups = userinfo.get("groups", [])

                if not any(g in user_groups for g in required_groups):
                    logger.warning(
                        f'Group denied: {userinfo.get("sub")} not in any of groups '
                        f"{required_groups}"
                    )

                    return (
                        jsonify(
                            {
                                "error": "Forbidden",
                                "message": (
                                    f'Membership in one of these groups required: '
                                    f'{", ".join(required_groups)}'
                                ),
                                "your_groups": user_groups,
                            }
                        ),
                        403,
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
                return jsonify({"error": "mfa_required", "message": "M2M tokens cannot satisfy 2FA requirement"}), 403

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
                return _bearer_unauthorized({"error": "Invalid or expired token"})
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
                return _bearer_unauthorized({"error": "Invalid or expired token"})
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


__all__ = [
    "login_required",
    "permission_required",
    "any_permission_required",
    "group_required",
    "any_group_required",
    "require_2fa",
    "user_only",
    "m2m_only",
]
