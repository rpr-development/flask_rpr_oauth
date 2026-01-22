"""
flask_rpr_oauth.decorators
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unified decorators that work for BOTH session-based (browser) and stateless (API) authentication.
Automatically detects Bearer tokens and falls back to session-based auth.
"""

import logging
from functools import wraps
from flask import abort, current_app, session, redirect, url_for, request, jsonify
from .models import current_user
from .exceptions import PermissionDeniedError, GroupDeniedError


logger = logging.getLogger(__name__)


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


def login_required(f):
    """
    Unified decorator that requires authentication via Bearer token OR session.

    - Bearer token (API): Validates token and injects 'userinfo' kwarg
    - Session (browser): Checks current_user and redirects to login if needed

    Usage:
        @login_required
        def my_endpoint(userinfo=None):
            # For API calls: userinfo contains token data
            # For browser: userinfo is None, use current_user instead
            if userinfo:
                user_id = userinfo['sub']  # API mode
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
                return jsonify({"error": "Invalid or expired token"}), 401

            # Inject userinfo for API calls
            kwargs["userinfo"] = userinfo
            return f(*args, **kwargs)

        # Session-based (browser mode)
        if not current_user.is_authenticated:
            # AJAX/fetch requests krijgen 401 JSON
            if _is_ajax_request():
                return jsonify({"error": "Authentication required"}), 401

            # Store next URL in session
            session["next"] = request.url
            # Redirect to login
            return redirect(url_for("auth.login"))

        return f(*args, **kwargs)

    return decorated_function


def permission_required(permission):
    """
    Unified decorator that requires a specific permission via Bearer token OR session.

    Works for BOTH user tokens AND M2M tokens in API mode.

    Args:
        permission (str): Required permission string

    Example:
        @app.route('/admin')
        @permission_required('admin.access')
        def admin_panel(userinfo=None):
            # Works for both API and browser requests
            return 'Admin panel'
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check for Bearer token (API mode)
            if _is_bearer_token_request():
                token = _get_bearer_token()
                userinfo = _get_userinfo_from_token(token)

                if not userinfo:
                    return jsonify({"error": "Invalid or expired token"}), 401

                # Check permission for API token
                permissions = userinfo.get("permissions", [])

                if permission not in permissions:
                    token_type = userinfo.get("token_type", "unknown")
                    subject = userinfo.get("sub", "unknown")

                    logger.warning(
                        f"Permission denied: {subject} ({token_type}) tried to access {permission}. "
                        f"Available permissions: {permissions}"
                    )

                    return (
                        jsonify(
                            {
                                "error": "Forbidden",
                                "message": f"{permission} permission required",
                                "your_permissions": permissions,
                            }
                        ),
                        403,
                    )

                # Inject userinfo for API calls
                kwargs["userinfo"] = userinfo
                return f(*args, **kwargs)

            # Session-based (browser mode)
            if not current_user.is_authenticated:
                abort(401)

            if not hasattr(current_user, "has_permission"):
                logger.error(f"User {current_user.get_id()} heeft geen has_permission method")
                abort(403)

            if not current_user.has_permission(permission):
                logger.warning(f"User {current_user.get_id()} heeft geen permission: {permission}")
                raise PermissionDeniedError(permission=permission)

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def any_permission_required(*permissions):
    """
    Unified decorator that requires ANY of the specified permissions via Bearer token OR session.

    Args:
        *permissions: Variable aantal permission strings

    Example:
        @app.route('/moderate')
        @any_permission_required('moderator', 'admin')
        def moderate(userinfo=None):
            # Works for both API and browser requests
            return 'Moderation panel'
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check for Bearer token (API mode)
            if _is_bearer_token_request():
                token = _get_bearer_token()
                userinfo = _get_userinfo_from_token(token)

                if not userinfo:
                    return jsonify({"error": "Invalid or expired token"}), 401

                user_permissions = userinfo.get("permissions", [])

                # Check if token has ANY of the required permissions
                if not any(perm in user_permissions for perm in permissions):
                    logger.warning(
                        f'Permission denied: {userinfo.get("sub")} tried to access endpoint requiring '
                        f"one of {permissions}. Has: {user_permissions}"
                    )

                    return (
                        jsonify(
                            {
                                "error": "Forbidden",
                                "message": f'One of these permissions required: {", ".join(permissions)}',
                                "your_permissions": user_permissions,
                            }
                        ),
                        403,
                    )

                kwargs["userinfo"] = userinfo
                return f(*args, **kwargs)

            # Session-based (browser mode)
            if not current_user.is_authenticated:
                abort(401)

            if not hasattr(current_user, "has_any_permission"):
                logger.error(f"User {current_user.get_id()} heeft geen has_any_permission method")
                abort(403)

            if not current_user.has_any_permission(*permissions):
                logger.warning(
                    f"User {current_user.get_id()} heeft geen van de permissions: {permissions}"
                )
                raise PermissionDeniedError(
                    message=f"Een van deze rechten is vereist: {', '.join(permissions)}"
                )

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def group_required(group):
    """
    Unified decorator that requires group membership via Bearer token OR session.

    NOTE: Only works for user tokens (not M2M tokens).

    Args:
        group (str): Required group name

    Example:
        @app.route('/staff')
        @group_required('staff')
        def staff_panel(userinfo=None):
            # Works for both API and browser requests
            return 'Staff panel'
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check for Bearer token (API mode)
            if _is_bearer_token_request():
                token = _get_bearer_token()
                userinfo = _get_userinfo_from_token(token)

                if not userinfo:
                    return jsonify({"error": "Invalid or expired token"}), 401

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

                if group not in groups:
                    logger.warning(f'Group denied: {userinfo.get("sub")} not in group {group}')

                    return (
                        jsonify(
                            {
                                "error": "Forbidden",
                                "message": f"{group} group membership required",
                                "your_groups": groups,
                            }
                        ),
                        403,
                    )

                kwargs["userinfo"] = userinfo
                return f(*args, **kwargs)

            # Session-based (browser mode)
            if not current_user.is_authenticated:
                abort(401)

            if not hasattr(current_user, "in_group"):
                logger.error(f"User {current_user.get_id()} heeft geen in_group method")
                abort(403)

            if not current_user.in_group(group):
                logger.warning(f"User {current_user.get_id()} zit niet in groep: {group}")
                raise GroupDeniedError(group=group)

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def any_group_required(*groups):
    """
    Unified decorator that requires membership in ANY of the specified groups via Bearer token OR session.

    NOTE: Only works for user tokens (not M2M tokens).

    Args:
        *groups: Variable aantal group names

    Example:
        @app.route('/special')
        @any_group_required('vip', 'premium', 'admin')
        def special_content(userinfo=None):
            # Works for both API and browser requests
            return 'Special content'
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check for Bearer token (API mode)
            if _is_bearer_token_request():
                token = _get_bearer_token()
                userinfo = _get_userinfo_from_token(token)

                if not userinfo:
                    return jsonify({"error": "Invalid or expired token"}), 401

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

                if not any(g in user_groups for g in groups):
                    logger.warning(
                        f'Group denied: {userinfo.get("sub")} not in any of groups {groups}'
                    )

                    return (
                        jsonify(
                            {
                                "error": "Forbidden",
                                "message": f'Membership in one of these groups required: {", ".join(groups)}',
                                "your_groups": user_groups,
                            }
                        ),
                        403,
                    )

                kwargs["userinfo"] = userinfo
                return f(*args, **kwargs)

            # Session-based (browser mode)
            if not current_user.is_authenticated:
                abort(401)

            if not hasattr(current_user, "in_any_group"):
                logger.error(f"User {current_user.get_id()} heeft geen in_any_group method")
                abort(403)

            if not current_user.in_any_group(*groups):
                logger.warning(
                    f"User {current_user.get_id()} zit niet in een van de groepen: {groups}"
                )
                raise GroupDeniedError(
                    message=f"Lidmaatschap van een van deze groepen is vereist: {', '.join(groups)}"
                )

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def require_2fa(f):
    """
    Decorator die vereist dat gebruiker 2FA heeft voltooid.

    Als de gebruiker niet is ingelogd, redirect naar login.
    Als de gebruiker geen 2FA heeft voltooid, start een nieuwe OAuth flow met acr_values=mfa.

    Example:
        @app.route('/admin/dashboard')
        @require_2fa
        def admin_dashboard():
            return 'Admin Dashboard - 2FA required'

    Note:
        Deze decorator checkt eerst de session (snel), en valideert daarna
        met de auth server indien nodig. Als 2FA ontbreekt, wordt de gebruiker
        doorgestuurd naar een nieuwe OAuth flow met 2FA requirement.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check of user is ingelogd
        if not current_user.is_authenticated:
            session["next"] = request.url
            return redirect(url_for("auth.login"))

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

            # Start nieuwe OAuth flow met 2FA requirement (acr_values=mfa)
            return rpr_auth.require_2fa_reauth()

        return f(*args, **kwargs)

    return decorated_function


# Extra decorators for explicit user/m2m enforcement
def user_only(f):
    """
    Decorator: alleen user tokens toegestaan (API) of session user.
    API: blokkeert M2M tokens. Session: altijd toegestaan.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if _is_bearer_token_request():
            token = _get_bearer_token()
            userinfo = _get_userinfo_from_token(token)
            if not userinfo:
                return jsonify({"error": "Invalid or expired token"}), 401
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
            kwargs["userinfo"] = userinfo
            return f(*args, **kwargs)
        # Session: altijd toegestaan
        return f(*args, **kwargs)

    return decorated_function


def m2m_only(f):
    """
    Decorator: alleen M2M tokens toegestaan (API). Session users geblokkeerd.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if _is_bearer_token_request():
            token = _get_bearer_token()
            userinfo = _get_userinfo_from_token(token)
            if not userinfo:
                return jsonify({"error": "Invalid or expired token"}), 401
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
            kwargs["userinfo"] = userinfo
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
