"""
flask_rpr_oauth.decorators
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Decorators voor permission en group checks.
"""

import logging
from functools import wraps
from flask import abort, current_app, session, redirect, url_for, request
from .models import current_user
from .exceptions import PermissionDeniedError, GroupDeniedError


logger = logging.getLogger(__name__)


def login_required(f):
    """
    Decorator die vereist dat gebruiker is ingelogd.

    Checkt of user in session zit en redirect naar login indien niet.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            # Store next URL in session
            session["next"] = request.url
            # Redirect to login
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)

    return decorated_function


def permission_required(permission):
    """
    Decorator die vereist dat gebruiker een specifieke permission heeft.

    Args:
        permission (str): Required permission string

    Example:
        @app.route('/admin')
        @login_required
        @permission_required('admin.access')
        def admin_panel():
            return 'Admin panel'
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
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
    Decorator die vereist dat gebruiker één van de opgegeven permissions heeft.

    Args:
        *permissions: Variable aantal permission strings

    Example:
        @app.route('/moderate')
        @login_required
        @any_permission_required('moderator', 'admin')
        def moderate():
            return 'Moderation panel'
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
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
    Decorator die vereist dat gebruiker in een specifieke groep zit.

    Args:
        group (str): Required group name

    Example:
        @app.route('/staff')
        @login_required
        @group_required('staff')
        def staff_panel():
            return 'Staff panel'
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
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
    Decorator die vereist dat gebruiker in één van de opgegeven groepen zit.

    Args:
        *groups: Variable aantal group names

    Example:
        @app.route('/special')
        @login_required
        @any_group_required('vip', 'premium', 'admin')
        def special_content():
            return 'Special content'
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
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


__all__ = [
    "login_required",
    "permission_required",
    "any_permission_required",
    "group_required",
    "any_group_required",
    "require_2fa",
]
