"""
flask_rpr_oauth.stateless
~~~~~~~~~~~~~~~~~~~~~~~~~~

Stateless decorators voor API endpoints die Bearer tokens gebruiken.
Geen session management - ideaal voor M2M tokens en REST APIs.

Werkt voor BEIDE:
- User tokens (authorization_code, password flow)
- M2M tokens (client_credentials flow)
"""

import logging
from functools import wraps
from typing import Dict, Tuple
from flask import request, jsonify, current_app
import requests

logger = logging.getLogger(__name__)

# Simple in-memory cache voor userinfo (voorkomt herhaalde API calls)
_userinfo_cache: Dict[str, Tuple[dict, float]] = {}


def get_userinfo_from_token(token):
    """
    Haal userinfo op via het /oauth/userinfo endpoint.

    Werkt voor zowel user tokens als M2M tokens.

    Args:
        token (str): Access token

    Returns:
        dict: Userinfo response of None bij error

    Example voor M2M token:
        {
            "sub": "fivem-server-1",  # client_id als subject
            "client_id": "fivem-server-1",
            "token_type": "m2m",
            "application_name": "fivem",
            "application_id": 5,
            "permissions": ["fivem.player.kick", "fivem.player.ban"],
            "groups": [],
            "scopes": ["openid", "profile"]
        }

    Example voor User token:
        {
            "sub": "12345",  # user_id als subject
            "token_type": "user",
            "email": "user@example.com",
            "name": "John Doe",
            "permissions": ["admin.users.view"],
            "groups": ["administrators"],
            "twofa_validated": true
        }
    """
    # Check cache
    if token in _userinfo_cache:
        logger.debug("Userinfo cache hit")
        return _userinfo_cache[token]

    oauth_base_url = current_app.config.get("OAUTH_BASE_URL")
    if not oauth_base_url:
        logger.error("OAUTH_BASE_URL not configured")
        return None

    try:
        response = requests.get(
            f"{oauth_base_url}/oauth/userinfo",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )

        if response.status_code == 200:
            userinfo = response.json()
            # Cache userinfo (simpele cache zonder expiry - productie zou Redis gebruiken)
            _userinfo_cache[token] = userinfo
            logger.debug(
                f'Userinfo fetched - token_type: {userinfo.get("token_type")}, '
                f'sub: {userinfo.get("sub")}, permissions: {len(userinfo.get("permissions", []))}'
            )
            return userinfo
        else:
            logger.warning(f"Userinfo request failed: {response.status_code}")
            return None

    except Exception as e:
        logger.error(f"Userinfo request error: {e}")
        return None


def clear_userinfo_cache():
    """Clear de userinfo cache (voor testing/development)."""
    global _userinfo_cache
    _userinfo_cache = {}
    logger.info("Userinfo cache cleared")


def token_required(f):
    """
    Decorator die vereist dat request een geldig Bearer token heeft.

    Werkt voor zowel user tokens als M2M tokens.
    De userinfo wordt toegevoegd aan kwargs als 'userinfo' parameter.

    Usage:
        @token_required
        def my_endpoint(userinfo):
            # Voor M2M token:
            if userinfo.get('token_type') == 'm2m':
                client_id = userinfo.get('client_id')
                app_name = userinfo.get('application_name')

            # Voor User token:
            else:
                user_id = userinfo.get('sub')
                email = userinfo.get('email')

            return {'status': 'success'}
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header[7:]  # Remove 'Bearer '

        # Valideer token via userinfo endpoint
        userinfo = get_userinfo_from_token(token)

        if not userinfo:
            return jsonify({"error": "Invalid or expired token"}), 401

        # Voeg userinfo toe aan kwargs
        kwargs["userinfo"] = userinfo

        return f(*args, **kwargs)

    return decorated_function


def permission_required_stateless(permission):
    """
    Stateless decorator die vereist dat token een specifieke permission heeft.

    Werkt voor ZOWEL user tokens ALS M2M tokens!

    Voor M2M tokens: Checkt of permission bestaat voor die applicatie
    Voor User tokens: Checkt of gebruiker die permission heeft

    Args:
        permission (str): Required permission string

    Usage:
        @permission_required_stateless('fivem.player.kick')
        def kick_player(userinfo):
            # Werkt voor BEIDE:
            # 1. M2M token met fivem.player.kick permission
            # 2. User token met fivem.player.kick permission

            token_type = userinfo.get('token_type')
            if token_type == 'm2m':
                logger.info(f"M2M action by {userinfo['client_id']}")
            else:
                logger.info(f"User action by {userinfo['email']}")

            return {'status': 'success'}
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")

            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "Missing or invalid Authorization header"}), 401

            token = auth_header[7:]

            # Haal userinfo op (werkt voor user EN M2M tokens)
            userinfo = get_userinfo_from_token(token)

            if not userinfo:
                return jsonify({"error": "Invalid or expired token"}), 401

            # Check permission (werkt voor BEIDE token types)
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

            # Voeg userinfo toe aan kwargs
            kwargs["userinfo"] = userinfo

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def any_permission_required_stateless(*permissions):
    """
    Stateless decorator die vereist dat token één van de opgegeven permissions heeft.

    Werkt voor zowel user tokens als M2M tokens.

    Args:
        *permissions: Variable aantal permission strings

    Usage:
        @any_permission_required_stateless('fivem.player.kick', 'fivem.player.ban')
        def moderate(userinfo):
            # Toegang als token MINIMAAL ÉÉN van deze permissions heeft
            return {'status': 'success'}
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")

            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "Missing or invalid Authorization header"}), 401

            token = auth_header[7:]
            userinfo = get_userinfo_from_token(token)

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

        return decorated_function

    return decorator


def scope_required_stateless(scope):
    """
    Stateless decorator die vereist dat token een specifieke scope heeft.

    Gebruik voor scope-based checks (bijv. 'admin', 'openid').
    Werkt voor zowel user als M2M tokens.

    Args:
        scope (str): Required scope string

    Usage:
        @scope_required_stateless('admin')
        def admin_endpoint(userinfo):
            return {'status': 'success'}
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")

            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "Missing or invalid Authorization header"}), 401

            token = auth_header[7:]
            userinfo = get_userinfo_from_token(token)

            if not userinfo:
                return jsonify({"error": "Invalid or expired token"}), 401

            scopes = userinfo.get("scopes", [])

            if scope not in scopes:
                logger.warning(f'Scope denied: {userinfo.get("sub")} missing scope {scope}')

                return (
                    jsonify(
                        {
                            "error": "Forbidden",
                            "message": f"{scope} scope required",
                            "your_scopes": scopes,
                        }
                    ),
                    403,
                )

            kwargs["userinfo"] = userinfo
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def group_required_stateless(group):
    """
    Stateless decorator die vereist dat user in een specifieke groep zit.

    NOTE: Werkt ALLEEN voor user tokens!
    M2M tokens hebben geen groups en worden afgewezen door deze decorator.

    Args:
        group (str): Required group name

    Usage:
        @group_required_stateless('administrators')
        def admin_panel(userinfo):
            # Alleen toegankelijk voor users in 'administrators' groep
            return {'status': 'success'}
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")

            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "Missing or invalid Authorization header"}), 401

            token = auth_header[7:]
            userinfo = get_userinfo_from_token(token)

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
                                "Use permission_required_stateless instead."
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

        return decorated_function

    return decorator


def user_only(f):
    """
    Decorator die vereist dat token een USER token is (geen M2M).

    Gebruik dit als je expliciet M2M tokens wilt blokkeren.

    Usage:
        @user_only
        @permission_required_stateless('admin.users.view')
        def get_profile(userinfo):
            # Alleen user tokens toegestaan
            email = userinfo['email']
            return {'email': email}
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header[7:]
        userinfo = get_userinfo_from_token(token)

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

    return decorated_function


def m2m_only(f):
    """
    Decorator die vereist dat token een M2M token is (geen user).

    Gebruik dit als je expliciet user tokens wilt blokkeren.

    Usage:
        @m2m_only
        @permission_required_stateless('fivem.server.status')
        def server_heartbeat(userinfo):
            # Alleen M2M tokens toegestaan
            client_id = userinfo['client_id']
            return {'status': 'ok'}
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header[7:]
        userinfo = get_userinfo_from_token(token)

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

    return decorated_function


__all__ = [
    "token_required",
    "permission_required_stateless",
    "any_permission_required_stateless",
    "scope_required_stateless",
    "group_required_stateless",
    "user_only",
    "m2m_only",
    "get_userinfo_from_token",
    "clear_userinfo_cache",
]
