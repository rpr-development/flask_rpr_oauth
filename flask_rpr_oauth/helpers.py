"""
flask_rpr_oauth.helpers
~~~~~~~~~~~~~~~~~~~~~~

Helper functions for fetching and caching userinfo via the OAuth server.
Suitable for both API (Bearer token) and session-based authentication.

Token validation order:
  1. /oauth/userinfo  — works for user tokens (authorization_code flow)
  2. /oauth/introspect — fallback for M2M tokens (client_credentials flow),
                         which receive 403 on userinfo
"""

import logging
from typing import Dict, Tuple
from flask import current_app
import requests

logger = logging.getLogger(__name__)

# Simple in-memory cache voor userinfo (voorkomt herhaalde API calls)
_userinfo_cache: Dict[str, Tuple[dict, float]] = {}


def get_userinfo_from_token(token):
    """
    Fetch userinfo for an access token.

    Tries /oauth/userinfo first (user tokens). If the server returns 403
    (typical for M2M client_credentials tokens), falls back to
    /oauth/introspect.

    Args:
        token (str): Access token

    Returns:
        dict: Userinfo/introspection response, or None on error
    """
    if token in _userinfo_cache:
        logger.debug("Userinfo cache hit")
        return _userinfo_cache[token]

    oauth_base_url = current_app.config.get("OAUTH_BASE_URL")
    if not oauth_base_url:
        logger.error("OAUTH_BASE_URL not configured")
        return None

    # Stap 1: probeer userinfo (werkt voor user tokens)
    try:
        response = requests.get(
            f"{oauth_base_url}/oauth/userinfo",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )

        if response.status_code == 200:
            userinfo = response.json()
            _userinfo_cache[token] = userinfo
            logger.debug(
                f'Userinfo fetched - token_type: {userinfo.get("token_type")}, '
                f'sub: {userinfo.get("sub")}, permissions: {len(userinfo.get("permissions", []))}'
            )
            return userinfo

        if response.status_code != 403:
            logger.warning(f"Userinfo request failed: {response.status_code}")
            return None

        # 403 = token is geldig maar heeft geen userinfo toegang (M2M token)
        logger.debug("Userinfo returned 403, falling back to token introspection")

    except Exception as e:
        logger.error(f"Userinfo request error: {e}")
        return None

    # Stap 2: introspection fallback voor M2M tokens
    return _introspect_token(token, oauth_base_url)


def _introspect_token(token: str, oauth_base_url: str) -> dict | None:
    """
    Validate a token via the /oauth/introspect endpoint.

    Uses OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET as HTTP Basic Auth,
    per RFC 7662 (Token Introspection).

    Returns:
        dict with token claims including 'token_type': 'm2m', or None on error
    """
    client_id = current_app.config.get("OAUTH_CLIENT_ID")
    client_secret = current_app.config.get("OAUTH_CLIENT_SECRET")

    if not client_id or not client_secret:
        logger.error("Token introspection vereist OAUTH_CLIENT_ID en OAUTH_CLIENT_SECRET")
        return None

    try:
        response = requests.post(
            f"{oauth_base_url}/oauth/introspect",
            data={"token": token},
            auth=(client_id, client_secret),
            timeout=10,
        )

        if response.status_code != 200:
            logger.warning(f"Token introspection failed: {response.status_code}")
            return None

        data = response.json()

        if not data.get("active"):
            logger.debug("Token introspection: token is not active")
            return None

        _userinfo_cache[token] = data
        logger.debug(
            f'Token introspected - token_type: {data.get("token_type")}, '
            f'sub: {data.get("sub")}, permissions: {len(data.get("permissions", []))}'
        )
        return data

    except Exception as e:
        logger.error(f"Token introspection error: {e}")
        return None


def clear_userinfo_cache():
    """Clear the userinfo cache (for testing/development)."""
    global _userinfo_cache
    _userinfo_cache = {}
    logger.info("Userinfo cache cleared")


__all__ = [
    "get_userinfo_from_token",
    "clear_userinfo_cache",
]
