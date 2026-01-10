"""
flask_rpr_oauth.helpers
~~~~~~~~~~~~~~~~~~~~~~

Helper functies voor het ophalen en cachen van userinfo via de OAuth server.
Geschikt voor gebruik in zowel API (Bearer tokens) als session-based authenticatie.
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
    """Leeg de userinfo cache (voor testing/development)."""
    global _userinfo_cache
    _userinfo_cache = {}
    logger.info("Userinfo cache cleared")

__all__ = [
    "get_userinfo_from_token",
    "clear_userinfo_cache",
]
