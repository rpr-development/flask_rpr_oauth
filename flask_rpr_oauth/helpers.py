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
import threading
import time
from typing import Dict, Tuple, Optional
from flask import current_app
import requests

logger = logging.getLogger(__name__)

# In-memory cache voor userinfo (voorkomt herhaalde API calls).
# Value = (userinfo dict, expiry timestamp). Een TTL is essentieel: zonder
# verloop zou een ingetrokken of verlopen token tot proces-herstart geldig
# blijven in API-mode. De cache is bovendien begrensd om geheugengroei
# (één entry per uniek token) te voorkomen.
_userinfo_cache: Dict[str, Tuple[dict, float]] = {}
# Beschermt _userinfo_cache: onder Gunicorn threads/gevent muteren meerdere requests
# de dict tegelijk (iteratie + pop in _cache_set) → anders RuntimeError/corruptie.
_cache_lock = threading.Lock()

# Defaults; overschrijfbaar via Flask config.
_DEFAULT_CACHE_TTL = 60  # seconden — begrenst het revocatie-venster
_DEFAULT_CACHE_MAXSIZE = 1000  # max aantal tokens in de cache


def _cache_ttl() -> int:
    """TTL (seconden) voor de userinfo-cache; 0 schakelt caching uit."""
    try:
        return int(current_app.config.get("OAUTH_USERINFO_CACHE_TTL", _DEFAULT_CACHE_TTL))
    except (RuntimeError, TypeError, ValueError):
        return _DEFAULT_CACHE_TTL


def _cache_maxsize() -> int:
    try:
        return int(current_app.config.get("OAUTH_USERINFO_CACHE_MAXSIZE", _DEFAULT_CACHE_MAXSIZE))
    except (RuntimeError, TypeError, ValueError):
        return _DEFAULT_CACHE_MAXSIZE


def _cache_get(token: str) -> Optional[dict]:
    """Return cached userinfo if present and not expired, else None."""
    with _cache_lock:
        entry = _userinfo_cache.get(token)
        if entry is None:
            return None
        userinfo, expires_at = entry
        if time.time() >= expires_at:
            _userinfo_cache.pop(token, None)
            return None
        return userinfo


def _cache_set(token: str, userinfo: dict) -> None:
    """Cache userinfo with a TTL, never longer than the token's own lifetime."""
    ttl = _cache_ttl()
    if ttl <= 0:
        return

    now = time.time()
    # Cap de TTL op de resterende levensduur van het token (introspect geeft 'exp')
    exp = userinfo.get("exp")
    if isinstance(exp, (int, float)):
        ttl = min(ttl, max(0, int(exp - now)))
        if ttl <= 0:
            return

    with _cache_lock:
        # Begrens de cachegrootte: ruim verlopen entries op, daarna oudste (FIFO)
        if len(_userinfo_cache) >= _cache_maxsize():
            for key in [k for k, (_, e) in _userinfo_cache.items() if e <= now]:
                _userinfo_cache.pop(key, None)
            while len(_userinfo_cache) >= _cache_maxsize() and _userinfo_cache:
                _userinfo_cache.pop(next(iter(_userinfo_cache)), None)

        _userinfo_cache[token] = (userinfo, now + ttl)


def _audience_allowed(data: dict) -> bool:
    """RFC 8707: weiger tokens die aan een ANDERE resource server gebonden zijn.

    Vereist ``OAUTH_RESOURCE_ID`` in de Flask-config: de canonieke resource-URI
    van déze applicatie, gelijk aan ``applications.resource_uri`` op de auth-server
    (bijv. ``https://gms.roleplayreality.nl``). Regels:

    - geen ``OAUTH_RESOURCE_ID`` geconfigureerd → geen handhaving (opt-in);
    - token zonder ``aud`` (legacy/ongebonden) → overal geldig;
    - token mét ``aud`` → moet exact matchen, anders wordt het token geweigerd
      alsof het ongeldig is (401 door de aanroepende decorator).
    """
    resource_id = current_app.config.get("OAUTH_RESOURCE_ID")
    aud = data.get("aud")
    if not resource_id or not aud or aud == resource_id:
        return True
    # Geen waarden loggen: de aud is afgeleid van het aangeboden token en de resource-id
    # is een config-waarde (CodeQL: config = gevoelig). De sleutelnaam volstaat voor ops.
    logger.warning(
        "Token geweigerd: token-aud hoort niet bij deze resource server (OAUTH_RESOURCE_ID)"
    )
    return False


def get_userinfo_from_token(token):
    """
    Fetch userinfo for an access token.

    Tries /oauth/userinfo first (user tokens). If the server returns 403
    (typical for M2M client_credentials tokens), falls back to
    /oauth/introspect.

    Both responses carry the token's ``aud`` (RFC 8707); when
    ``OAUTH_RESOURCE_ID`` is configured, tokens bound to a different resource
    are rejected (returns None).

    Args:
        token (str): Access token

    Returns:
        dict: Userinfo/introspection response, or None on error
    """
    cached = _cache_get(token)
    if cached is not None:
        logger.debug("Userinfo cache hit")
        return cached

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
            if not _audience_allowed(userinfo):
                return None
            _cache_set(token, userinfo)
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

        if not _audience_allowed(data):
            return None

        _cache_set(token, data)
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
    # .clear() i.p.v. herbinden: andere threads houden dezelfde dict-referentie vast.
    with _cache_lock:
        _userinfo_cache.clear()
    logger.info("Userinfo cache cleared")


__all__ = [
    "get_userinfo_from_token",
    "clear_userinfo_cache",
]
