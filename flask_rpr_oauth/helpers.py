"""
flask_rpr_oauth.helpers
~~~~~~~~~~~~~~~~~~~~~~

Thin Flask shell around ``core.RPROAuthCore``: builds a lightweight core instance
from ``current_app.config`` on every call (cheap — the constructor does no I/O) and
delegates the actual userinfo/introspection/audience/DPoP logic to it. The
underlying cache lives in ``core.py`` and is shared across calls/instances (module-
level, not tied to any one instance), so behaviour/performance are unchanged from
before this was split out — see ``core.py`` for the framework-agnostic logic.

Suitable for both API (Bearer token) and session-based authentication.

Token validation order:
  1. /oauth/userinfo  — works for user tokens (authorization_code flow)
  2. /oauth/introspect — fallback for M2M tokens (client_credentials flow),
                         which receive 403 on userinfo
"""

import logging

from flask import current_app

from .core import RPROAuthCore
from .core import clear_cache as _clear_core_cache
from .core import invalidate_by_sub as _invalidate_core_cache_by_sub

logger = logging.getLogger(__name__)


def _config_int(key: str, default: int) -> int:
    try:
        return int(current_app.config.get(key, default))
    except (RuntimeError, TypeError, ValueError):
        return default


def _dpop_redis_for_current_app():
    """Optionele Redis voor de DPoP-jti-replaycache. Hergebruikt de al-geconfigureerde
    back-channel-logout-client van de RPRAuth-extensie; None (fail-open) als die er niet is."""
    rpr_auth = current_app.extensions.get("rpr_auth")
    if rpr_auth is not None and hasattr(rpr_auth, "_logout_redis"):
        try:
            return rpr_auth._logout_redis()
        except Exception:
            return None
    return None


def _get_core() -> RPROAuthCore:
    """Bouw een ``RPROAuthCore`` vanuit de actuele Flask-config.

    Bewust NIET gecachet op ``current_app``/``g``: config kan tussen aanroepen wijzigen
    (o.a. in tests, die na app-initialisatie nog ``app.config[...]`` zetten) en de
    constructor zelf doet geen I/O — een nieuwe instance bouwen is goedkoop. De
    onderliggende cache (``core._cache``) is wél gedeeld/persistent over aanroepen heen.
    """
    return RPROAuthCore(
        auth_base_url=current_app.config.get("OAUTH_BASE_URL"),
        client_id=current_app.config.get("OAUTH_CLIENT_ID"),
        client_secret=current_app.config.get("OAUTH_CLIENT_SECRET"),
        resource_id=current_app.config.get("OAUTH_RESOURCE_ID"),
        require_aud=current_app.config.get("OAUTH_REQUIRE_AUD", False),
        require_dpop=current_app.config.get("OAUTH_REQUIRE_DPOP", False),
        cache_ttl=_config_int("OAUTH_USERINFO_CACHE_TTL", 60),
        cache_maxsize=_config_int("OAUTH_USERINFO_CACHE_MAXSIZE", 1000),
        redis=_dpop_redis_for_current_app(),
        timeout=current_app.config.get("OAUTH_TIMEOUT", 10),
    )


def resource_scopes_supported() -> list:
    """OAuth-scopes die deze resource server ondersteunt (RFC 9728 ``scopes_supported``).

    Gedeeld door de protected-resource-metadata (``auth.py``) en de ``scope``-hint op
    401/403 ``WWW-Authenticate``-challenges (``decorators.py``), zodat beide altijd
    dezelfde scopes adverteren. Bron: ``OAUTH_RESOURCE_SCOPES_SUPPORTED`` (lijst of
    spatie-gescheiden string); zonder die config afgeleid uit ``OAUTH_SCOPE``.

    ``offline_access`` wordt altijd gefilterd: het is een refresh-scope, niet iets wat een
    client zou moeten aanvragen om deze resource te mogen gebruiken. Met een warning als de
    eigenaar hem zelf in ``OAUTH_RESOURCE_SCOPES_SUPPORTED`` heeft gezet.

    Blijft hier (i.p.v. in ``core.py``): dit is puur resource-metadata-config, geen
    token-verificatie.
    """
    scopes = current_app.config.get("OAUTH_RESOURCE_SCOPES_SUPPORTED")
    if scopes is None:
        scopes = current_app.config.get("OAUTH_SCOPE", "openid profile email").split()
    elif isinstance(scopes, str):
        scopes = scopes.split()
    else:
        scopes = list(scopes)

    if "offline_access" in scopes:
        logger.warning(
            "OAUTH_RESOURCE_SCOPES_SUPPORTED bevat offline_access — dit is een refresh-scope, "
            "geen scope die clients voor deze resource moeten aanvragen; wordt gefilterd."
        )
        scopes = [s for s in scopes if s != "offline_access"]
    return scopes


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
    return _get_core().verify_bearer(token)


def _introspect_token(token: str, oauth_base_url: str = None) -> dict | None:
    """
    Validate a token via the /oauth/introspect endpoint (RFC 7662).

    ``oauth_base_url`` is accepted for backward compatibility with existing call
    sites/tests but ignored: the core reads ``OAUTH_BASE_URL`` from the current app
    config itself.

    Returns:
        dict with token claims including 'token_type': 'm2m', or None on error
    """
    return _get_core().introspect(token)


def _audience_allowed(data: dict) -> bool:
    """RFC 8707 audience-check for the current app; see ``core.RPROAuthCore._audience_allowed``."""
    return _get_core()._audience_allowed(data)


def get_token_scopes(token: str) -> set:
    """Geef de OAuth-``scope``s van ``token`` terug, voor gebruik door ``require_scope``.

    Zie ``core.RPROAuthCore.get_token_scopes`` voor de volledige uitleg (introspectie-
    fallback omdat userinfo geen ``scope`` teruggeeft voor user-tokens).
    """
    return _get_core().get_token_scopes(token)


def verify_dpop_request(token: str, proof: str, method: str, url: str):
    """Thin Flask shell for ``core.RPROAuthCore.verify_dpop``, used by ``decorators.py``."""
    return _get_core().verify_dpop(token, proof, method, url)


def clear_userinfo_cache():
    """Clear the userinfo cache (for testing/development)."""
    _clear_core_cache()
    logger.info("Userinfo cache cleared")


def invalidate_userinfo_cache_for_sub(sub) -> int:
    """Verwijder alle userinfo/introspectie-cache-entries voor ``sub``.

    Gebruikt door de BCL-/SSF-ontvangers (``auth.py``) na een logout/account-event, zodat
    een nog niet verlopen Bearer-cache-entry de gewijzigde staat niet even verbergt. Zie
    ``core.invalidate_by_sub`` voor de details.
    """
    count = _invalidate_core_cache_by_sub(sub)
    if count:
        logger.info("Userinfo cache geïnvalideerd voor sub (%d entries)", count)
    return count


__all__ = [
    "get_userinfo_from_token",
    "clear_userinfo_cache",
]
