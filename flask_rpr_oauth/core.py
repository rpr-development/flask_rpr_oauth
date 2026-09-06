"""
flask_rpr_oauth.core
~~~~~~~~~~~~~~~~~~~~~

Framework-agnostic OAuth 2.0 resource-server core.

No Flask import in this module: the same verification logic (userinfo/introspection,
RFC 8707 audience-check, RFC 9449 DPoP proof-validation, and the bounded in-memory
cache) needs to run equally well from an ASGI/Starlette context (see ``mcp.py``'s
``RPRTokenVerifier``, used by MCP servers) as from Flask (see ``helpers.py``/
``decorators.py``, thin shells that build an ``RPROAuthCore`` from
``current_app.config`` on every call).

The userinfo/introspection cache is process-wide (module-level), not tied to any one
``RPROAuthCore`` instance: Flask rebuilds a fresh, cheap instance from live config on
every call (config can change between calls, e.g. in tests), but all instances share
one cache — exactly like the single global cache this package has always had.
"""

import logging
import threading
import time
from typing import Dict, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

# In-memory cache voor userinfo/introspectie-resultaten (voorkomt herhaalde API-calls).
# Value = (data dict, expiry timestamp). Een TTL is essentieel: zonder verloop zou een
# ingetrokken of verlopen token tot proces-herstart geldig blijven. De cache is
# bovendien begrensd om geheugengroei (één entry per uniek token) te voorkomen.
_cache: Dict[str, Tuple[dict, float]] = {}
# Beschermt _cache: onder Gunicorn threads/gevent muteren meerdere requests de dict
# tegelijk (iteratie + pop in _cache_set) → anders RuntimeError/corruptie.
_cache_lock = threading.Lock()


def _cache_get(token: str) -> Optional[dict]:
    """Return cached data if present and not expired, else None."""
    with _cache_lock:
        entry = _cache.get(token)
        if entry is None:
            return None
        data, expires_at = entry
        if time.time() >= expires_at:
            _cache.pop(token, None)
            return None
        return data


def _cache_set(token: str, data: dict, ttl: int, maxsize: int) -> None:
    """Cache data with a TTL, never longer than the token's own lifetime."""
    if ttl <= 0:
        return

    now = time.time()
    # Cap de TTL op de resterende levensduur van het token (introspect/userinfo geeft 'exp')
    exp = data.get("exp")
    if isinstance(exp, (int, float)):
        ttl = min(ttl, max(0, int(exp - now)))
        if ttl <= 0:
            return

    with _cache_lock:
        # Begrens de cachegrootte: ruim verlopen entries op, daarna oudste (FIFO)
        if len(_cache) >= maxsize:
            for key in [k for k, (_, e) in _cache.items() if e <= now]:
                _cache.pop(key, None)
            while len(_cache) >= maxsize and _cache:
                _cache.pop(next(iter(_cache)), None)

        _cache[token] = (data, now + ttl)


def clear_cache() -> None:
    """Clear the shared userinfo/introspection cache (for testing/development)."""
    # .clear() i.p.v. herbinden: andere threads houden dezelfde dict-referentie vast.
    with _cache_lock:
        _cache.clear()


class RPROAuthCore:
    """Resource-server-side OAuth 2.0 token verification, zonder framework-koppeling.

    Bundelt userinfo/introspectie, RFC 8707 audience-handhaving en RFC 9449 DPoP-
    proofvalidatie achter expliciete, dependency-injected constructor-parameters in
    plaats van Flask's ``current_app.config``. Gebruikt door zowel Flask
    (``helpers.py``/``decorators.py``, die per aanroep een instance bouwen vanuit de
    actuele app-config) als een ASGI/Starlette MCP-server (``mcp.py``, één
    langlevende instance per server-proces).
    """

    def __init__(
        self,
        auth_base_url: Optional[str],
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        resource_id: Optional[str] = None,
        require_aud: bool = False,
        require_dpop: bool = False,
        cache_ttl: int = 60,
        cache_maxsize: int = 1000,
        redis=None,
        timeout: int = 10,
    ):
        self.auth_base_url = auth_base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.resource_id = resource_id
        self.require_aud = require_aud
        self.require_dpop = require_dpop
        self.cache_ttl = cache_ttl
        self.cache_maxsize = cache_maxsize
        self.redis = redis
        self.timeout = timeout

    def _audience_allowed(self, data: dict) -> bool:
        """RFC 8707: weiger tokens die aan een ANDERE resource server gebonden zijn.

        Regels:
        - geen ``resource_id`` geconfigureerd → geen handhaving (opt-in);
        - token zonder ``aud`` (legacy/ongebonden) → overal geldig, tenzij
          ``require_aud`` aanstaat — dan is een ontbrekende ``aud`` ook een weigering;
        - token mét ``aud`` → moet exact matchen, anders wordt het token geweigerd
          alsof het ongeldig is.
        """
        if not self.resource_id:
            return True

        aud = data.get("aud")
        if not aud:
            if self.require_aud:
                logger.warning("Token geweigerd: geen aud-claim, maar require_aud vereist er een")
                return False
            return True

        if aud == self.resource_id:
            return True

        # Geen waarden loggen: de aud komt uit het (nog onvertrouwde) token en resource_id
        # is een config-waarde (CodeQL: config = gevoelig). De sleutelnaam volstaat voor ops.
        logger.warning("Token geweigerd: token-aud hoort niet bij deze resource server")
        return False

    def introspect(self, token: str) -> Optional[dict]:
        """
        Validate a token via the /oauth/introspect endpoint (RFC 7662).

        Uses client_id/client_secret as HTTP Basic Auth. Works for both M2M and user
        tokens, and is the only one of the two endpoints that returns ``scope``.

        Returns:
            dict with token claims including 'token_type', or None on error.
        """
        if not self.auth_base_url:
            logger.error("auth_base_url is niet geconfigureerd")
            return None
        if not self.client_id or not self.client_secret:
            logger.error("Token introspection vereist client_id en client_secret")
            return None

        try:
            response = requests.post(
                f"{self.auth_base_url}/oauth/introspect",
                data={"token": token},
                auth=(self.client_id, self.client_secret),
                timeout=self.timeout,
            )

            if response.status_code != 200:
                logger.warning(f"Token introspection failed: {response.status_code}")
                return None

            data = response.json()

            if not data.get("active"):
                logger.debug("Token introspection: token is not active")
                return None

            if not self._audience_allowed(data):
                return None

            _cache_set(token, data, self.cache_ttl, self.cache_maxsize)
            logger.debug(
                f'Token introspected - token_type: {data.get("token_type")}, '
                f'sub: {data.get("sub")}, permissions: {len(data.get("permissions", []))}'
            )
            return data

        except Exception as e:
            logger.error(f"Token introspection error: {e}")
            return None

    def userinfo(self, token: str) -> Optional[dict]:
        """Fetch /oauth/userinfo for an access token (user tokens only; M2M gets 403)."""
        if not self.auth_base_url:
            logger.error("auth_base_url is niet geconfigureerd")
            return None

        try:
            response = requests.get(
                f"{self.auth_base_url}/oauth/userinfo",
                headers={"Authorization": f"Bearer {token}"},
                timeout=self.timeout,
            )
        except Exception as e:
            logger.error(f"Userinfo request error: {e}")
            return None

        if response.status_code != 200:
            return None

        data = response.json()
        if not self._audience_allowed(data):
            return None

        _cache_set(token, data, self.cache_ttl, self.cache_maxsize)
        return data

    def verify_bearer(self, token: str) -> Optional[dict]:
        """
        Resolve a Bearer token.

        Tries /oauth/userinfo first (works for user tokens). If the server returns
        403 (typical for M2M client_credentials tokens), falls back to
        /oauth/introspect. Both responses carry the token's ``aud`` (RFC 8707);
        when ``resource_id`` is configured, tokens bound to a different resource are
        rejected (returns None). Results are cached (bounded, TTL'd, capped at the
        token's own expiry).

        Returns:
            dict: Userinfo/introspection response, or None on error.
        """
        cached = _cache_get(token)
        if cached is not None:
            logger.debug("Token cache hit")
            return cached

        if not self.auth_base_url:
            logger.error("auth_base_url is niet geconfigureerd")
            return None

        # Stap 1: probeer userinfo (werkt voor user tokens)
        try:
            response = requests.get(
                f"{self.auth_base_url}/oauth/userinfo",
                headers={"Authorization": f"Bearer {token}"},
                timeout=self.timeout,
            )

            if response.status_code == 200:
                userinfo = response.json()
                if not self._audience_allowed(userinfo):
                    return None
                _cache_set(token, userinfo, self.cache_ttl, self.cache_maxsize)
                logger.debug(
                    f'Userinfo fetched - token_type: {userinfo.get("token_type")}, '
                    f'sub: {userinfo.get("sub")}, '
                    f'permissions: {len(userinfo.get("permissions", []))}'
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
        return self.introspect(token)

    def get_token_scopes(self, token: str) -> set:
        """Return the OAuth ``scope``s carried by ``token`` (via cached introspection).

        ``/oauth/userinfo`` doesn't return ``scope`` for user tokens (only
        introspection does, RFC 7662) — a cache hit without a ``scope`` field (e.g.
        previously set by ``verify_bearer()``) still triggers an introspection call.

        Returns:
            set: the token's scopes, or an empty set if the token is invalid or
                 carries no scopes.
        """
        cached = _cache_get(token)
        if cached is not None and "scope" in cached:
            data = cached
        else:
            data = self.introspect(token)

        if not data:
            return set()
        return set((data.get("scope") or "").split())

    def verify_dpop(self, token: str, proof: str, method: str, url: str) -> Optional[dict]:
        """Validate a DPoP-bound request (RFC 9449 SS7.1).

        Validates the proof locally (against ``method``/``url``/``token``) and
        compares its thumbprint with the ``cnf.jkt`` from introspection.

        Returns:
            dict: the introspection response (permissions/groups/acr/sub/...), or
                  None if the proof or the token binding is invalid.
        """
        from .dpop import DPoPError, validate_dpop_proof

        try:
            proof_jkt = validate_dpop_proof(proof, method, url, token, redis=self.redis)
        except DPoPError as e:
            logger.info("[dpop] Proof geweigerd: %s", e)
            return None

        data = self.introspect(token)
        if not data:
            return None

        bound_jkt = (data.get("cnf") or {}).get("jkt")
        if not bound_jkt:
            # Token is niet DPoP-gebonden maar wordt wél via het DPoP-scheme aangeboden →
            # weiger. Anders zou een gewoon token als "DPoP" met een eigen sleutel de
            # bindingcontrole omzeilen.
            logger.warning("[dpop] Token is niet DPoP-gebonden maar aangeboden via het DPoP-scheme")
            return None
        if bound_jkt != proof_jkt:
            logger.warning("[dpop] Thumbprint-mismatch: proof=%s token=%s", proof_jkt, bound_jkt)
            return None

        return data


__all__ = ["RPROAuthCore", "clear_cache"]
