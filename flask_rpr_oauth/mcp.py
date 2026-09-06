"""
flask_rpr_oauth.mcp
~~~~~~~~~~~~~~~~~~~~

Optional MCP-SDK adapter: wraps ``core.RPROAuthCore`` behind the MCP Python SDK's
``TokenVerifier`` protocol (``mcp.server.auth.provider``), so an ASGI/Starlette MCP
server can authenticate Bearer tokens against the RPR-API auth server without any
Flask dependency.

Requires the optional ``mcp`` extra (``pip install flask-rpr-oauth[mcp]``); importing
this module without it installed still works, but constructing ``RPRTokenVerifier``
raises a clear ``ImportError``.
"""

import asyncio
import logging
from typing import Optional

from .core import RPROAuthCore

logger = logging.getLogger(__name__)

try:
    from mcp.server.auth.provider import AccessToken, TokenVerifier

    MCP_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised via importorskip in tests
    MCP_AVAILABLE = False

    class TokenVerifier:  # type: ignore[no-redef]
        """Placeholder base so this module still imports without the `mcp` extra."""

    AccessToken = None  # type: ignore[assignment]


class RPRTokenVerifier(TokenVerifier):
    """MCP SDK ``TokenVerifier`` backed by the RPR-API auth server.

    MCP resource servers are expected to be audience-strict (RFC 8707 + RFC 9728):
    ``resource_id`` should always be set, and ``require_aud`` defaults to True here
    (unlike ``RPROAuthCore``'s own default of False) — a token without an ``aud``
    claim is rejected rather than silently accepted. Pass ``require_aud=False`` only
    as a temporary opt-out (e.g. migrating an auth server that doesn't bind audiences
    yet).

    Example (with the MCP Python SDK's ``MCPServer``, formerly ``FastMCP``)::

        from mcp.server.auth.settings import AuthSettings
        from mcp.server.mcpserver import MCPServer
        from flask_rpr_oauth.mcp import RPRTokenVerifier

        verifier = RPRTokenVerifier(
            auth_base_url="https://auth.roleplayreality.nl",
            client_id="gms-mcp",
            client_secret="...",
            resource_id="https://gms.roleplayreality.nl/mcp",
        )
        server = MCPServer(
            "RPR GMS",
            token_verifier=verifier,
            auth=AuthSettings(
                issuer_url="https://auth.roleplayreality.nl",
                resource_server_url="https://gms.roleplayreality.nl/mcp",
                required_scopes=["gms.read"],
            ),
        )

    The SDK itself serves the protected-resource-metadata document (RFC 9728) on the
    ``resource_server_url``'s path suffix — no need to also register
    ``auth.py``'s Flask route for a pure MCP server.
    """

    def __init__(
        self,
        auth_base_url: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        resource_id: Optional[str] = None,
        require_aud: bool = True,
        require_dpop: bool = False,
        cache_ttl: int = 60,
        cache_maxsize: int = 1000,
        redis=None,
        timeout: int = 10,
    ):
        if not MCP_AVAILABLE:
            raise ImportError(
                "RPRTokenVerifier vereist het optionele 'mcp'-pakket. Installeer met: "
                "pip install flask-rpr-oauth[mcp]"
            )
        self._core = RPROAuthCore(
            auth_base_url=auth_base_url,
            client_id=client_id,
            client_secret=client_secret,
            resource_id=resource_id,
            require_aud=require_aud,
            require_dpop=require_dpop,
            cache_ttl=cache_ttl,
            cache_maxsize=cache_maxsize,
            redis=redis,
            timeout=timeout,
        )

    async def verify_token(self, token: str):
        """Verify a bearer token (MCP SDK ``TokenVerifier`` protocol).

        Runs the synchronous core (blocking HTTP + cache) in a worker thread via
        ``asyncio.to_thread`` so it doesn't block the ASGI event loop.

        Returns:
            AccessToken | None: None if the token is invalid, expired, or bound to a
                different resource (RFC 8707); an ``AccessToken`` otherwise.
        """
        data = await asyncio.to_thread(self._core.verify_bearer, token)
        if not data:
            return None

        scope = data.get("scope") or ""
        return AccessToken(
            token=token,
            # RPR-API's userinfo/introspection responses don't always carry a
            # dedicated `client_id` claim; `sub` is the best available fallback
            # (for M2M tokens `sub` already *is* the client's own identity).
            client_id=str(data.get("client_id") or data.get("sub") or ""),
            scopes=scope.split(),
            expires_at=data.get("exp"),
            resource=data.get("aud"),
            subject=data.get("sub"),
            claims={
                "permissions": data.get("permissions"),
                "groups": data.get("groups"),
                "acr": data.get("acr"),
                "twofa_validated": data.get("twofa_validated"),
                "token_type": data.get("token_type"),
            },
        )


__all__ = ["RPRTokenVerifier"]
