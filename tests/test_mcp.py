"""
Tests voor de optionele MCP-SDK-adapter (``flask_rpr_oauth.mcp.RPRTokenVerifier``).

Vereist het ``mcp``-pakket (extra: ``pip install flask-rpr-oauth[mcp]``); zonder dat
pakket worden deze tests overgeslagen (``pytest.importorskip``).
"""

import asyncio
from unittest.mock import patch

import pytest

mcp = pytest.importorskip("mcp")

import flask_rpr_oauth.mcp as rpr_mcp
from flask_rpr_oauth.mcp import RPRTokenVerifier


def _verifier(**overrides):
    kwargs = dict(
        auth_base_url="https://auth.test.nl",
        client_id="gms-mcp",
        client_secret="test-secret",
        resource_id="https://gms.test.nl/mcp",
    )
    kwargs.update(overrides)
    return RPRTokenVerifier(**kwargs)


class TestConstruction:
    def test_require_aud_defaults_true(self):
        verifier = _verifier()
        assert verifier._core.require_aud is True

    def test_require_aud_opt_out(self):
        verifier = _verifier(require_aud=False)
        assert verifier._core.require_aud is False

    def test_missing_mcp_package_raises_import_error(self):
        with patch.object(rpr_mcp, "MCP_AVAILABLE", False):
            with pytest.raises(ImportError):
                _verifier()


class TestVerifyToken:
    """Draait de coroutine synchroon via asyncio.run — geen pytest-asyncio nodig."""

    def test_invalid_token_returns_none(self):
        verifier = _verifier()
        with patch.object(verifier._core, "verify_bearer", return_value=None):
            result = asyncio.run(verifier.verify_token("bad-token"))
        assert result is None

    def test_valid_m2m_token_maps_to_access_token(self):
        verifier = _verifier()
        data = {
            "active": True,
            "sub": "gms-worker",
            "token_type": "m2m",
            "scope": "gms.read gms.write",
            "aud": "https://gms.test.nl/mcp",
            "exp": 1234567890,
            "permissions": ["gms.read", "gms.write"],
        }
        with patch.object(verifier._core, "verify_bearer", return_value=data):
            result = asyncio.run(verifier.verify_token("m2m-token"))

        assert result is not None
        assert result.token == "m2m-token"
        assert result.client_id == "gms-worker"
        assert set(result.scopes) == {"gms.read", "gms.write"}
        assert result.expires_at == 1234567890
        assert result.resource == "https://gms.test.nl/mcp"
        assert result.subject == "gms-worker"
        assert result.claims["token_type"] == "m2m"
        assert result.claims["permissions"] == ["gms.read", "gms.write"]

    def test_valid_user_token_maps_to_access_token(self):
        verifier = _verifier()
        data = {
            "sub": "42",
            "token_type": "user",
            "acr": "mfa",
            "twofa_validated": True,
            "groups": ["staff"],
            "permissions": ["gms.read"],
        }
        with patch.object(verifier._core, "verify_bearer", return_value=data):
            result = asyncio.run(verifier.verify_token("user-token"))

        assert result is not None
        assert result.subject == "42"
        assert result.client_id == "42"  # geen client_id-claim -> fallback op sub
        assert result.scopes == []  # userinfo geeft geen scope voor user-tokens
        assert result.claims["acr"] == "mfa"
        assert result.claims["groups"] == ["staff"]

    def test_runs_core_in_worker_thread(self):
        """verify_token roept de sync core aan via asyncio.to_thread (non-blocking)."""
        verifier = _verifier()
        with patch.object(verifier._core, "verify_bearer", return_value=None) as mock_verify:
            asyncio.run(verifier.verify_token("tok"))
        mock_verify.assert_called_once_with("tok")
