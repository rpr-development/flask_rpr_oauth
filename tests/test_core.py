"""
Tests voor de framework-agnostische ``core.RPROAuthCore`` (stap 7): geen Flask hier,
alleen gemockte HTTP. Dekt introspectie, userinfo, de gecombineerde verify_bearer-flow
(incl. cache en RFC 8707 audience-check) en RFC 9449 DPoP-validatie.
"""

import time
from unittest.mock import MagicMock, patch

import pytest
from joserfc import jwt as joserfc_jwt
from joserfc.jwk import ECKey

from flask_rpr_oauth.core import RPROAuthCore, clear_cache
from flask_rpr_oauth.dpop import compute_ath


@pytest.fixture(autouse=True)
def _clean_cache():
    clear_cache()
    yield
    clear_cache()


def _core(**overrides):
    kwargs = dict(
        auth_base_url="https://auth.test.nl",
        client_id="test-client",
        client_secret="test-secret",
    )
    kwargs.update(overrides)
    return RPROAuthCore(**kwargs)


def _response(status_code, json_data=None):
    resp = MagicMock()
    resp.status_code = status_code
    if json_data is not None:
        resp.json.return_value = json_data
    return resp


class TestIntrospect:
    def test_success(self):
        core = _core()
        data = {"active": True, "sub": "1", "token_type": "m2m", "scope": "gms.read"}
        with patch("requests.post", return_value=_response(200, data)):
            result = core.introspect("tok")
        assert result == data

    def test_missing_credentials_returns_none(self):
        core = _core(client_id=None, client_secret=None)
        with patch("requests.post") as mock_post:
            result = core.introspect("tok")
        assert result is None
        mock_post.assert_not_called()

    def test_missing_base_url_returns_none(self):
        core = _core(auth_base_url=None)
        result = core.introspect("tok")
        assert result is None

    def test_non_200_returns_none(self):
        core = _core()
        with patch("requests.post", return_value=_response(500)):
            assert core.introspect("tok") is None

    def test_inactive_token_returns_none(self):
        core = _core()
        with patch("requests.post", return_value=_response(200, {"active": False})):
            assert core.introspect("tok") is None

    def test_network_error_returns_none(self):
        core = _core()
        with patch("requests.post", side_effect=Exception("no network")):
            assert core.introspect("tok") is None

    def test_wrong_audience_rejected(self):
        core = _core(resource_id="https://gms.test.nl")
        data = {"active": True, "sub": "1", "aud": "https://other.test.nl"}
        with patch("requests.post", return_value=_response(200, data)):
            assert core.introspect("tok") is None

    def test_matching_audience_accepted(self):
        core = _core(resource_id="https://gms.test.nl")
        data = {"active": True, "sub": "1", "aud": "https://gms.test.nl"}
        with patch("requests.post", return_value=_response(200, data)):
            assert core.introspect("tok") is not None

    def test_writes_to_shared_cache_for_verify_bearer(self):
        """introspect() zelf leest de cache niet (elke aanroep is een verse call), maar
        schrijft er wel naar toe — verify_bearer()/get_token_scopes() lezen die terug."""
        core = _core()
        data = {"active": True, "sub": "1"}
        with patch("requests.post", return_value=_response(200, data)) as mock_post:
            core.introspect("tok-cache")
        with patch("requests.get") as mock_get:
            result = core.verify_bearer("tok-cache")
        assert result == data
        mock_get.assert_not_called()
        assert mock_post.call_count == 1


class TestUserinfo:
    def test_success(self):
        core = _core()
        data = {"sub": "1", "token_type": "user"}
        with patch("requests.get", return_value=_response(200, data)):
            assert core.userinfo("tok") == data

    def test_non_200_returns_none(self):
        core = _core()
        with patch("requests.get", return_value=_response(403)):
            assert core.userinfo("tok") is None

    def test_wrong_audience_rejected(self):
        core = _core(resource_id="https://gms.test.nl")
        data = {"sub": "1", "aud": "https://other.test.nl"}
        with patch("requests.get", return_value=_response(200, data)):
            assert core.userinfo("tok") is None


class TestVerifyBearer:
    def test_user_token_via_userinfo(self):
        core = _core()
        data = {"sub": "1", "token_type": "user"}
        with (
            patch("requests.get", return_value=_response(200, data)),
            patch("requests.post") as mock_post,
        ):
            result = core.verify_bearer("tok")
        assert result == data
        mock_post.assert_not_called()

    def test_m2m_token_falls_back_to_introspect(self):
        core = _core()
        introspected = {"active": True, "sub": "client-1", "token_type": "m2m"}
        with (
            patch("requests.get", return_value=_response(403)),
            patch("requests.post", return_value=_response(200, introspected)),
        ):
            result = core.verify_bearer("tok")
        assert result == introspected

    def test_other_userinfo_error_no_fallback(self):
        core = _core()
        with (
            patch("requests.get", return_value=_response(500)),
            patch("requests.post") as mock_post,
        ):
            assert core.verify_bearer("tok") is None
        mock_post.assert_not_called()

    def test_result_is_cached(self):
        core = _core()
        data = {"sub": "1", "token_type": "user"}
        with patch("requests.get", return_value=_response(200, data)) as mock_get:
            core.verify_bearer("tok-cache")
            core.verify_bearer("tok-cache")
        assert mock_get.call_count == 1

    def test_rejected_token_not_cached(self):
        core = _core(resource_id="https://gms.test.nl")
        data = {"sub": "1", "aud": "https://other.test.nl"}
        with patch("requests.get", return_value=_response(200, data)):
            assert core.verify_bearer("tok-rejected") is None
        with patch("requests.get", side_effect=Exception("geen netwerk")):
            assert core.verify_bearer("tok-rejected") is None

    def test_missing_base_url_returns_none(self):
        core = _core(auth_base_url=None)
        assert core.verify_bearer("tok") is None


class TestRequireAud:
    def test_missing_aud_rejected_when_required(self):
        core = _core(resource_id="https://gms.test.nl", require_aud=True)
        data = {"sub": "1"}
        with patch("requests.get", return_value=_response(200, data)):
            assert core.verify_bearer("tok") is None

    def test_missing_aud_accepted_by_default(self):
        core = _core(resource_id="https://gms.test.nl")
        data = {"sub": "1"}
        with patch("requests.get", return_value=_response(200, data)):
            assert core.verify_bearer("tok") is not None


class TestGetTokenScopes:
    def test_from_introspection(self):
        core = _core()
        data = {"active": True, "sub": "1", "scope": "gms.read gms.write"}
        with patch("requests.post", return_value=_response(200, data)):
            assert core.get_token_scopes("tok") == {"gms.read", "gms.write"}

    def test_cache_without_scope_still_introspects(self):
        core = _core()
        userinfo = {"sub": "1", "token_type": "user"}
        with patch("requests.get", return_value=_response(200, userinfo)):
            core.verify_bearer("tok")  # caches the scope-less userinfo response

        introspected = {"active": True, "sub": "1", "scope": "gms.read"}
        with patch("requests.post", return_value=_response(200, introspected)):
            assert core.get_token_scopes("tok") == {"gms.read"}

    def test_invalid_token_returns_empty_set(self):
        core = _core()
        with patch("requests.post", return_value=_response(200, {"active": False})):
            assert core.get_token_scopes("tok") == set()


class TestVerifyDpop:
    @pytest.fixture
    def key(self):
        return ECKey.generate_key("P-256")

    def _proof(self, key, token, *, htm="GET", htu="http://localhost/mcp"):
        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": key.as_dict(private=False)}
        claims = {
            "htm": htm,
            "htu": htu,
            "jti": f"jti-{time.time_ns()}",
            "iat": int(time.time()),
            "ath": compute_ath(token),
        }
        return joserfc_jwt.encode(header, claims, key)

    def test_valid_proof_and_matching_jkt(self, key):
        core = _core()
        token = "the-token"
        proof = self._proof(key, token)
        introspected = {
            "active": True,
            "sub": "1",
            "token_type": "user",
            "cnf": {"jkt": key.thumbprint()},
        }
        with patch("requests.post", return_value=_response(200, introspected)):
            result = core.verify_dpop(token, proof, "GET", "http://localhost/mcp")
        assert result == introspected

    def test_missing_proof_rejected(self):
        core = _core()
        assert core.verify_dpop("tok", None, "GET", "http://localhost/mcp") is None

    def test_jkt_mismatch_rejected(self, key):
        core = _core()
        token = "the-token"
        proof = self._proof(key, token)
        other = ECKey.generate_key("P-256")
        introspected = {"active": True, "sub": "1", "cnf": {"jkt": other.thumbprint()}}
        with patch("requests.post", return_value=_response(200, introspected)):
            result = core.verify_dpop(token, proof, "GET", "http://localhost/mcp")
        assert result is None

    def test_unbound_token_rejected(self, key):
        core = _core()
        token = "the-token"
        proof = self._proof(key, token)
        introspected = {"active": True, "sub": "1"}  # geen cnf.jkt
        with patch("requests.post", return_value=_response(200, introspected)):
            result = core.verify_dpop(token, proof, "GET", "http://localhost/mcp")
        assert result is None
