"""
flask_rpr_oauth.dpop
~~~~~~~~~~~~~~~~~~~~~

RFC 9449 — DPoP proof-validatie aan de **resource-server-kant**.

Een DPoP-gebonden access token is vastgeklonken aan een sleutelpaar van de client. Bij elke
resource-call stuurt de client naast ``Authorization: DPoP <token>`` ook een ``DPoP:``-header:
een korte JWT ondertekend met die sleutel, met claims die het aan déze request binden
(``htm``/``htu``), een ``ath`` (hash van het access token) en een unieke ``jti``.

Deze module valideert die proof lokaal (tegen de URL/methode van *deze* resource server) en
geeft de thumbprint (``jkt``) terug. De aanroeper vergelijkt die met de ``cnf.jkt`` die de
authorization server via introspectie teruggeeft — matchen ze, dan bezit de aanbieder de
sleutel en is het token geldig; zo niet (of geen proof), dan is een gestolen token waardeloos.

Spiegelt bewust ``utils/dpop.py`` van de RPR-API auth-server: joserfc voor de JWT-validatie
tegen de meegestuurde JWK, en een optionele Redis ``SET NX EX`` jti-replaycache met
fail-open-gedrag (consistent met de back-channel-logout-Redis in ``auth.py``).
"""

import base64
import hashlib
import logging
import time
from urllib.parse import urlsplit, urlunsplit

logger = logging.getLogger(__name__)

# Alleen asymmetrische algoritmes: de client registreert zijn public key in de proof-header,
# dus 'none'/HMAC (HS*) zijn per definitie ongeldig (alg-confusion). ES256 is de gangbare keuze.
DPOP_SIGNING_ALGS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]

IAT_PAST_LEEWAY = 300  # seconden dat een proof "oud" mag zijn
IAT_FUTURE_LEEWAY = 60  # seconden klokverschil naar de toekomst


class DPoPError(Exception):
    """Ongeldige/ontbrekende DPoP-proof (leidt tot een 401 met WWW-Authenticate: DPoP)."""


def _b64url_no_pad(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def compute_ath(access_token):
    """RFC 9449 §4.2 ``ath``: base64url(SHA-256(access_token)) zonder padding."""
    return _b64url_no_pad(hashlib.sha256(access_token.encode("ascii")).digest())


def _normalize_htu(url):
    """RFC 9449 §4.3: vergelijk de ``htu`` zonder query/fragment; scheme+host lowercased."""
    parts = urlsplit(url or "")
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, "", ""))


def _consume_jti(jkt, jti, iat, redis):
    """Markeer een proof-``jti`` als gebruikt (replay-preventie). Redis ``SET NX EX``, per
    thumbprint gesleuteld. Fail-open als er geen (werkende) Redis is — handtekening + korte
    geldigheid blijven de primaire verdediging (zelfde afweging als de RPR-API-kant)."""
    if redis is None:
        return True
    try:
        now = int(time.time())
        ttl = max((int(iat) + IAT_PAST_LEEWAY) - now, 1) + 5
        key = f"rpr:dpop:jti:{jkt}:{jti}"
        if not redis.set(key, "1", nx=True, ex=ttl):
            logger.warning("[dpop] Replay gedetecteerd: jti=%s jkt=%s", jti, jkt)
            return False
        return True
    except Exception as e:
        logger.warning("[dpop] jti-replaycontrole faalde (%s) — toegestaan", e)
        return True


def validate_dpop_proof(proof, htm, htu, access_token, redis=None):
    """Valideer een DPoP-proof-JWT voor een resource-request en retourneer de ``jkt``.

    Raist ``DPoPError`` bij elke afwijking. Controleert (RFC 9449 §4.3 + §7.1):
    header ``typ='dpop+jwt'`` + asymmetrisch ``alg``; een public ``jwk``; de handtekening tegen
    die jwk; ``htm``/``htu`` == deze request; ``iat`` binnen het venster; ``jti`` (replay);
    en ``ath`` == hash(access_token) — verplicht op resource-calls.

    Args:
        proof: de ruwe ``DPoP``-headerwaarde (compacte JWT).
        htm: HTTP-methode van deze request.
        htu: URL van deze request (query/fragment worden genegeerd).
        access_token: het aangeboden access token (voor de ``ath``-controle).
        redis: optionele Redis-client voor de jti-replaycache.

    Returns:
        De ``jkt`` (RFC 7638 thumbprint) van de proof-sleutel.
    """
    if not proof or not isinstance(proof, str):
        raise DPoPError("DPoP proof ontbreekt")

    from joserfc import jwt
    from joserfc.errors import JoseError
    from joserfc.jwk import import_key
    from joserfc.jws import extract_compact

    try:
        extracted = extract_compact(proof.encode("ascii"))
        header = extracted.headers()
    except (JoseError, ValueError, UnicodeError) as e:
        raise DPoPError("DPoP proof is geen geldige JWT") from e

    if header.get("typ") != "dpop+jwt":
        raise DPoPError("DPoP proof mist header typ='dpop+jwt'")
    alg = header.get("alg")
    if alg not in DPOP_SIGNING_ALGS:
        raise DPoPError(f"DPoP proof gebruikt een niet-toegestaan alg: {alg}")

    jwk_dict = header.get("jwk")
    if not isinstance(jwk_dict, dict):
        raise DPoPError("DPoP proof mist een jwk-header")
    if jwk_dict.get("kty") == "oct" or "d" in jwk_dict or "k" in jwk_dict:
        raise DPoPError("DPoP proof jwk moet een asymmetrische public key zijn")

    try:
        key = import_key(jwk_dict)
    except (JoseError, ValueError) as e:
        raise DPoPError("DPoP proof jwk is ongeldig") from e
    try:
        decoded = jwt.decode(proof, key, algorithms=[alg])
    except (JoseError, ValueError) as e:
        raise DPoPError("DPoP proof handtekening is ongeldig") from e

    claims = decoded.claims
    jkt = key.thumbprint()

    if str(claims.get("htm", "")).upper() != str(htm).upper():
        raise DPoPError("DPoP proof htm komt niet overeen met de HTTP-methode")
    if _normalize_htu(str(claims.get("htu", ""))) != _normalize_htu(htu):
        raise DPoPError("DPoP proof htu komt niet overeen met de request-URL")

    iat = claims.get("iat")
    if not isinstance(iat, (int, float)):
        raise DPoPError("DPoP proof mist een geldige iat")
    now = int(time.time())
    if iat > now + IAT_FUTURE_LEEWAY:
        raise DPoPError("DPoP proof iat ligt te ver in de toekomst")
    if iat < now - IAT_PAST_LEEWAY:
        raise DPoPError("DPoP proof is verlopen (iat te oud)")

    jti = claims.get("jti")
    if not jti or not isinstance(jti, str):
        raise DPoPError("DPoP proof mist een jti")

    if claims.get("ath") != compute_ath(access_token):
        raise DPoPError("DPoP proof ath komt niet overeen met het access-token")

    if not _consume_jti(jkt, jti, int(iat), redis):
        raise DPoPError("DPoP proof jti is al gebruikt (replay)")

    return jkt
