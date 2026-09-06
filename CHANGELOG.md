# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- **Breaking:** legacy `/auth/webhook/*` receivers removed (zie Removed).

### Added
- **RFC 9728 Protected Resource Metadata** op `/.well-known/oauth-protected-resource`:
  publiek discovery-document (`resource`, `authorization_servers`, `scopes_supported`,
  `bearer_methods_supported`) waarmee een OAuth-/MCP-client bij een `401` (via de
  `WWW-Authenticate: Bearer resource_metadata="..."`-header) ontdekt welke authorization
  server en scopes bij deze resource server horen. Config: `OAUTH_RESOURCE_ID` (resource-URI,
  default de request-host) en `OAUTH_RESOURCE_SCOPES_SUPPORTED` (default afgeleid uit
  `OAUTH_SCOPE`).
- **RFC 9449 DPoP (resource-server-validatie)**, opt-in per app via `OAUTH_REQUIRE_DPOP`
  (nieuwe module `dpop.py`): valideert de `DPoP:`-proof-header lokaal (`htm`/`htu`/`ath`/`jti`,
  optionele Redis-jti-replaycache met fail-open-gedrag) en vergelijkt de thumbprint (`jkt`)
  met de `cnf.jkt` uit de introspectie-respons van de auth server. Staat `OAUTH_REQUIRE_DPOP`
  aan, dan weigert de resource server kale `Authorization: Bearer`-tokens en verwacht het
  `DPoP`-scheme; de `WWW-Authenticate`-header van de decorators meldt dan `DPoP` i.p.v.
  `Bearer`.
- **`POST /auth/logout`** naast de bestaande `GET`-variant (zelfde handler). Sinds de
  RFC 7009-revocatie heeft een cross-site-triggerbare `GET /auth/logout` (bijv. via
  `<img src>`) een écht server-side effect (refresh-token wordt ingetrokken); een
  `POST` vanuit een CSRF-beschermd formulier voorkomt dat. `GET` blijft bestaan voor
  bestaande navbar-`<a href>`-links.
- README documenteert nu ook `OAUTH_TIMEOUT`, `OAUTH_TOKEN_REVALIDATE_INTERVAL`,
  `OAUTH_POST_LOGOUT_REDIRECT_URI`, `OAUTH_USERINFO_CACHE_TTL`/`_MAXSIZE`,
  `OAUTH_REQUIRE_2FA` en `OAUTH_RESOURCE_SCOPES_SUPPORTED` — deze config-keys bestonden
  al in de code maar stonden nergens beschreven. Ook `current_user.name`/`.full_name`
  (al langer in productiegebruik bij consumers) staan nu in de README.
- `tests/test_models.py`: unit-tests voor `OAuthUser.name`/`.full_name`/`get_permissions()`/
  `get_groups()`/`is_anonymous`, en voor de `current_user`/`current_token`-proxies
  (sessie-pad, Bearer-token-fallback, M2M-uitsluiting, `g._user_extra`-verrijking,
  `current_token.get()`/`__contains__`/`__repr__`) — `models.py` ging hiermee van ~36%
  naar 88% dekking.
- De twee overgeslagen tests in `tests/test_2fa.py` (`test_callback_saves_2fa_status(_false)`,
  ooit gemarkeerd met `Complex mocking - needs refactor`) draaien nu echt: i.p.v. de hele
  `OAuth`-klasse te mocken en `RPRAuth(app)` een tweede keer te initialiseren (wat op
  dubbele Flask-route-registratie botste), vervangen ze `rpr_auth.auth_server` door een
  kale `Mock()` op de al door de fixture geregistreerde instance.
- **Token-revocatie bij logout (RFC 7009)**: `/auth/logout` trekt de sessietokens nu eerst
  server-naar-server in op het `revocation_endpoint` (voorkeur: het refresh token — access
  en refresh horen bij dezelfde token-registratie). Voorheen bleven de tokens (refresh: tot
  30 dagen) geldig wanneer de gebruiker de end_session-bevestigingspagina op de auth server
  niet afmaakte. Best-effort: een onbereikbaar endpoint breekt de logout nooit. Config:
  `OAUTH_REVOKE_ON_LOGOUT` (default `True`). De end_session-request stuurt daarnaast nu ook
  `client_id` mee (RP-Initiated Logout 1.0 §2, RECOMMENDED). De logout-flow heeft nu ook
  eigen tests (`tests/test_logout.py` — was ongetest).
- **SCIM 2.0-ontvanger (RFC 7643/7644)** op `/scim/v2/Users[/<id>]`: herbruikbaar
  provisioning-endpoint waarop de RPR-API scim-worker user-lifecycle pusht. Contract:
  `PUT /Users/<id>` = **upsert** (aanmaken als de gebruiker lokaal nog niet bestaat),
  `POST /Users` = create-fallback, `DELETE /Users/<id>` = idempotente verwijdering,
  `GET /Users/<id>` = data voor de AVG-export. Auth: Bearer M2M-token gevalideerd via
  userinfo/introspectie (`get_userinfo_from_token`, incl. RFC 8707 audience-check) + de
  permissie `OAUTH_SCIM_PERMISSION` (default `auth.scim.provision`). De app implementeert
  alleen callbacks: `OAUTH_ON_SCIM_SYNC(user_id, resource)`, `OAUTH_ON_SCIM_DELETE(user_id)`
  en optioneel `OAUTH_ON_SCIM_GET(user_id) -> dict | None`; een callback-exception geeft
  `500` zodat de worker requeuet. Config: `OAUTH_ENABLE_SCIM` (default `False` — pas
  aanzetten mét callbacks). Fouten per RFC 7644 §3.12 (`urn:...:api:messages:2.0:Error`).
- **Shared Signals Framework (RFC 8417 SET) ontvanger** op `/auth/ssf`: één gedeelde ontvanger
  voor ondertekende Security Event Tokens (push, RFC 8935). Valideert de SET met dezelfde
  auth-server-JWKS als de logout tokens (`_validate_set`, gedeeld met de back-channel-logout-
  ontvanger) en routeert op event-type: `account-disabled`/`account-purged` (RISC),
  `session-revoked`/`credential-change` (CAEP) beëindigen de sessie(s) van de gebruiker
  (mark_logged_out → re-auth). Optionele per-event app-callbacks via config
  (`OAUTH_ON_ACCOUNT_PURGED`/`_DISABLED`/`_SESSION_REVOKED`/`_CREDENTIAL_CHANGE`, elk `(sub, payload)`).
  Config: `OAUTH_ENABLE_SSF` (default `True`), `OAUTH_SSF_AUDIENCE` (default `OAUTH_CLIENT_ID`).
  Ondersteunt RFC 9493 `sub_id` (iss_sub) als fallback voor `sub`. Opvolger van de ad-hoc
  `/auth/webhook/token-revoked` + `/auth/webhook/user-deleted` (in dezelfde release
  verwijderd — zie Removed).
- **RFC 9470 step-up-challenge** in `@require_2fa` (Bearer/API-modus): een geldig *user*-token
  met te laag auth-niveau (`acr=pwd`) krijgt nu een `401` met
  `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="mfa"`
  (via de bestaande 401-helper), zodat een client machinaal weet dat de gebruiker via
  `/oauth/authorize?acr_values=mfa` moet her-authenticeren. De JSON-body blijft
  `{"error": "mfa_required", ...}` (backwards-compatibel).
- **RFC 8707 audience-check** via nieuwe config `OAUTH_RESOURCE_ID`: als de auth-server
  een token aan een resource bindt (`aud` in userinfo/introspectie), weigert
  `get_userinfo_from_token` tokens die voor een andere resource zijn uitgegeven (→ 401 in
  de decorators). Opt-in: zonder `OAUTH_RESOURCE_ID` verandert er niets; tokens zonder
  `aud` blijven overal geldig.
- Dependabot configuration for automated dependency updates
- GitHub Issue templates (bug report, feature request)
- Pull Request template
- Security policy (SECURITY.md)
- CODEOWNERS file
- Enhanced pre-deploy scripts with security scanning (bandit), type checking (mypy), and version consistency checks

### Changed
- **`@require_2fa` (Bearer): een user-token met te laag niveau geeft nu `401` i.p.v. `403`**
  (RFC 9470 step-up, zie Added). M2M-tokens blijven `403` (kunnen niet step-uppen). Consumers
  die op de JSON-body (`error == "mfa_required"`) checken, blijven ongewijzigd werken;
  consumers die hard op statuscode `403` checkten moeten `401` meenemen.
- **Genormaliseerde 401-foutrespons bij een ongeldig/verlopen Bearer-token**: `login_required`,
  `permission_required`, `any_permission_required`, `group_required` en `any_group_required`
  gaven bij een ontbrekend/ongeldig token `{"error": "Invalid or expired token"}` terug — nu
  `{"error": "invalid_token", "message": "Invalid or expired token"}`, gelijk aan wat
  `require_2fa` al deed én aan de `error="invalid_token"` die de `WWW-Authenticate`-header
  standaard al meestuurde (die twee kwamen niet overeen). Consumers die generiek op de
  aanwezigheid van `message` checken blijven werken; een consument die specifiek matcht op
  `error == "Invalid or expired token"` (in plaats van op de statuscode 401) moet
  `error == "invalid_token"` gebruiken.
- Improved pre-deploy scripts with more comprehensive checks

### Removed
- **`GET /auth/fivem-bootstrap`** (deprecated alias) en de bijbehorende
  `OAUTH_ENABLE_FIVEM_BOOTSTRAP`-config. Geen enkele consumer (RPR-GMS, RPR-Intranet,
  rpr-tablet, rpr_core) gebruikt dit pad of deze vlag; de enige resterende verwijzing was
  verouderde documentatie bij MEOS die nog het oude (vóór-generalisatie) contract beschreef
  — dat contract wisselde een OAuth `code` in, terwijl de huidige handler een Bearer
  `access_token` verwacht. Gebruik `/auth/session-bootstrap` (`OAUTH_ENABLE_SESSION_BOOTSTRAP`).
- **`GET /auth/refresh`**. Ongebruikt door alle onderzochte consumers, en de foutafhandeling
  klopte niet: het succespad gaf JSON terug, maar een falende refresh gooide een
  `TokenExpiredError` die door de globale error-handler naar een **redirect** werd omgezet
  i.p.v. een JSON-foutrespons. Tokenrefresh loopt bij alle consumers al via de
  `before_request`-hervalidatie (`OAUTH_TOKEN_REVALIDATE_INTERVAL`) of via `/oauth/token`
  met `grant_type=refresh_token`.
- **`OAuthUser.type`/`.status`/`.username`** (ongedocumenteerde aliassen voor `user_type`/
  `user_status`/`name`). Geen enkele onderzochte consumer gebruikte ze en ze hadden geen
  testdekking. `.name` en `.full_name` blijven bestaan — die zijn wél in productiegebruik
  (RPR-GMS, RPR-Intranet) en staan nu ook in de README.
- `tests/quick_test.py`: ad-hoc script dat niet matchte met pytest's `python_files` (werd
  dus nooit als test gecollecteerd) en volledig gedupliceerd was door `test_auth.py`.
- **Legacy webhooks `/auth/webhook/token-revoked` + `/auth/webhook/user-deleted`** en de
  bijbehorende `WEBHOOK_SECRET`-config. Er heeft nooit een verzender bestaan (de auth server
  heeft deze endpoints in zijn hele git-historie nooit aangeroepen) en geen enkele consumer
  gebruikte ze; de functionaliteit is volledig gedekt door de ondertekende SSF-events op
  `/auth/ssf` (session-revoked → uitloggen, account-purged → uitloggen + callback). Een
  geconfigureerd `WEBHOOK_SECRET` in een app wordt vanaf nu simpelweg genegeerd.

### Fixed
- README-voorbeeld in de SCIM-sectie zette `OAUTH_AUDIENCE` voor RFC 8707 audience-binding —
  die config-key bestaat niet, de code leest uitsluitend `OAUTH_RESOURCE_ID`. Wie het
  voorbeeld letterlijk volgde, kreeg dus stilzwijgend geen audience-binding.
- `require_2fa_reauth()` stuurde onterecht `prompt=login` mee bij normale step-up authenticatie.
  Dit wiste de bestaande `2fa_verified`-sessie op de auth server, waardoor gebruikers die al 2FA
  hadden gedaan (bij een andere app) of ingelogd waren met een passkey toch opnieuw 2FA moesten
  doorlopen. De methode gebruikt nu correcte OIDC step-up authenticatie (`acr_values=mfa` zonder
  `prompt`), zodat bestaande 2FA-sessies en passkey-inlogs (`acr=phr`) automatisch worden
  geaccepteerd zonder extra prompten.
- `require_fresh_2fa()` krijgt nu expliciet `force_fresh=True` mee zodat het gedrag (altijd verse
  2FA afdwingen voor gevoelige handelingen) ongewijzigd blijft.

## [1.0.0] - 2025-11-25

### Added
- Initial release of flask-rpr-oauth
- OAuth 2.0 / OpenID Connect integration for Flask
- Support for Roleplay Reality Auth Server
- Two-factor authentication (2FA) support
- Session-based authentication
- Token refresh functionality
- Comprehensive test suite
- Example applications
- Full documentation

### Security
- Secure token handling
- CSRF protection
- Session security best practices

[Unreleased]: https://github.com/rpr-development/flask_rpr_oauth/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/rpr-development/flask_rpr_oauth/releases/tag/v1.0.0
