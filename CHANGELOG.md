# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
- Improved pre-deploy scripts with more comprehensive checks

### Removed
- **Legacy webhooks `/auth/webhook/token-revoked` + `/auth/webhook/user-deleted`** en de
  bijbehorende `WEBHOOK_SECRET`-config. Er heeft nooit een verzender bestaan (de auth server
  heeft deze endpoints in zijn hele git-historie nooit aangeroepen) en geen enkele consumer
  gebruikte ze; de functionaliteit is volledig gedekt door de ondertekende SSF-events op
  `/auth/ssf` (session-revoked → uitloggen, account-purged → uitloggen + callback). Een
  geconfigureerd `WEBHOOK_SECRET` in een app wordt vanaf nu simpelweg genegeerd.

### Fixed

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
