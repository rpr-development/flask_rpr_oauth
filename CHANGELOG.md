# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
- Improved pre-deploy scripts with more comprehensive checks

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
