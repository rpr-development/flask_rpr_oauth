# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Dependabot configuration for automated dependency updates
- GitHub Issue templates (bug report, feature request)
- Pull Request template
- Security policy (SECURITY.md)
- CODEOWNERS file
- Enhanced pre-deploy scripts with security scanning (bandit), type checking (mypy), and version consistency checks

### Changed
- Improved pre-deploy scripts with more comprehensive checks

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
