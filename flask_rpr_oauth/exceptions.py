"""
flask_rpr_oauth.exceptions
~~~~~~~~~~~~~~~~~~~~~~~~~~

Custom exceptions voor Flask RPR OAuth.
"""


class OAuthError(Exception):
    """Base exception voor OAuth errors."""

    def __init__(self, message, status_code=401):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class TokenExpiredError(OAuthError):
    """Exception voor verlopen tokens."""

    def __init__(self, message="Token is verlopen"):
        super().__init__(message, status_code=401)


class PermissionDeniedError(OAuthError):
    """Exception voor ontbrekende permissions."""

    def __init__(self, message="Onvoldoende rechten", permission=None):
        self.permission = permission
        if permission:
            message = f"{message}: {permission}"
        super().__init__(message, status_code=403)


class GroupDeniedError(OAuthError):
    """Exception voor ontbrekende groep membership."""

    def __init__(self, message="Niet in vereiste groep", group=None):
        self.group = group
        if group:
            message = f"{message}: {group}"
        super().__init__(message, status_code=403)


class InvalidTokenError(OAuthError):
    """Exception voor ongeldige tokens."""

    def __init__(self, message="Token is ongeldig"):
        super().__init__(message, status_code=401)
