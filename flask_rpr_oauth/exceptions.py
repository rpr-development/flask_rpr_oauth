"""
flask_rpr_oauth.exceptions
~~~~~~~~~~~~~~~~~~~~~~~~~~

Custom exceptions for Flask RPR OAuth.
"""


class OAuthError(Exception):
    """Base exception for OAuth errors."""

    def __init__(self, message, status_code=401):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class TokenExpiredError(OAuthError):
    """Exception for expired tokens."""

    def __init__(self, message="Token is verlopen"):
        super().__init__(message, status_code=401)


class PermissionDeniedError(OAuthError):
    """Exception for missing permissions."""

    def __init__(self, message="Onvoldoende rechten", permission=None):
        self.permission = permission
        if permission:
            message = f"{message}: {permission}"
        super().__init__(message, status_code=403)


class GroupDeniedError(OAuthError):
    """Exception for missing group membership."""

    def __init__(self, message="Niet in vereiste groep", group=None):
        self.group = group
        if group:
            message = f"{message}: {group}"
        super().__init__(message, status_code=403)


class InvalidTokenError(OAuthError):
    """Exception for invalid tokens."""

    def __init__(self, message="Token is ongeldig"):
        super().__init__(message, status_code=401)
