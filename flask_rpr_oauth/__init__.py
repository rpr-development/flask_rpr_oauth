"""
Flask RPR OAuth
~~~~~~~~~~~~~~~

Een Flask extensie voor OAuth 2.0 / OpenID Connect authenticatie met de Roleplay Reality Auth Server.

:copyright: (c) 2025 by Roleplay Reality.
:license: MIT, see LICENSE for more details.
"""

try:
    from ._version import version as __version__
except ImportError:
    __version__ = "0.0.0+unknown"

from .auth import RPRAuth
from .decorators import (
    login_required,
    permission_required,
    any_permission_required,
    group_required,
    any_group_required,
    require_2fa,
)
from .models import OAuthUser, current_user
from .exceptions import OAuthError, TokenExpiredError, PermissionDeniedError
from .helpers import (
    get_userinfo_from_token,
    clear_userinfo_cache,
)

__all__ = [
    # Session-based (original)
    "RPRAuth",
    "OAuthUser",
    "current_user",
    "login_required",
    "permission_required",
    "any_permission_required",
    "group_required",
    "any_group_required",
    "require_2fa",
    # Stateless helpers
    "get_userinfo_from_token",
    "clear_userinfo_cache",
    # Exceptions
    "OAuthError",
    "TokenExpiredError",
    "PermissionDeniedError",
]
