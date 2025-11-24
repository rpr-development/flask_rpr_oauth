"""
Flask RPR OAuth
~~~~~~~~~~~~~~~

Een Flask extensie voor OAuth 2.0 / OpenID Connect authenticatie met de Roleplay Reality Auth Server.

:copyright: (c) 2025 by Roleplay Reality.
:license: MIT, see LICENSE for more details.
"""

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

__version__ = "1.0.0"
__all__ = [
    "RPRAuth",
    "OAuthUser",
    "current_user",
    "login_required",
    "permission_required",
    "any_permission_required",
    "group_required",
    "any_group_required",
    "require_2fa",
    "OAuthError",
    "TokenExpiredError",
    "PermissionDeniedError",
]
