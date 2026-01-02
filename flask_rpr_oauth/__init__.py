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
from .stateless import (
    token_required,
    permission_required_stateless,
    any_permission_required_stateless,
    scope_required_stateless,
    group_required_stateless,
    user_only,
    m2m_only,
    get_userinfo_from_token,
    clear_userinfo_cache,
)

__version__ = "1.1.3"
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
    # Stateless (new - voor APIs en M2M)
    "token_required",
    "permission_required_stateless",
    "any_permission_required_stateless",
    "scope_required_stateless",
    "group_required_stateless",
    "user_only",
    "m2m_only",
    "get_userinfo_from_token",
    "clear_userinfo_cache",
    # Exceptions
    "OAuthError",
    "TokenExpiredError",
    "PermissionDeniedError",
]
