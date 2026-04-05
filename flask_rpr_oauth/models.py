"""
flask_rpr_oauth.models
~~~~~~~~~~~~~~~~~~~~~~

User model voor OAuth authenticatie.
"""

from typing import Optional
from flask import g, session


class OAuthUser:
    """
    User model voor OAuth authenticated users.

    Users worden opgeslagen in Flask session.

    Attributes:
        oauth_id (str): OAuth subject (sub) identifier
        email (str): User's email address
        voornaam (str): First name
        achternaam (str): Last name
        teamspeak_id (str): TeamSpeak identifier
        discord_id (str): Discord identifier
        ingame_phone (str): In-game phone number
        fivem_role (str): FiveM role
        name_prefix (str): Name prefix
        email_verified (bool): Email verification status
        user_type (str): User type
        user_status (str): User status
        claims (dict): All raw claims from userinfo
        _permissions (list): List of permission strings
        _groups (list): List of group names
    """

    def __init__(
        self,
        oauth_id,
        email,
        voornaam="",
        achternaam="",
        teamspeak_id="",
        discord_id="",
        ingame_phone="",
        fivem_role="",
        name_prefix="",
        email_verified=False,
        user_type="",
        user_status="",
        permissions=None,
        groups=None,
        claims=None,
    ):
        """
        Initialize OAuth user.

        Args:
            oauth_id: OAuth subject identifier
            email: User's email address
            voornaam: First name (optional)
            achternaam: Last name (optional)
            teamspeak_id: TeamSpeak identifier (optional)
            discord_id: Discord identifier (optional)
            ingame_phone: In-game phone number (optional)
            fivem_role: FiveM role (optional)
            name_prefix: Name prefix (optional)
            email_verified: Email verification status (optional)
            user_type: User type (optional)
            user_status: User status (optional)
            permissions: List of permissions (optional)
            groups: List of groups (optional)
            claims: All raw claims from userinfo (optional)
        """
        self.oauth_id = oauth_id
        self.email = email
        self.voornaam = voornaam
        self.achternaam = achternaam
        self.teamspeak_id = teamspeak_id
        self.discord_id = discord_id
        self.ingame_phone = ingame_phone
        self.fivem_role = fivem_role
        self.name_prefix = name_prefix
        self.email_verified = email_verified
        self.user_type = user_type
        self.user_status = user_status
        self._permissions = permissions or []
        self._groups = groups or []
        self.claims = claims or {}

    def get_id(self):
        """Return unique identifier."""
        return self.oauth_id

    @property
    def id(self):
        """Property alias for get_id()."""
        return self.oauth_id

    @property
    def name(self):
        """Display name: voornaam + first letter of achternaam."""
        if self.achternaam:
            return f"{self.voornaam} {self.achternaam[0]}."
        return self.voornaam

    @property
    def username(self):
        """Alias for name."""
        return self.name

    @property
    def is_authenticated(self):
        """Check if user is authenticated."""
        return True

    @property
    def is_active(self):
        """Check if user is active (REVIEW en BANNED zijn geblokkeerd)."""
        return self.user_status not in ("REVIEW", "BANNED")

    @property
    def is_anonymous(self):
        """Check if user is anonymous."""
        return False

    @property
    def twofa_validated(self):
        """
        Check if user has completed 2FA.

        Returns:
            bool: True if 2FA is validated
        """
        return session.get("twofa_validated", False)

    def get_permissions(self):
        """
        Get list of user's permissions.

        Returns:
            List[str]: List of permission strings
        """
        return self._permissions

    def get_groups(self):
        """
        Get list of user's groups.

        Returns:
            List[str]: List of group names
        """
        return self._groups

    def has_permission(self, permission):
        """
        Check if user has specific permission.

        Args:
            permission (str): Permission to check

        Returns:
            bool: True if user has permission
        """
        return permission in self._permissions

    def has_any_permission(self, *permissions):
        """
        Check if user has any of the specified permissions.

        Args:
            *permissions: Variable number of permission strings

        Returns:
            bool: True if user has at least one permission
        """
        return any(perm in self._permissions for perm in permissions)

    def in_group(self, group):
        """
        Check if user is in specific group.

        Args:
            group (str): Group name to check

        Returns:
            bool: True if user is in group
        """
        return group in self._groups

    def in_any_group(self, *groups):
        """
        Check if user is in any of the specified groups.

        Args:
            *groups: Variable number of group names

        Returns:
            bool: True if user is in at least one group
        """
        return any(group in self._groups for group in groups)

    def __repr__(self):
        """String representation of user."""
        return f"<OAuthUser {self.email}>"


class _CurrentUserProxy:
    """
    Proxy voor current_user die de user uit de session haalt.
    """

    def _get_user(self) -> Optional[OAuthUser]:
        """Get current user from session."""
        if "oauth_user" not in session:
            return None

        user_data = session["oauth_user"]
        return OAuthUser(
            oauth_id=user_data.get("oauth_id"),
            email=user_data.get("email", ""),
            voornaam=user_data.get("voornaam", ""),
            achternaam=user_data.get("achternaam", ""),
            teamspeak_id=user_data.get("teamspeak_id", ""),
            discord_id=user_data.get("discord_id", ""),
            ingame_phone=user_data.get("ingame_phone", ""),
            fivem_role=user_data.get("fivem_role", ""),
            name_prefix=user_data.get("name_prefix", ""),
            email_verified=user_data.get("email_verified", False),
            user_type=user_data.get("user_type", ""),
            user_status=user_data.get("user_status", ""),
            permissions=session.get("oauth_permissions", []),
            groups=session.get("oauth_groups", []),
            claims=user_data,
        )

    def __setattr__(self, name, value):
        """Store enriched attributes in flask.g (per-request) instead of on the singleton."""
        try:
            if not hasattr(g, '_user_extra'):
                g._user_extra = {}
            g._user_extra[name] = value
        except RuntimeError:
            # Outside request context — fall back to object dict
            object.__setattr__(self, name, value)

    def __getattr__(self, name):
        """Proxy attribute access: check g._user_extra first, then session-backed user."""
        try:
            user_extra = getattr(g, '_user_extra', {})
            if name in user_extra:
                return user_extra[name]
        except RuntimeError:
            pass  # Outside request context
        user = self._get_user()
        if user is None:
            # Return anonymous user attributes
            if name == "is_authenticated":
                return False
            elif name == "is_anonymous":
                return True
            elif name == "is_active":
                return False
            raise AttributeError("No user authenticated")
        return getattr(user, name)

    def __bool__(self):
        """Check if user is authenticated."""
        user = self._get_user()
        return user is not None and getattr(user, "is_authenticated", True)

    @property
    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        user = self._get_user()
        return user is not None and getattr(user, "is_authenticated", True)


# Create singleton instance
current_user = _CurrentUserProxy()


class _CurrentTokenProxy:
    """
    Proxy voor de huidige API token info (Bearer token userinfo).

    Werkt net als current_user, maar dan voor API requests met Bearer tokens.
    De decorators slaan de token info op in flask.g, deze proxy leest het daaruit.

    Usage:
        from flask_rpr_oauth import current_token

        @permission_required('melding.view')
        def my_endpoint():
            if current_token:
                print(current_token.sub)           # subject (user_id of client_id)
                print(current_token.token_type)     # 'user' of 'm2m'
                print(current_token.permissions)    # ['melding.view', ...]
            return 'OK'
    """

    def _get_info(self):
        """Get token info from flask.g request context."""
        return getattr(g, '_rpr_token_info', None)

    @property
    def is_authenticated(self):
        """Check if a valid Bearer token is present."""
        return self._get_info() is not None

    def get(self, key, default=None):
        """Dict-like access to token info fields."""
        info = self._get_info()
        if info is None:
            return default
        return info.get(key, default)

    def __getattr__(self, name):
        """Attribute access to token info fields (current_token.sub, etc.)."""
        info = self._get_info()
        if info is None:
            raise AttributeError("No token info available - is this a Bearer token request?")
        if isinstance(info, dict):
            try:
                return info[name]
            except KeyError:
                raise AttributeError(f"Token info has no attribute '{name}'")
        return getattr(info, name)

    def __bool__(self):
        """Truthy if a valid Bearer token is present."""
        return self._get_info() is not None

    def __contains__(self, key):
        """Support 'key in current_token' syntax."""
        info = self._get_info()
        return info is not None and key in info

    def __repr__(self):
        info = self._get_info()
        if info is None:
            return "<CurrentToken: anonymous>"
        return f"<CurrentToken: {info.get('token_type', '?')} sub={info.get('sub', '?')}>"


# Create singleton instance
current_token = _CurrentTokenProxy()

__all__ = ["OAuthUser", "current_user", "current_token"]
