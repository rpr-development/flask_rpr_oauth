"""
flask_rpr_oauth.models
~~~~~~~~~~~~~~~~~~~~~~

User model voor OAuth authenticatie.
"""

from typing import Optional
from flask import session


class OAuthUser:
    """
    User model voor OAuth authenticated users.
    
    Users worden opgeslagen in Flask session.
    
    Attributes:
        oauth_id (str): OAuth subject (sub) identifier
        email (str): User's email address
        voornaam (str): First name
        achternaam (str): Last name
        _permissions (list): List of permission strings
        _groups (list): List of group names
    """
    
    def __init__(self, oauth_id, email, voornaam='', achternaam='', permissions=None, groups=None):
        """
        Initialize OAuth user.
        
        Args:
            oauth_id: OAuth subject identifier
            email: User's email address
            voornaam: First name (optional)
            achternaam: Last name (optional)
            permissions: List of permissions (optional)
            groups: List of groups (optional)
        """
        self.oauth_id = oauth_id
        self.email = email
        self.voornaam = voornaam
        self.achternaam = achternaam
        self._permissions = permissions or []
        self._groups = groups or []
    
    def get_id(self):
        """Return unique identifier."""
        return self.oauth_id
    
    @property
    def id(self):
        """Property alias for get_id()."""
        return self.oauth_id
    
    @property
    def is_authenticated(self):
        """Check if user is authenticated."""
        return True
    
    @property
    def is_active(self):
        """Check if user is active."""
        return True
    
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
        return session.get('twofa_validated', False)
    
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
        return f'<OAuthUser {self.email}>'


class _CurrentUserProxy:
    """
    Proxy voor current_user die de user uit de session haalt.
    """
    
    def _get_user(self) -> Optional[OAuthUser]:
        """Get current user from session."""
        if 'oauth_user' not in session:
            return None
        
        user_data = session['oauth_user']
        return OAuthUser(
            oauth_id=user_data.get('oauth_id'),
            email=user_data.get('email', ''),
            voornaam=user_data.get('voornaam', ''),
            achternaam=user_data.get('achternaam', ''),
            permissions=session.get('oauth_permissions', []),
            groups=session.get('oauth_groups', [])
        )
    
    def __getattr__(self, name):
        """Proxy all attribute access to the actual user object."""
        user = self._get_user()
        if user is None:
            # Return anonymous user attributes
            if name == 'is_authenticated':
                return False
            elif name == 'is_anonymous':
                return True
            elif name == 'is_active':
                return False
            raise AttributeError(f"No user authenticated")
        return getattr(user, name)
    
    def __bool__(self):
        """Check if user is authenticated."""
        user = self._get_user()
        return user is not None and getattr(user, 'is_authenticated', True)
    
    @property
    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        user = self._get_user()
        return user is not None and getattr(user, 'is_authenticated', True)


# Create singleton instance
current_user = _CurrentUserProxy()

__all__ = ['OAuthUser', 'current_user']
