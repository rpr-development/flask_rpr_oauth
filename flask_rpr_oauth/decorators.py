"""
flask_rpr_oauth.decorators
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Decorators voor permission en group checks.
"""

from functools import wraps
from flask import abort, current_app, session, redirect, url_for, request
from .models import current_user
from .exceptions import PermissionDeniedError, GroupDeniedError


def login_required(f):
    """
    Decorator die vereist dat gebruiker is ingelogd.
    
    Checkt of user in session zit en redirect naar login indien niet.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            # Store next URL in session
            session['next'] = request.url
            # Redirect to login
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function


def permission_required(permission):
    """
    Decorator die vereist dat gebruiker een specifieke permission heeft.
    
    Args:
        permission (str): Required permission string
        
    Example:
        @app.route('/admin')
        @login_required
        @permission_required('admin.access')
        def admin_panel():
            return 'Admin panel'
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            
            if not hasattr(current_user, 'has_permission'):
                current_app.logger.error(
                    f"User {current_user.get_id()} heeft geen has_permission method"
                )
                abort(403)
            
            if not current_user.has_permission(permission):
                current_app.logger.warning(
                    f"User {current_user.get_id()} heeft geen permission: {permission}"
                )
                raise PermissionDeniedError(permission=permission)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def any_permission_required(*permissions):
    """
    Decorator die vereist dat gebruiker één van de opgegeven permissions heeft.
    
    Args:
        *permissions: Variable aantal permission strings
        
    Example:
        @app.route('/moderate')
        @login_required
        @any_permission_required('moderator', 'admin')
        def moderate():
            return 'Moderation panel'
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            
            if not hasattr(current_user, 'has_any_permission'):
                current_app.logger.error(
                    f"User {current_user.get_id()} heeft geen has_any_permission method"
                )
                abort(403)
            
            if not current_user.has_any_permission(*permissions):
                current_app.logger.warning(
                    f"User {current_user.get_id()} heeft geen van de permissions: {permissions}"
                )
                raise PermissionDeniedError(
                    message=f"Een van deze rechten is vereist: {', '.join(permissions)}"
                )
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def group_required(group):
    """
    Decorator die vereist dat gebruiker in een specifieke groep zit.
    
    Args:
        group (str): Required group name
        
    Example:
        @app.route('/staff')
        @login_required
        @group_required('staff')
        def staff_panel():
            return 'Staff panel'
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            
            if not hasattr(current_user, 'in_group'):
                current_app.logger.error(
                    f"User {current_user.get_id()} heeft geen in_group method"
                )
                abort(403)
            
            if not current_user.in_group(group):
                current_app.logger.warning(
                    f"User {current_user.get_id()} zit niet in groep: {group}"
                )
                raise GroupDeniedError(group=group)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def any_group_required(*groups):
    """
    Decorator die vereist dat gebruiker in één van de opgegeven groepen zit.
    
    Args:
        *groups: Variable aantal group names
        
    Example:
        @app.route('/special')
        @login_required
        @any_group_required('vip', 'premium', 'admin')
        def special_content():
            return 'Special content'
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            
            if not hasattr(current_user, 'in_any_group'):
                current_app.logger.error(
                    f"User {current_user.get_id()} heeft geen in_any_group method"
                )
                abort(403)
            
            if not current_user.in_any_group(*groups):
                current_app.logger.warning(
                    f"User {current_user.get_id()} zit niet in een van de groepen: {groups}"
                )
                raise GroupDeniedError(
                    message=f"Lidmaatschap van een van deze groepen is vereist: {', '.join(groups)}"
                )
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_2fa(f):
    """
    Decorator die vereist dat gebruiker 2FA heeft voltooid.
    
    Als de gebruiker niet is ingelogd, redirect naar login.
    Als de gebruiker geen 2FA heeft voltooid, redirect naar auth server voor 2FA.
    
    Example:
        @app.route('/sensitive')
        @require_2fa
        def sensitive_endpoint():
            return 'Highly sensitive data'
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check of user is ingelogd
        if not current_user.is_authenticated:
            session['next'] = request.url
            return redirect(url_for('auth.login'))
        
        # Check 2FA status in session
        twofa_validated = session.get('twofa_validated', False)
        
        if not twofa_validated:
            # Haal RPRAuth instance op
            rpr_auth = current_app.extensions.get('rpr_auth')
            
            if rpr_auth:
                # Valideer actuele 2FA status bij auth server
                if not rpr_auth.validate_2fa():
                    current_app.logger.warning(
                        f"User {current_user.get_id()} heeft geen 2FA validatie"
                    )
                    # Redirect naar auth server voor 2FA
                    redirect_url = rpr_auth.get_2fa_redirect_url(request.url)
                    return redirect(redirect_url)
            else:
                current_app.logger.error("RPRAuth niet gevonden in extensions")
                abort(500)
        
        return f(*args, **kwargs)
    return decorated_function


__all__ = [
    'login_required',
    'permission_required',
    'any_permission_required',
    'group_required',
    'any_group_required',
    'require_2fa',
]
