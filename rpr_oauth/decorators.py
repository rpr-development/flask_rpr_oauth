from functools import wraps
import logging

def oauth_required(f):
    """
    A decorator to enforce OAuth requirements.
    This decorator checks if the user is authenticated and if the token is expired.
    If the token is expired, it will attempt to refresh it.
    If the refresh fails, it will redirect to the login page.

    :param f: The function to be decorated.
    :return: The decorated function.

    Be aweare that this decorator will not check for 2FA requirements.
    It is recommended to use the `oauth_2fa_required` decorator for 2FA checks.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from .getters import is_authenticated
        from . import refresh_token, redirect_to_login, is_token_expired

        if is_authenticated():
            if is_token_expired():
                logging.info("Token expired, refreshing token")
                return refresh_token()
            else:
                return f(*args, **kwargs)
        else:
            logging.info("User not authenticated, redirecting to login")
            return redirect_to_login()

    return decorated_function

def oauth_2fa_required(f):
    """
    A decorator to enforce OAuth 2FA requirements.
    This decorator checks if the user is authenticated and if the token is expired.
    If the token is expired, it will attempt to refresh it.
    If the refresh fails, it will redirect to the login page.

    :param f: The function to be decorated.
    :return: The decorated function.

    Be aware that this decorator will check for 2FA requirements.
    It is recommended to use the `oauth_required` decorator for non-2FA checks.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from .getters import is_authenticated, get_is_2fa
        from . import refresh_token, redirect_to_login, is_token_expired

        if is_authenticated():
            if is_token_expired():
                logging.info("Token expired, refreshing token")
                return refresh_token(needing_2fa=True)
            elif not get_is_2fa():
                logging.info("User not authenticated with 2FA, redirecting to login")
                return redirect_to_login(needing_2fa=True)
            else:
                return f(*args, **kwargs)
        else:
            logging.info("User not authenticated, redirecting to login")
            return redirect_to_login(needing_2fa=True)
        
    return decorated_function