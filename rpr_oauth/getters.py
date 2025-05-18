from flask import session

def get_user_id():
    """
    Get the user ID from the session.

    :return: The user ID if present, otherwise None.
    """
    return session.get("user_id")

def get_token():
    """
    Get the OAuth token from the session.

    :return: The OAuth token if present, otherwise None.
    """
    return session.get("token")

def get_refresh_token():
    """
    Get the refresh token from the session.

    :return: The refresh token if present, otherwise None.
    """
    return session.get("refresh_token")

def get_expires_at():
    """
    Get the expiration time of the token from the session.

    :return: The expiration time if present, otherwise None.
    """
    return session.get("expires_at")

def get_is_2fa():
    """
    Get the 2FA status from the session.

    :return: True if 2FA is required, otherwise False.
    """
    return session.get("twofa_validated", False)

def is_authenticated():
    """
    Check if the user is authenticated.
    """
    if "token" in session and "user_id" in session and session.get("user_id") is not None:
        return True
    else:
        return False