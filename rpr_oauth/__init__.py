import os
import requests
import logging

from flask import session, redirect, url_for, request, jsonify
from datetime import datetime
from urllib.parse import urlencode

from .getters import get_user_id, get_token, get_refresh_token, get_expires_at, get_is_2fa, is_authenticated
from .decorators import oauth_required, oauth_2fa_required

# This module handles OAuth authentication and session management.
# It provides functions to redirect users to the login page, check token expiration,
# refresh tokens, and manage user sessions.
# The base URL for the OAuth server.
base_url = os.getenv("RPR_OAUTH_BASE_URL", "https://auth.roleplayreality.nl")

def redirect_to_login(needing_2fa=False):
    """
    Redirect the user to the login page.

    :param: needing_2fa: A boolean indicating if 2FA is needed.
    :return: A redirect response to the login page.
    """
    # Set session next page to the current URL
    session["next_page"] = request.path

    # Construct query parameters
    query_params = {
        "next": url_for("oauth.callback", _external=True),
        "2fa_needed": needing_2fa
    }

    # Append query parameters to the base URL
    login_url = f"{base_url}?{urlencode(query_params)}"

    logging.error("Redirecting to login URL: %s", login_url)

    return redirect(login_url, code=302)

def is_token_expired():
    """
    Check if the OAuth token is expired.
    If the token is expired, return True.
    If the token is not expired, return False.
    """
    if "expires_at" in session:
        return True
    
    return datetime.fromtimestamp(get_expires_at()) < datetime.now()

def refresh_token(needing_2fa=False):
    """
    Refresh the OAuth token using the refresh token.
    If the refresh token is not present, redirect to the login page.
    """
    try:
        if "refresh_token" not in session:
            logging.debug("Geen refresh token in sessie")
            redirect_to_login(needing_2fa=needing_2fa)
        else: # Prevents futher code execution if no refresh token is present
            payload = {
                'refresh_token': get_refresh_token()
            }
            url = f"{base_url}/api/v1/refresh-token"

            response = requests.post(url, json=payload)
            data = response.json()
            logging.debug(data)
            if response.status_code == 200 and "access_token" in data:
                # Sla de nieuwe tokens op in de sessie
                login_user(
                    data.get("user_id", get_user_id()),
                    access_token=data.get("access_token"),
                    refresh_token=data.get("refresh_token"),
                    expires_at=data.get("expires_in"),
                    twofa_validated=data.get("twofa_validated", False)
                )
            else:
                logout_user()
                redirect_to_login()
    except Exception as e:
        logging.exception("Error refreshing token: %s", str(e))
        # Log the error and redirect to login
        logout_user()
        redirect_to_login()

def login_user(user_id, access_token, refresh_token, expires_at, twofa_validated=False):
    """
    Log the user in using the provided token information.

    :param user_id: The user ID.
    :param access_token: The access token.
    :param refresh_token: The refresh token.
    :param expires_at: The expiration time of the token.
    :param twofa_validated: A boolean indicating the user has authenticated with 2FA.
    :return: None
    """
    session['user_id'] = user_id
    session['token'] = access_token
    session['refresh_token'] = refresh_token
    session['expires_at'] = expires_at
    session['twofa_validated'] = twofa_validated

    session.modified = True

def logout_user():
    """
    Log the user out and clear the session.
    """
    session.clear()
    session.modified = True

