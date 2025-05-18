import logging

from flask import request, session, redirect, url_for

from . import oauth
from .. import login_user

@oauth.route('/callback', methods=['GET', 'POST'])
def callback():
    print("login handler")
    logging.error("login handler")
    token = request.args.get("access_token")
    refresh_token = request.args.get("refresh_token")
    expires_at = request.args.get("expires_at")
    user_id = request.args.get("user_id")

    if not token or not refresh_token or not expires_at or not user_id:
        logging.error("Missing token information, got:", request.args)
        raise Exception("Missing token information")

    login_user(
        user_id,
        token,
        refresh_token,
        expires_at,
        request.args.get("2fa_needed", False)
    )

    return redirect(session.pop("next_page", url_for("main.index")))