"""
Voorbeeld: Stateless API met M2M en User token support

Deze API ondersteunt BEIDE:
1. User tokens (authorization_code flow) - voor web clients
2. M2M tokens (client_credentials flow) - voor server-to-server
"""

import os

from flask import Flask, jsonify, request
from flask_rpr_oauth import (
    permission_required,
    any_permission_required,
    login_required,
    user_only,
    m2m_only,
)

app = Flask(__name__)

# Configuratie
app.config["OAUTH_BASE_URL"] = "https://auth.roleplayreality.nl"
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]

# ============================================
# ENDPOINTS VOOR BEIDE TOKEN TYPES
# ============================================


@app.route("/api/status")
@login_required
def api_status(userinfo=None):
    """
    Basis endpoint - accepteert zowel user als M2M tokens.

    Test met M2M token:
        curl -X GET http://localhost:5001/api/status \
          -H "Authorization: Bearer M2M_TOKEN"

    Test met User token:
        curl -X GET http://localhost:5001/api/status \
          -H "Authorization: Bearer USER_TOKEN"
    """
    token_type = userinfo.get("token_type")

    if token_type == "m2m":
        return jsonify(
            {
                "status": "ok",
                "token_type": "m2m",
                "client_id": userinfo.get("client_id"),
                "application": userinfo.get("application_name"),
                "permissions_count": len(userinfo.get("permissions", [])),
            }
        )
    else:
        return jsonify(
            {
                "status": "ok",
                "token_type": "user",
                "user_id": userinfo.get("sub"),
                "email": userinfo.get("email"),
                "name": userinfo.get("name"),
                "groups": userinfo.get("groups", []),
            }
        )


@app.route("/api/kick-player", methods=["POST"])
@permission_required("fivem.player.kick")
def kick_player(userinfo=None):
    """
    Kick een speler - werkt voor BEIDE token types.

    M2M token: FiveM server kan spelers kicken
    User token: Admin kan spelers kicken

    Test met M2M token:
        curl -X POST http://localhost:5001/api/kick-player \
          -H "Authorization: Bearer M2M_TOKEN" \
          -H "Content-Type: application/json" \
          -d '{"player_id": 123, "reason": "Spamming"}'

    Test met User token:
        curl -X POST http://localhost:5001/api/kick-player \
          -H "Authorization: Bearer USER_TOKEN" \
          -H "Content-Type: application/json" \
          -d '{"player_id": 123, "reason": "Spamming"}'
    """
    data = request.get_json()
    player_id = data.get("player_id")
    reason = data.get("reason", "No reason provided")

    token_type = userinfo.get("token_type")

    # Log wie de actie uitvoerde
    if token_type == "m2m":
        actor = f"Server {userinfo.get('client_id')}"
    else:
        actor = f"User {userinfo.get('email')}"

    # Kick logic hier...
    app.logger.info(f"{actor} kicked player {player_id}: {reason}")

    return jsonify(
        {
            "status": "success",
            "message": f"Player {player_id} kicked",
            "kicked_by": actor,
            "reason": reason,
        }
    )


@app.route("/api/ban-player", methods=["POST"])
@permission_required("fivem.player.ban")
def ban_player(userinfo=None):
    """Ban een speler - werkt voor beide token types."""
    data = request.get_json()
    player_id = data.get("player_id")
    duration = data.get("duration", "permanent")

    token_type = userinfo.get("token_type")
    actor = userinfo.get("client_id") if token_type == "m2m" else userinfo.get("email")

    return jsonify(
        {
            "status": "success",
            "message": f"Player {player_id} banned",
            "duration": duration,
            "banned_by": actor,
        }
    )


@app.route("/api/moderate", methods=["POST"])
@any_permission_required("fivem.player.kick", "fivem.player.ban", "fivem.admin.noclip")
def moderate(userinfo=None):
    """
    Moderatie actie - vereist minimaal ÉÉN van de permissions.

    Werkt voor beide token types.
    """
    data = request.get_json()
    action = data.get("action")

    return jsonify(
        {
            "status": "success",
            "action": action,
            "moderator": userinfo.get("sub"),
            "available_permissions": userinfo.get("permissions"),
        }
    )


# ============================================
# USER-ONLY ENDPOINTS
# ============================================


@app.route("/api/profile")
@user_only
@permission_required("profile.view")
def get_profile(userinfo=None):
    """
    Haal user profiel op - ALLEEN voor user tokens.

    M2M tokens worden AFGEWEZEN.

    Test met User token:
        curl -X GET http://localhost:5001/api/profile \
          -H "Authorization: Bearer USER_TOKEN"

    Test met M2M token (wordt afgewezen):
        curl -X GET http://localhost:5001/api/profile \
          -H "Authorization: Bearer M2M_TOKEN"
        # Response: 403 Forbidden - This endpoint requires a user token
    """
    return jsonify(
        {
            "user_id": userinfo.get("sub"),
            "email": userinfo.get("email"),
            "name": userinfo.get("name"),
            "groups": userinfo.get("groups"),
            "permissions": userinfo.get("permissions"),
            "twofa_validated": userinfo.get("twofa_validated"),
        }
    )


@app.route("/api/settings", methods=["PUT"])
@user_only
@permission_required("profile.edit")
def update_settings(userinfo=None):
    """Update user settings - alleen voor user tokens."""
    data = request.get_json()

    return jsonify(
        {"status": "success", "message": "Settings updated", "user_id": userinfo.get("sub")}
    )


# ============================================
# M2M-ONLY ENDPOINTS
# ============================================


@app.route("/api/server/heartbeat", methods=["POST"])
@m2m_only
@permission_required("fivem.server.status")
def server_heartbeat(userinfo=None):
    """
    Server heartbeat - ALLEEN voor M2M tokens.

    User tokens worden AFGEWEZEN.

    Test met M2M token:
        curl -X POST http://localhost:5001/api/server/heartbeat \
          -H "Authorization: Bearer M2M_TOKEN" \
          -H "Content-Type: application/json" \
          -d '{"player_count": 42, "uptime": 3600}'

    Test met User token (wordt afgewezen):
        curl -X POST http://localhost:5001/api/server/heartbeat \
          -H "Authorization: Bearer USER_TOKEN"
        # Response: 403 Forbidden - This endpoint requires an M2M token
    """
    data = request.get_json()
    player_count = data.get("player_count")
    uptime = data.get("uptime")

    client_id = userinfo.get("client_id")
    app_name = userinfo.get("application_name")

    app.logger.info(
        f"Heartbeat from {client_id} ({app_name}): {player_count} players, uptime {uptime}s"
    )

    return jsonify({"status": "ok", "message": "Heartbeat received", "server": client_id})


@app.route("/api/server/metrics", methods=["POST"])
@m2m_only
@permission_required("fivem.server.metrics")
def server_metrics(userinfo=None):
    """Server metrics upload - alleen voor M2M tokens."""
    data = request.get_json()

    return jsonify(
        {"status": "success", "message": "Metrics received", "client_id": userinfo.get("client_id")}
    )


# ============================================
# PERMISSION INFO ENDPOINT
# ============================================


@app.route("/api/whoami")
@login_required
def whoami(userinfo=None):
    """
    Debug endpoint - toont alle info over het huidige token.

    Werkt voor beide token types.
    """
    return jsonify(userinfo)


# ============================================
# ERROR HANDLERS
# ============================================


@app.errorhandler(401)
def unauthorized(error):
    return (
        jsonify({"error": "Unauthorized", "message": "Invalid or missing authentication token"}),
        401,
    )


@app.errorhandler(403)
def forbidden(error):
    return jsonify({"error": "Forbidden", "message": "Insufficient permissions"}), 403


@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Internal error: {error}")
    return jsonify({"error": "Internal Server Error"}), 500


# ============================================
# MAIN
# ============================================

if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.DEBUG)

    print("=" * 60)
    print("Flask RPR OAuth - Stateless API Example")
    print("=" * 60)
    print()
    print("Endpoints:")
    print("  GET  /api/status            - Status (user + M2M)")
    print("  POST /api/kick-player       - Kick player (user + M2M)")
    print("  POST /api/ban-player        - Ban player (user + M2M)")
    print("  POST /api/moderate          - Moderate (user + M2M)")
    print("  GET  /api/profile           - Profile (user only)")
    print("  PUT  /api/settings          - Settings (user only)")
    print("  POST /api/server/heartbeat  - Heartbeat (M2M only)")
    print("  POST /api/server/metrics    - Metrics (M2M only)")
    print("  GET  /api/whoami            - Token info (user + M2M)")
    print()
    print("Test commands:")
    print("  # Get M2M token")
    print("  TOKEN=$(curl -s -X POST https://auth.roleplayreality.nl/oauth/token \\")
    print('    -d "grant_type=client_credentials" \\')
    print('    -d "client_id=fivem-server-1" \\')
    print('    -d "client_secret=YOUR_SECRET" \\')
    print("    -d \"scope=openid profile\" | jq -r '.access_token')")
    print()
    print("  # Test endpoint")
    print("  curl -X GET http://localhost:5001/api/whoami \\")
    print('    -H "Authorization: Bearer $TOKEN" | jq')
    print()
    print("=" * 60)

    app.run(debug=False, port=5001)  # nosec B201
