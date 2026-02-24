"""
AiTelDa Auth Routes
POST /api/auth/register
POST /api/auth/login
POST /api/auth/refresh
POST /api/auth/logout
GET  /api/auth/me
"""

import hashlib
from flask import Blueprint, request, current_app
from werkzeug.security import generate_password_hash, check_password_hash

from app.models.schema import get_db
from app.utils.auth import (
    generate_access_token,
    generate_refresh_token,
    store_refresh_token,
    revoke_refresh_token,
    validate_refresh_token,
    jwt_required,
)
from app.utils.validators import validate_email, validate_password, require_fields
from app.utils.responses import success, error

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


# ---------------------------------------------------------------------------
# POST /api/auth/register
# ---------------------------------------------------------------------------
@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}

    ok, msg = require_fields(data, ["email", "password", "full_name"])
    if not ok:
        return error(msg, 422)

    if not validate_email(data["email"]):
        return error("Invalid email address", 422)

    pw_ok, pw_msg = validate_password(data["password"])
    if not pw_ok:
        return error(pw_msg, 422)

    conn = get_db()
    existing = conn.execute(
        "SELECT id FROM users WHERE email = ?", (data["email"].lower(),)
    ).fetchone()
    if existing:
        conn.close()
        return error("An account with this email already exists", 409)

    pw_hash = generate_password_hash(data["password"])
    cur = conn.execute(
        """INSERT INTO users (email, password_hash, full_name, phone)
           VALUES (?, ?, ?, ?)""",
        (
            data["email"].lower().strip(),
            pw_hash,
            data["full_name"].strip(),
            data.get("phone", "").strip() or None,
        ),
    )
    user_id = cur.lastrowid
    conn.commit()
    conn.close()

    access_token = generate_access_token(user_id, data["email"].lower())
    raw_refresh, refresh_hash = generate_refresh_token(user_id)
    store_refresh_token(
        user_id, refresh_hash, current_app.config["JWT_REFRESH_EXPIRES_DAYS"]
    )

    return success(
        {
            "user": {"id": user_id, "email": data["email"].lower(), "full_name": data["full_name"].strip()},
            "access_token": access_token,
            "refresh_token": raw_refresh,
            "token_type": "Bearer",
        },
        message="Account created successfully",
        status=201,
    )


# ---------------------------------------------------------------------------
# POST /api/auth/login
# ---------------------------------------------------------------------------
@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    ok, msg = require_fields(data, ["email", "password"])
    if not ok:
        return error(msg, 422)

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE email = ? AND is_active = 1",
        (data["email"].lower().strip(),),
    ).fetchone()
    conn.close()

    if not user or not check_password_hash(user["password_hash"], data["password"]):
        return error("Invalid email or password", 401)

    access_token = generate_access_token(user["id"], user["email"])
    raw_refresh, refresh_hash = generate_refresh_token(user["id"])
    store_refresh_token(
        user["id"], refresh_hash, current_app.config["JWT_REFRESH_EXPIRES_DAYS"]
    )

    return success(
        {
            "user": {
                "id": user["id"],
                "email": user["email"],
                "full_name": user["full_name"],
                "is_verified": bool(user["is_verified"]),
            },
            "access_token": access_token,
            "refresh_token": raw_refresh,
            "token_type": "Bearer",
        },
        message="Login successful",
    )


# ---------------------------------------------------------------------------
# POST /api/auth/refresh
# ---------------------------------------------------------------------------
@auth_bp.route("/refresh", methods=["POST"])
def refresh():
    data = request.get_json(silent=True) or {}
    raw_token = data.get("refresh_token", "")

    if not raw_token:
        return error("refresh_token is required", 422)

    token_data = validate_refresh_token(raw_token)
    if not token_data:
        return error("Invalid or expired refresh token", 401)

    # Rotate: revoke old, issue new
    old_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    revoke_refresh_token(old_hash)

    new_access = generate_access_token(token_data["user_id"], token_data["email"])
    raw_refresh, refresh_hash = generate_refresh_token(token_data["user_id"])
    store_refresh_token(
        token_data["user_id"],
        refresh_hash,
        current_app.config["JWT_REFRESH_EXPIRES_DAYS"],
    )

    return success(
        {
            "access_token": new_access,
            "refresh_token": raw_refresh,
            "token_type": "Bearer",
        },
        message="Token refreshed",
    )


# ---------------------------------------------------------------------------
# POST /api/auth/logout
# ---------------------------------------------------------------------------
@auth_bp.route("/logout", methods=["POST"])
@jwt_required
def logout():
    data = request.get_json(silent=True) or {}
    raw_token = data.get("refresh_token", "")

    if raw_token:
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        revoke_refresh_token(token_hash)

    return success(message="Logged out successfully")


# ---------------------------------------------------------------------------
# GET /api/auth/me
# ---------------------------------------------------------------------------
@auth_bp.route("/me", methods=["GET"])
@jwt_required
def me():
    from flask import g

    conn = get_db()
    user = conn.execute(
        "SELECT id, email, full_name, phone, is_verified, created_at FROM users WHERE id = ?",
        (g.current_user["id"],),
    ).fetchone()
    device_count = conn.execute(
        "SELECT COUNT(*) as c FROM devices WHERE user_id = ?", (g.current_user["id"],)
    ).fetchone()["c"]
    conn.close()

    if not user:
        return error("User not found", 404)

    return success(
        {
            "id": user["id"],
            "email": user["email"],
            "full_name": user["full_name"],
            "phone": user["phone"],
            "is_verified": bool(user["is_verified"]),
            "registered_devices": device_count,
            "created_at": user["created_at"],
        }
    )
