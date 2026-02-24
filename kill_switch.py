"""
AiTelDa Kill Switch Routes — v2.0

GET  /api/killswitch                   — Get current settings for a device
POST /api/killswitch/enable            — Enable Kill Switch
POST /api/killswitch/disable           — Disable Kill Switch
POST /api/killswitch/whitelist/add     — Add app to whitelist
POST /api/killswitch/whitelist/remove  — Remove app from whitelist
POST /api/killswitch/event             — Log a blocked-session event (from device)
GET  /api/killswitch/events            — List block events
GET  /api/killswitch/stats             — Savings statistics
"""

import json
from datetime import datetime, timezone
from flask import Blueprint, request, g

from app.models.schema import get_db
from app.utils.auth import jwt_required, device_belongs_to_user
from app.utils.validators import require_fields
from app.utils.responses import success, error

ks_bp = Blueprint("kill_switch", __name__, url_prefix="/api/killswitch")

# Naira cost per MB (approximate avg across MTN/Airtel/Glo)
NGN_PER_MB = 3.0


def _require_device(device_id: str) -> bool:
    return device_belongs_to_user(device_id, g.current_user["id"])


def _get_or_create_settings(conn, device_id: str) -> dict:
    row = conn.execute(
        "SELECT * FROM kill_switch_settings WHERE device_id=?", (device_id,)
    ).fetchone()
    if not row:
        conn.execute(
            "INSERT INTO kill_switch_settings (device_id) VALUES (?)", (device_id,)
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM kill_switch_settings WHERE device_id=?", (device_id,)
        ).fetchone()
    return dict(row)


# ── GET settings ────────────────────────────────────────────────────────

@ks_bp.route("", methods=["GET"])
@jwt_required
def get_settings():
    device_id = request.args.get("device_id")
    if not device_id:
        return error("device_id query param required", 422)
    if not _require_device(device_id):
        return error("Device not found", 404)

    conn = get_db()
    settings = _get_or_create_settings(conn, device_id)
    conn.close()

    settings["whitelist"] = json.loads(settings.get("whitelist") or "[]")
    settings["money_saved_ngn"] = round(settings["money_saved_ngn"], 2)
    settings["bytes_blocked_mb"] = round(settings["bytes_blocked"] / 1_048_576, 2)
    return success(settings)


# ── ENABLE ──────────────────────────────────────────────────────────────

@ks_bp.route("/enable", methods=["POST"])
@jwt_required
def enable():
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["device_id"])
    if not ok:
        return error(msg, 422)
    if not _require_device(data["device_id"]):
        return error("Device not found", 404)

    conn = get_db()
    _get_or_create_settings(conn, data["device_id"])
    conn.execute(
        "UPDATE kill_switch_settings SET is_enabled=1, updated_at=datetime('now') WHERE device_id=?",
        (data["device_id"],)
    )
    conn.commit()
    conn.close()
    return success(
        {"device_id": data["device_id"], "is_enabled": True},
        message="Kill Switch enabled — screen-off firewall active",
    )


# ── DISABLE ─────────────────────────────────────────────────────────────

@ks_bp.route("/disable", methods=["POST"])
@jwt_required
def disable():
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["device_id"])
    if not ok:
        return error(msg, 422)
    if not _require_device(data["device_id"]):
        return error("Device not found", 404)

    conn = get_db()
    _get_or_create_settings(conn, data["device_id"])
    conn.execute(
        "UPDATE kill_switch_settings SET is_enabled=0, updated_at=datetime('now') WHERE device_id=?",
        (data["device_id"],)
    )
    conn.commit()
    conn.close()
    return success(
        {"device_id": data["device_id"], "is_enabled": False},
        message="Kill Switch disabled — background data now permitted",
    )


# ── WHITELIST ADD ───────────────────────────────────────────────────────

@ks_bp.route("/whitelist/add", methods=["POST"])
@jwt_required
def whitelist_add():
    """
    { "device_id": "...", "app_uid": "com.whatsapp", "app_name": "WhatsApp" }
    """
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["device_id", "app_uid"])
    if not ok:
        return error(msg, 422)
    if not _require_device(data["device_id"]):
        return error("Device not found", 404)

    conn = get_db()
    settings = _get_or_create_settings(conn, data["device_id"])
    whitelist = json.loads(settings.get("whitelist") or "[]")

    entry = {"app_uid": data["app_uid"], "app_name": data.get("app_name", data["app_uid"])}
    if not any(w["app_uid"] == data["app_uid"] for w in whitelist):
        whitelist.append(entry)

    conn.execute(
        "UPDATE kill_switch_settings SET whitelist=?, updated_at=datetime('now') WHERE device_id=?",
        (json.dumps(whitelist), data["device_id"])
    )
    conn.commit()
    conn.close()
    return success({"whitelist": whitelist}, message=f"{entry['app_name']} added to whitelist — background data permitted")


# ── WHITELIST REMOVE ────────────────────────────────────────────────────

@ks_bp.route("/whitelist/remove", methods=["POST"])
@jwt_required
def whitelist_remove():
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["device_id", "app_uid"])
    if not ok:
        return error(msg, 422)
    if not _require_device(data["device_id"]):
        return error("Device not found", 404)

    conn = get_db()
    settings = _get_or_create_settings(conn, data["device_id"])
    whitelist = json.loads(settings.get("whitelist") or "[]")
    whitelist = [w for w in whitelist if w["app_uid"] != data["app_uid"]]

    conn.execute(
        "UPDATE kill_switch_settings SET whitelist=?, updated_at=datetime('now') WHERE device_id=?",
        (json.dumps(whitelist), data["device_id"])
    )
    conn.commit()
    conn.close()
    return success({"whitelist": whitelist}, message="App removed from whitelist")


# ── LOG BLOCK EVENT ─────────────────────────────────────────────────────

@ks_bp.route("/event", methods=["POST"])
@jwt_required
def log_event():
    """
    On-device Packet-Sentry reports a blocked session.
    {
      "device_id": "...",
      "app_uid": "com.zhiliaoapp.musically",
      "app_name": "TikTok",
      "bytes_blocked": 12345678,
      "screen_state": "off",
      "event_time": "2026-02-14T02:41:07Z"
    }
    """
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["device_id", "app_uid", "bytes_blocked"])
    if not ok:
        return error(msg, 422)
    if not _require_device(data["device_id"]):
        return error("Device not found", 404)

    bytes_blocked = int(data["bytes_blocked"])
    money_saved   = (bytes_blocked / 1_048_576) * NGN_PER_MB

    conn = get_db()
    _get_or_create_settings(conn, data["device_id"])

    conn.execute("""
        INSERT INTO kill_switch_events
            (device_id, app_uid, app_name, bytes_blocked, screen_state, event_time)
        VALUES (?, ?, ?, ?, ?, COALESCE(?, datetime('now')))
    """, (
        data["device_id"],
        data["app_uid"],
        data.get("app_name", data["app_uid"]),
        bytes_blocked,
        data.get("screen_state", "off"),
        data.get("event_time"),
    ))

    # Update running totals
    conn.execute("""
        UPDATE kill_switch_settings
        SET bytes_blocked   = bytes_blocked + ?,
            money_saved_ngn = money_saved_ngn + ?,
            updated_at      = datetime('now')
        WHERE device_id=?
    """, (bytes_blocked, money_saved, data["device_id"]))

    conn.commit()
    conn.close()
    return success(
        {"bytes_blocked": bytes_blocked, "money_saved_ngn": round(money_saved, 2)},
        message="Block event logged",
        status=201,
    )


# ── LIST EVENTS ─────────────────────────────────────────────────────────

@ks_bp.route("/events", methods=["GET"])
@jwt_required
def list_events():
    device_id = request.args.get("device_id")
    if not device_id:
        return error("device_id query param required", 422)
    if not _require_device(device_id):
        return error("Device not found", 404)

    limit  = min(int(request.args.get("limit", 50)), 500)
    offset = int(request.args.get("offset", 0))

    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM kill_switch_events
        WHERE device_id=?
        ORDER BY event_time DESC
        LIMIT ? OFFSET ?
    """, (device_id, limit, offset)).fetchall()
    total = conn.execute(
        "SELECT COUNT(*) as c FROM kill_switch_events WHERE device_id=?", (device_id,)
    ).fetchone()["c"]
    conn.close()

    return success({
        "events": [dict(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    })


# ── STATS ───────────────────────────────────────────────────────────────

@ks_bp.route("/stats", methods=["GET"])
@jwt_required
def stats():
    """Comprehensive savings statistics for a device."""
    device_id = request.args.get("device_id")
    if not device_id:
        return error("device_id query param required", 422)
    if not _require_device(device_id):
        return error("Device not found", 404)

    conn = get_db()
    settings = _get_or_create_settings(conn, device_id)

    # Top apps blocked
    top_apps = conn.execute("""
        SELECT app_uid, app_name,
               SUM(bytes_blocked) as total_bytes,
               COUNT(*) as events
        FROM kill_switch_events
        WHERE device_id=?
        GROUP BY app_uid, app_name
        ORDER BY total_bytes DESC
        LIMIT 10
    """, (device_id,)).fetchall()

    # Daily savings last 30 days
    daily = conn.execute("""
        SELECT date(event_time) as day,
               SUM(bytes_blocked) as bytes,
               COUNT(*) as events
        FROM kill_switch_events
        WHERE device_id=? AND event_time >= datetime('now', '-30 days')
        GROUP BY day
        ORDER BY day ASC
    """, (device_id,)).fetchall()

    bytes_blocked = settings["bytes_blocked"]
    mb_blocked    = bytes_blocked / 1_048_576
    money_saved   = settings["money_saved_ngn"]

    conn.close()
    return success({
        "device_id":        device_id,
        "is_enabled":       bool(settings["is_enabled"]),
        "bytes_blocked":    bytes_blocked,
        "mb_blocked":       round(mb_blocked, 2),
        "money_saved_ngn":  round(money_saved, 2),
        "yearly_projection_ngn": round(money_saved * 12, 2),
        "whitelist":        json.loads(settings.get("whitelist") or "[]"),
        "top_apps_blocked": [dict(r) for r in top_apps],
        "daily_savings":    [dict(r) for r in daily],
    })
