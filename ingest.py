"""
AiTelDa Packet Ingestion Routes (Packet-Sentry → Backend)

POST /api/ingest/session          — Open a new monitoring session
POST /api/ingest/session/<id>/end — Close session with final byte counts
POST /api/ingest/snapshots        — Bulk ingest per-app usage snapshots
POST /api/ingest/telco-report     — Submit a telco deduction (SMS/USSD)
POST /api/ingest/anomaly          — Report an Aura-Brain anomaly event
GET  /api/ingest/sessions         — List sessions for a device
GET  /api/ingest/sessions/<id>    — Session detail with per-app breakdown
"""

import json
from flask import Blueprint, request, g, current_app

from app.models.schema import get_db
from app.utils.auth import jwt_required, device_belongs_to_user
from app.utils.validators import require_fields, sanitize_string
from app.utils.responses import success, error
from app.services.variance import update_baseline

ingest_bp = Blueprint("ingest", __name__, url_prefix="/api/ingest")


def _check_device(device_id: str) -> bool:
    return device_belongs_to_user(device_id, g.current_user["id"])


# ---------------------------------------------------------------------------
# POST /api/ingest/session  — open a new monitoring session
# ---------------------------------------------------------------------------
@ingest_bp.route("/session", methods=["POST"])
@jwt_required
def open_session():
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["device_id", "session_start"])
    if not ok:
        return error(msg, 422)

    if not _check_device(data["device_id"]):
        return error("Device not found or not yours", 404)

    screen_state = data.get("screen_state", "off").lower()
    if screen_state not in ("on", "off"):
        screen_state = "off"

    conn = get_db()
    cur = conn.execute(
        """INSERT INTO packet_sessions (device_id, session_start, screen_state,
                                        total_bytes_tx, total_bytes_rx)
           VALUES (?, ?, ?, 0, 0)""",
        (data["device_id"], data["session_start"], screen_state),
    )
    session_id = cur.lastrowid
    conn.commit()
    conn.close()
    return success({"session_id": session_id}, message="Session opened", status=201)


# ---------------------------------------------------------------------------
# POST /api/ingest/session/<session_id>/end  — close a session
# ---------------------------------------------------------------------------
@ingest_bp.route("/session/<int:session_id>/end", methods=["POST"])
@jwt_required
def close_session(session_id):
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["session_end", "total_bytes_tx", "total_bytes_rx"])
    if not ok:
        return error(msg, 422)

    conn = get_db()
    session = conn.execute(
        "SELECT * FROM packet_sessions WHERE id = ?", (session_id,)
    ).fetchone()

    if not session or not _check_device(session["device_id"]):
        conn.close()
        return error("Session not found", 404)

    conn.execute(
        """UPDATE packet_sessions
           SET session_end=?, total_bytes_tx=?, total_bytes_rx=?
           WHERE id=?""",
        (
            data["session_end"],
            int(data["total_bytes_tx"]),
            int(data["total_bytes_rx"]),
            session_id,
        ),
    )
    conn.commit()
    conn.close()
    return success({"session_id": session_id}, message="Session closed")


# ---------------------------------------------------------------------------
# POST /api/ingest/snapshots  — bulk per-app usage data
# ---------------------------------------------------------------------------
@ingest_bp.route("/snapshots", methods=["POST"])
@jwt_required
def ingest_snapshots():
    """
    Accepts a list of per-app usage snapshot objects:
    {
      "session_id": 1,
      "snapshots": [
        {
          "app_uid": "com.whatsapp",
          "app_name": "WhatsApp",
          "bytes_tx": 1024000,
          "bytes_rx": 4096000,
          "dest_ips": ["157.240.1.35"],
          "is_whitelisted": true,
          "snapshot_time": "2024-11-01T02:14:33Z"
        }, ...
      ]
    }
    """
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["session_id", "snapshots"])
    if not ok:
        return error(msg, 422)

    if not isinstance(data["snapshots"], list) or len(data["snapshots"]) == 0:
        return error("snapshots must be a non-empty array", 422)

    conn = get_db()
    session = conn.execute(
        "SELECT * FROM packet_sessions WHERE id = ?", (data["session_id"],)
    ).fetchone()

    if not session or not _check_device(session["device_id"]):
        conn.close()
        return error("Session not found", 404)

    inserted = 0
    for snap in data["snapshots"]:
        if not snap.get("app_uid"):
            continue
        dest_ips = snap.get("dest_ips", [])
        conn.execute(
            """INSERT INTO usage_snapshots
               (session_id, app_uid, app_name, bytes_tx, bytes_rx,
                dest_ips, is_whitelisted, snapshot_time)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                data["session_id"],
                sanitize_string(snap["app_uid"], 200),
                sanitize_string(snap.get("app_name", ""), 200),
                int(snap.get("bytes_tx", 0)),
                int(snap.get("bytes_rx", 0)),
                json.dumps(dest_ips) if dest_ips else None,
                1 if snap.get("is_whitelisted") else 0,
                snap.get("snapshot_time"),
            ),
        )
        inserted += 1

    conn.commit()

    # Trigger async baseline update per app
    device_id = session["device_id"]
    for snap in data["snapshots"]:
        if snap.get("app_uid"):
            total = int(snap.get("bytes_tx", 0)) + int(snap.get("bytes_rx", 0))
            update_baseline(conn, device_id, snap["app_uid"], total)

    conn.commit()
    conn.close()
    return success({"inserted": inserted}, message="Snapshots ingested", status=201)


# ---------------------------------------------------------------------------
# POST /api/ingest/telco-report  — log a telco deduction
# ---------------------------------------------------------------------------
@ingest_bp.route("/telco-report", methods=["POST"])
@jwt_required
def ingest_telco_report():
    """
    Log what the telco claims was consumed.
    {
      "device_id": "abc123",
      "report_date": "2024-11-01",
      "bytes_reported": 52428800,
      "source": "sms",
      "raw_message": "Your data balance is now 500MB...",
      "billing_period_start": "2024-10-01",
      "billing_period_end": "2024-10-31"
    }
    """
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["device_id", "report_date", "bytes_reported"])
    if not ok:
        return error(msg, 422)

    if not _check_device(data["device_id"]):
        return error("Device not found", 404)

    source = data.get("source", "sms").lower()
    if source not in ("sms", "ussd", "manual"):
        source = "manual"

    conn = get_db()
    cur = conn.execute(
        """INSERT INTO telco_reports
           (device_id, report_date, bytes_reported, source, raw_message,
            billing_period_start, billing_period_end)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            data["device_id"],
            data["report_date"],
            int(data["bytes_reported"]),
            source,
            data.get("raw_message", ""),
            data.get("billing_period_start"),
            data.get("billing_period_end"),
        ),
    )
    report_id = cur.lastrowid
    conn.commit()
    conn.close()
    return success({"report_id": report_id}, message="Telco report logged", status=201)


# ---------------------------------------------------------------------------
# POST /api/ingest/anomaly  — report an on-device anomaly detection event
# ---------------------------------------------------------------------------
@ingest_bp.route("/anomaly", methods=["POST"])
@jwt_required
def ingest_anomaly():
    """
    {
      "device_id": "abc123",
      "session_id": 5,
      "app_uid": "com.tiktok.musically",
      "detected_at": "2024-11-01T02:14:33Z",
      "screen_state": "off",
      "baseline_bytes": 2200000,
      "actual_bytes": 40265318,
      "deviation_pct": 17.30
    }
    """
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(
        data, ["device_id", "app_uid", "detected_at", "baseline_bytes", "actual_bytes", "deviation_pct"]
    )
    if not ok:
        return error(msg, 422)

    if not _check_device(data["device_id"]):
        return error("Device not found", 404)

    deviation = float(data["deviation_pct"])
    if deviation < 1:
        severity = "low"
    elif deviation < 5:
        severity = "medium"
    else:
        severity = "high"

    conn = get_db()
    cur = conn.execute(
        """INSERT INTO anomaly_events
           (device_id, session_id, app_uid, detected_at, screen_state,
            baseline_bytes, actual_bytes, deviation_pct, severity)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            data["device_id"],
            data.get("session_id"),
            sanitize_string(data["app_uid"], 200),
            data["detected_at"],
            data.get("screen_state", "off"),
            int(data["baseline_bytes"]),
            int(data["actual_bytes"]),
            deviation,
            severity,
        ),
    )
    anomaly_id = cur.lastrowid
    conn.commit()
    conn.close()
    return success(
        {"anomaly_id": anomaly_id, "severity": severity},
        message="Anomaly recorded",
        status=201,
    )


# ---------------------------------------------------------------------------
# GET /api/ingest/sessions  — list sessions for a device
# ---------------------------------------------------------------------------
@ingest_bp.route("/sessions", methods=["GET"])
@jwt_required
def list_sessions():
    device_id = request.args.get("device_id")
    if not device_id:
        return error("device_id query param required", 422)
    if not _check_device(device_id):
        return error("Device not found", 404)

    limit = min(int(request.args.get("limit", 50)), 200)
    offset = int(request.args.get("offset", 0))

    conn = get_db()
    rows = conn.execute(
        """SELECT id, session_start, session_end, screen_state,
                  total_bytes_tx, total_bytes_rx,
                  (total_bytes_tx + total_bytes_rx) as total_bytes
           FROM packet_sessions
           WHERE device_id = ?
           ORDER BY session_start DESC
           LIMIT ? OFFSET ?""",
        (device_id, limit, offset),
    ).fetchall()
    total = conn.execute(
        "SELECT COUNT(*) as c FROM packet_sessions WHERE device_id = ?", (device_id,)
    ).fetchone()["c"]
    conn.close()

    return success({"sessions": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset})


# ---------------------------------------------------------------------------
# GET /api/ingest/sessions/<session_id>  — session detail
# ---------------------------------------------------------------------------
@ingest_bp.route("/sessions/<int:session_id>", methods=["GET"])
@jwt_required
def session_detail(session_id):
    conn = get_db()
    session = conn.execute(
        "SELECT * FROM packet_sessions WHERE id = ?", (session_id,)
    ).fetchone()

    if not session or not _check_device(session["device_id"]):
        conn.close()
        return error("Session not found", 404)

    snapshots = conn.execute(
        """SELECT app_uid, app_name, bytes_tx, bytes_rx,
                  (bytes_tx + bytes_rx) as total_bytes,
                  dest_ips, is_whitelisted, snapshot_time
           FROM usage_snapshots WHERE session_id = ?
           ORDER BY total_bytes DESC""",
        (session_id,),
    ).fetchall()
    conn.close()

    result = dict(session)
    result["total_bytes"] = result["total_bytes_tx"] + result["total_bytes_rx"]
    result["app_breakdown"] = [dict(s) for s in snapshots]
    return success(result)
