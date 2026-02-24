"""
AiTelDa Analytics Routes — v2.0

GET  /api/analytics/summary                — User-level dashboard summary (expanded)
GET  /api/analytics/device/<device_id>     — Per-device deep analytics
GET  /api/analytics/baselines/<device_id>  — App usage baselines
POST /api/analytics/check-anomaly          — Stateless anomaly check
GET  /api/analytics/dashboard/<device_id>  — Full dashboard data in one call
GET  /api/analytics/trend/<device_id>      — Chart-ready time-series data
GET  /api/analytics/savings/<device_id>    — Savings breakdown across all tools
"""

from flask import Blueprint, request, g
from datetime import datetime, timezone
from app.models.schema import get_db
from app.utils.auth import jwt_required, device_belongs_to_user
from app.utils.responses import success, error
from app.services.variance import get_baselines, check_anomaly_threshold

analytics_bp = Blueprint("analytics", __name__, url_prefix="/api/analytics")

NGN_PER_MB = 3.0


def _check_device(device_id, user_id):
    return device_belongs_to_user(device_id, user_id)


# ── SUMMARY ──────────────────────────────────────────────────────────────

@analytics_bp.route("/summary", methods=["GET"])
@jwt_required
def summary():
    conn = get_db()
    user_id = g.current_user["id"]

    devices = conn.execute(
        "SELECT COUNT(*) as c FROM devices WHERE user_id=?", (user_id,)
    ).fetchone()["c"]

    disputes = conn.execute("""
        SELECT status, COUNT(*) as c FROM dispute_cases
        WHERE user_id=? GROUP BY status
    """, (user_id,)).fetchall()
    disputes_by_status = {r["status"]: r["c"] for r in disputes}

    total_bytes = conn.execute("""
        SELECT SUM(ps.total_bytes_tx + ps.total_bytes_rx) as total
        FROM packet_sessions ps
        JOIN devices d ON d.device_id=ps.device_id
        WHERE d.user_id=?
    """, (user_id,)).fetchone()["total"] or 0

    anomalies = conn.execute("""
        SELECT COUNT(*) as c FROM anomaly_events ae
        JOIN devices d ON d.device_id=ae.device_id
        WHERE d.user_id=? AND ae.created_at >= datetime('now', '-30 days')
    """, (user_id,)).fetchone()["c"]

    # Kill Switch savings (all devices)
    ks_savings = conn.execute("""
        SELECT SUM(ks.bytes_blocked) as bytes, SUM(ks.money_saved_ngn) as money
        FROM kill_switch_settings ks
        JOIN devices d ON d.device_id=ks.device_id
        WHERE d.user_id=?
    """, (user_id,)).fetchone()

    # DNS savings
    dns_savings = conn.execute("""
        SELECT SUM(db.bytes_saved) as bytes
        FROM dns_blocked_domains db
        JOIN devices d ON d.device_id=db.device_id
        WHERE d.user_id=?
    """, (user_id,)).fetchone()

    worst = conn.execute("""
        SELECT reference, variance_pct, period_start, period_end
        FROM dispute_cases WHERE user_id=? ORDER BY variance_pct DESC LIMIT 1
    """, (user_id,)).fetchone()

    conn.close()

    total_saved_bytes = (ks_savings["bytes"] or 0) + (dns_savings["bytes"] or 0)

    return success({
        "registered_devices":     devices,
        "total_bytes_monitored":  total_bytes,
        "total_bytes_monitored_mb": round(total_bytes / 1_048_576, 2),
        "disputes":               disputes_by_status,
        "total_disputes":         sum(disputes_by_status.values()),
        "anomalies_last_30_days": anomalies,
        "highest_variance_dispute": dict(worst) if worst else None,
        "savings": {
            "total_bytes_saved":  total_saved_bytes,
            "total_mb_saved":     round(total_saved_bytes / 1_048_576, 2),
            "kill_switch_ngn":    round(ks_savings["money"] or 0, 2),
            "kill_switch_bytes":  ks_savings["bytes"] or 0,
            "dns_bytes_saved":    dns_savings["bytes"] or 0,
        },
    })


# ── DEVICE ANALYTICS ─────────────────────────────────────────────────────

@analytics_bp.route("/device/<device_id>", methods=["GET"])
@jwt_required
def device_analytics(device_id):
    if not _check_device(device_id, g.current_user["id"]):
        return error("Device not found", 404)

    days = min(int(request.args.get("days", 30)), 90)
    conn = get_db()

    daily = conn.execute("""
        SELECT date(session_start) as day,
               SUM(total_bytes_tx + total_bytes_rx) as total_bytes,
               COUNT(*) as sessions
        FROM packet_sessions
        WHERE device_id=? AND session_start >= datetime('now', ? || ' days')
        GROUP BY day ORDER BY day ASC
    """, (device_id, f"-{days}")).fetchall()

    top_apps = conn.execute("""
        SELECT us.app_uid, us.app_name,
               SUM(us.bytes_tx + us.bytes_rx) as total_bytes,
               COUNT(DISTINCT us.session_id) as sessions
        FROM usage_snapshots us
        JOIN packet_sessions ps ON ps.id=us.session_id
        WHERE ps.device_id=?
        GROUP BY us.app_uid, us.app_name
        ORDER BY total_bytes DESC LIMIT 15
    """, (device_id,)).fetchall()

    anomaly_trend = conn.execute("""
        SELECT date(detected_at) as day,
               COUNT(*) as count,
               MAX(deviation_pct) as max_deviation
        FROM anomaly_events
        WHERE device_id=? AND detected_at >= datetime('now', ? || ' days')
        GROUP BY day ORDER BY day ASC
    """, (device_id, f"-{days}")).fetchall()

    screen_breakdown = conn.execute("""
        SELECT screen_state,
               SUM(total_bytes_tx + total_bytes_rx) as bytes,
               COUNT(*) as sessions
        FROM packet_sessions WHERE device_id=? GROUP BY screen_state
    """, (device_id,)).fetchall()

    recent_anomalies = conn.execute("""
        SELECT app_uid, app_name, detected_at, deviation_pct, severity,
               screen_state, actual_bytes, baseline_bytes
        FROM anomaly_events
        WHERE device_id=? ORDER BY detected_at DESC LIMIT 20
    """, (device_id,)).fetchall()

    conn.close()
    return success({
        "device_id":            device_id,
        "period_days":          days,
        "daily_usage":          [dict(r) for r in daily],
        "top_apps":             [dict(r) for r in top_apps],
        "anomaly_trend":        [dict(r) for r in anomaly_trend],
        "screen_state_breakdown": [dict(r) for r in screen_breakdown],
        "recent_anomalies":     [dict(r) for r in recent_anomalies],
    })


# ── BASELINES ─────────────────────────────────────────────────────────────

@analytics_bp.route("/baselines/<device_id>", methods=["GET"])
@jwt_required
def device_baselines(device_id):
    if not _check_device(device_id, g.current_user["id"]):
        return error("Device not found", 404)

    baselines = get_baselines(device_id)
    formatted = [
        {
            "app_uid":         uid,
            "avg_daily_bytes": data["avg_daily_bytes"],
            "avg_daily_mb":    round(data["avg_daily_bytes"] / 1_048_576, 3),
            "sample_days":     data["sample_days"],
        }
        for uid, data in sorted(baselines.items(), key=lambda x: -x[1]["avg_daily_bytes"])
    ]
    return success({"device_id": device_id, "baselines": formatted, "app_count": len(formatted)})


# ── CHECK ANOMALY ─────────────────────────────────────────────────────────

@analytics_bp.route("/check-anomaly", methods=["POST"])
@jwt_required
def check_anomaly():
    data = request.get_json(silent=True) or {}
    baseline = data.get("baseline_bytes", 0)
    actual   = data.get("actual_bytes", 0)

    if not isinstance(baseline, (int, float)) or not isinstance(actual, (int, float)):
        return error("baseline_bytes and actual_bytes must be numbers", 422)

    result = check_anomaly_threshold(int(baseline), int(actual))
    return success(result)


# ── FULL DASHBOARD ────────────────────────────────────────────────────────

@analytics_bp.route("/dashboard/<device_id>", methods=["GET"])
@jwt_required
def full_dashboard(device_id):
    """
    One-shot endpoint returning everything the dashboard needs:
    - Current variance gauge
    - Kill Switch status
    - Recent anomalies
    - Top apps
    - Savings summary
    - Recent disputes
    """
    if not _check_device(device_id, g.current_user["id"]):
        return error("Device not found", 404)

    conn = get_db()

    # Device info
    device = conn.execute(
        "SELECT * FROM devices WHERE device_id=?", (device_id,)
    ).fetchone()

    # Latest telco report
    latest_telco = conn.execute("""
        SELECT * FROM telco_reports WHERE device_id=?
        ORDER BY created_at DESC LIMIT 1
    """, (device_id,)).fetchone()

    # Device bytes this cycle (last 30 days)
    device_bytes_row = conn.execute("""
        SELECT SUM(total_bytes_tx + total_bytes_rx) as total
        FROM packet_sessions
        WHERE device_id=? AND session_start >= datetime('now', '-30 days')
    """, (device_id,)).fetchone()
    device_bytes = device_bytes_row["total"] or 0
    telco_bytes  = latest_telco["bytes_reported"] if latest_telco else 0

    variance_bytes = abs(device_bytes - telco_bytes)
    variance_pct   = (variance_bytes / telco_bytes * 100) if telco_bytes > 0 else 0
    overbilled     = device_bytes < telco_bytes and variance_pct > 5

    # Kill Switch
    ks = conn.execute(
        "SELECT * FROM kill_switch_settings WHERE device_id=?", (device_id,)
    ).fetchone()

    # Recent anomalies (24h)
    anomalies = conn.execute("""
        SELECT * FROM anomaly_events
        WHERE device_id=? AND detected_at >= datetime('now', '-24 hours')
        ORDER BY detected_at DESC LIMIT 10
    """, (device_id,)).fetchall()

    # Top 5 apps (last 7 days)
    top_apps = conn.execute("""
        SELECT us.app_uid, us.app_name,
               SUM(us.bytes_tx + us.bytes_rx) as total_bytes
        FROM usage_snapshots us
        JOIN packet_sessions ps ON ps.id=us.session_id
        WHERE ps.device_id=? AND ps.session_start >= datetime('now', '-7 days')
        GROUP BY us.app_uid, us.app_name
        ORDER BY total_bytes DESC LIMIT 5
    """, (device_id,)).fetchall()

    # Active disputes
    disputes = conn.execute("""
        SELECT reference, variance_pct, status, period_start, period_end, created_at
        FROM dispute_cases
        WHERE device_id=? AND status NOT IN ('resolved', 'rejected')
        ORDER BY created_at DESC LIMIT 5
    """, (device_id,)).fetchall()

    # DNS blocked today
    dns_today = conn.execute("""
        SELECT COUNT(*) as c, SUM(bytes_saved) as saved
        FROM dns_blocked_domains
        WHERE device_id=? AND blocked_at >= datetime('now', '-24 hours')
    """, (device_id,)).fetchone()

    conn.close()

    ks_bytes    = ks["bytes_blocked"]  if ks else 0
    ks_money    = ks["money_saved_ngn"] if ks else 0
    ks_enabled  = bool(ks["is_enabled"]) if ks else False
    dns_blocked = dns_today["c"]     or 0
    dns_saved   = dns_today["saved"] or 0

    total_saved_mb = (ks_bytes + (dns_saved or 0)) / 1_048_576

    return success({
        "device": dict(device) if device else None,
        "variance": {
            "device_bytes":          device_bytes,
            "telco_bytes":           telco_bytes,
            "variance_bytes":        variance_bytes,
            "variance_pct":          round(variance_pct, 2),
            "is_suspected_overbilling": overbilled,
            "dispute_eligible":      variance_pct > 5,
        },
        "kill_switch": {
            "is_enabled":     ks_enabled,
            "bytes_blocked":  ks_bytes,
            "mb_blocked":     round(ks_bytes / 1_048_576, 2),
            "money_saved_ngn": round(ks_money, 2),
        },
        "anomalies_24h":    [dict(a) for a in anomalies],
        "top_apps":         [dict(a) for a in top_apps],
        "active_disputes":  [dict(d) for d in disputes],
        "savings_today": {
            "dns_domains_blocked":   dns_blocked,
            "dns_bytes_saved":       dns_saved,
            "total_mb_saved":        round(total_saved_mb, 2),
            "ngn_equivalent":        round(total_saved_mb * NGN_PER_MB, 2),
        },
    })


# ── TREND DATA ────────────────────────────────────────────────────────────

@analytics_bp.route("/trend/<device_id>", methods=["GET"])
@jwt_required
def trend_data(device_id):
    """Return chart-ready time-series: device vs telco vs anomalies."""
    if not _check_device(device_id, g.current_user["id"]):
        return error("Device not found", 404)

    days = min(int(request.args.get("days", 30)), 90)
    conn = get_db()

    # Daily device usage
    daily_device = conn.execute("""
        SELECT date(session_start) as day,
               SUM(total_bytes_tx + total_bytes_rx) as bytes
        FROM packet_sessions
        WHERE device_id=? AND session_start >= datetime('now', ? || ' days')
        GROUP BY day ORDER BY day ASC
    """, (device_id, f"-{days}")).fetchall()

    # Kill switch blocks daily
    daily_blocked = conn.execute("""
        SELECT date(event_time) as day,
               SUM(bytes_blocked) as bytes
        FROM kill_switch_events
        WHERE device_id=? AND event_time >= datetime('now', ? || ' days')
        GROUP BY day ORDER BY day ASC
    """, (device_id, f"-{days}")).fetchall()

    # Anomaly count daily
    daily_anomalies = conn.execute("""
        SELECT date(detected_at) as day, COUNT(*) as count
        FROM anomaly_events
        WHERE device_id=? AND detected_at >= datetime('now', ? || ' days')
        GROUP BY day ORDER BY day ASC
    """, (device_id, f"-{days}")).fetchall()

    conn.close()
    return success({
        "device_id":       device_id,
        "period_days":     days,
        "daily_device":    [dict(r) for r in daily_device],
        "daily_blocked":   [dict(r) for r in daily_blocked],
        "daily_anomalies": [dict(r) for r in daily_anomalies],
    })


# ── SAVINGS BREAKDOWN ─────────────────────────────────────────────────────

@analytics_bp.route("/savings/<device_id>", methods=["GET"])
@jwt_required
def savings_breakdown(device_id):
    """Full savings summary across all six diagnostic tools."""
    if not _check_device(device_id, g.current_user["id"]):
        return error("Device not found", 404)

    conn = get_db()

    ks = conn.execute(
        "SELECT bytes_blocked, money_saved_ngn FROM kill_switch_settings WHERE device_id=?",
        (device_id,)
    ).fetchone()

    dns = conn.execute(
        "SELECT SUM(bytes_saved) as saved FROM dns_blocked_domains WHERE device_id=?",
        (device_id,)
    ).fetchone()

    phishing = conn.execute(
        "SELECT COUNT(*) as count, SUM(bytes_prevented) as prevented FROM phishing_intercepts WHERE device_id=?",
        (device_id,)
    ).fetchone()

    updates = conn.execute(
        "SELECT COUNT(*) as count, SUM(size_bytes) as bytes FROM update_queue WHERE device_id=? AND status='held'",
        (device_id,)
    ).fetchone()

    video = conn.execute(
        "SELECT SUM(bytes_saved) as saved FROM video_governor_settings WHERE device_id=?",
        (device_id,)
    ).fetchone()

    # Total bytes refunded via disputes
    disputes = conn.execute(
        "SELECT SUM(variance_bytes) as bytes, COUNT(*) as count FROM dispute_cases WHERE device_id=? AND status='resolved'",
        (device_id,)
    ).fetchone()

    conn.close()

    ks_bytes        = ks["bytes_blocked"] if ks else 0
    dns_bytes       = dns["saved"] or 0
    phishing_bytes  = phishing["prevented"] or 0
    updates_bytes   = updates["bytes"] or 0
    video_bytes     = video["saved"] or 0
    dispute_bytes   = disputes["bytes"] or 0

    total_bytes = ks_bytes + dns_bytes + phishing_bytes + updates_bytes + video_bytes
    total_mb    = total_bytes / 1_048_576
    total_ngn   = (ks["money_saved_ngn"] if ks else 0) + (total_mb - ks_bytes / 1_048_576) * NGN_PER_MB

    return success({
        "device_id": device_id,
        "total_bytes_saved": total_bytes,
        "total_mb_saved":    round(total_mb, 2),
        "total_ngn_saved":   round(ks["money_saved_ngn"] if ks else 0, 2),
        "yearly_projection_ngn": round((ks["money_saved_ngn"] if ks else 0) * 12, 2),
        "breakdown": {
            "kill_switch": {
                "bytes":  ks_bytes,
                "mb":     round(ks_bytes / 1_048_576, 2),
                "ngn":    round(ks["money_saved_ngn"] if ks else 0, 2),
            },
            "dns_blackhole": {
                "bytes":  dns_bytes,
                "mb":     round(dns_bytes / 1_048_576, 2),
            },
            "phishing_interceptor": {
                "bytes":  phishing_bytes,
                "events": phishing["count"] or 0,
            },
            "update_guardian": {
                "bytes":   updates_bytes,
                "mb":      round(updates_bytes / 1_048_576, 2),
                "updates": updates["count"] or 0,
            },
            "video_governor": {
                "bytes": video_bytes,
                "mb":    round(video_bytes / 1_048_576, 2),
            },
            "dispute_refunds": {
                "bytes":    dispute_bytes,
                "disputes": disputes["count"] or 0,
            },
        },
    })
