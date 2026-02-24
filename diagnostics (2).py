"""
AiTelDa Diagnostic Routes — v2.0

All six Diagnostic Suite tools exposed as REST endpoints:

  A. Malware Auditor
     GET  /api/diagnostics/malware/scan
     POST /api/diagnostics/malware/quarantine
     POST /api/diagnostics/malware/release
     GET  /api/diagnostics/malware/quarantined

  B. DNS Blackhole
     GET  /api/diagnostics/dns/stats
     POST /api/diagnostics/dns/check
     POST /api/diagnostics/dns/block
     GET  /api/diagnostics/dns/blacklist

  C. Phishing Interceptor
     POST /api/diagnostics/phishing/check
     POST /api/diagnostics/phishing/report
     GET  /api/diagnostics/phishing/events

  D. Update Guardian
     GET  /api/diagnostics/updates/queue
     POST /api/diagnostics/updates/queue
     POST /api/diagnostics/updates/approve
     POST /api/diagnostics/updates/policy

  E. Video Governor
     GET  /api/diagnostics/video/settings
     POST /api/diagnostics/video/set-quality

  F. Zero-Perm Audit
     POST /api/diagnostics/zeroperm/audit
     GET  /api/diagnostics/zeroperm/history

  G. Full suite run
     POST /api/diagnostics/run-all
     GET  /api/diagnostics/summary
"""

from flask import Blueprint, request, g
from app.utils.auth import jwt_required, device_belongs_to_user
from app.utils.validators import require_fields
from app.utils.responses import success, error
from app.services.diagnostics import (
    # Malware
    run_malware_scan, quarantine_app, release_quarantine, get_quarantined_apps,
    # DNS
    check_dns_domain, log_dns_block, get_dns_stats, get_blacklist, add_to_blacklist,
    # Phishing
    check_url_safety, log_phishing_intercept, get_phishing_events,
    # Updates
    queue_update, approve_update, get_update_queue, set_update_policy,
    # Video
    set_video_quality, get_video_settings,
    # Zero-perm
    run_zero_perm_audit, get_audit_history, calculate_risk_score,
)
from app.models.schema import get_db
from datetime import datetime, timezone

diag_bp = Blueprint("diagnostics", __name__, url_prefix="/api/diagnostics")


def _require_device(device_id: str) -> bool:
    return device_belongs_to_user(device_id, g.current_user["id"])


# ═══════════════════════════════════════════════════════════════════════
# G. Summary & Full Run
# ═══════════════════════════════════════════════════════════════════════

@diag_bp.route("/summary", methods=["GET"])
@jwt_required
def diagnostic_summary():
    """Return high-level threat summary across all tools for the user."""
    device_id = request.args.get("device_id")
    if not device_id:
        return error("device_id query param required", 422)
    if not _require_device(device_id):
        return error("Device not found", 404)

    conn = get_db()

    quarantined = conn.execute(
        "SELECT COUNT(*) as c FROM quarantined_apps WHERE device_id=? AND is_active=1",
        (device_id,)
    ).fetchone()["c"]

    dns_blocked = conn.execute(
        "SELECT COUNT(*) as c, SUM(bytes_saved) as saved FROM dns_blocked_domains WHERE device_id=?",
        (device_id,)
    ).fetchone()

    phishing = conn.execute(
        "SELECT COUNT(*) as c, SUM(bytes_prevented) as prevented FROM phishing_intercepts WHERE device_id=?",
        (device_id,)
    ).fetchone()

    updates_held = conn.execute(
        "SELECT COUNT(*) as c, SUM(size_bytes) as bytes FROM update_queue WHERE device_id=? AND status='held'",
        (device_id,)
    ).fetchone()

    video_savings = conn.execute(
        "SELECT SUM(bytes_saved) as saved FROM video_governor_settings WHERE device_id=?",
        (device_id,)
    ).fetchone()

    critical_apps = conn.execute(
        """SELECT COUNT(*) as c FROM zero_perm_audits
           WHERE device_id=? AND risk_score >= 75
             AND audited_at = (SELECT MAX(audited_at) FROM zero_perm_audits z2 WHERE z2.device_id=zero_perm_audits.device_id AND z2.app_uid=zero_perm_audits.app_uid)""",
        (device_id,)
    ).fetchone()["c"]

    anomalies_24h = conn.execute(
        """SELECT COUNT(*) as c FROM anomaly_events
           WHERE device_id=? AND detected_at >= datetime('now', '-24 hours')""",
        (device_id,)
    ).fetchone()["c"]

    conn.close()

    total_bytes_saved = (
        (dns_blocked["saved"] or 0) +
        (phishing["prevented"] or 0) +
        (updates_held["bytes"] or 0) +
        (video_savings["saved"] or 0)
    )

    return success({
        "device_id":            device_id,
        "threats": {
            "quarantined_apps":     quarantined,
            "dns_domains_blocked":  dns_blocked["c"] or 0,
            "phishing_blocked":     phishing["c"] or 0,
            "updates_held":         updates_held["c"] or 0,
            "high_risk_apps":       critical_apps,
            "anomalies_24h":        anomalies_24h,
        },
        "savings": {
            "total_bytes_saved":    total_bytes_saved,
            "total_mb_saved":       round(total_bytes_saved / 1_048_576, 2),
            "dns_bytes_saved":      dns_blocked["saved"] or 0,
            "phishing_prevented":   phishing["prevented"] or 0,
            "update_bytes_held":    updates_held["bytes"] or 0,
            "video_bytes_saved":    video_savings["saved"] or 0,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    })


@diag_bp.route("/run-all", methods=["POST"])
@jwt_required
def run_all_diagnostics():
    """
    Chain all diagnostic tools and return a combined report.
    Body: { "device_id": "...", "apps": [...] }
    """
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["device_id"])
    if not ok:
        return error(msg, 422)
    if not _require_device(data["device_id"]):
        return error("Device not found", 404)

    device_id = data["device_id"]

    malware   = run_malware_scan(device_id, window_hours=data.get("window_hours", 24))
    dns       = get_dns_stats(device_id, days=data.get("days", 30))
    phishing  = get_phishing_events(device_id, days=data.get("days", 30))
    updates   = get_update_queue(device_id)
    video     = get_video_settings(device_id)

    # Zero-perm if apps provided
    zeroperm = None
    if data.get("apps"):
        zeroperm = run_zero_perm_audit(device_id, data["apps"])

    # Log the run
    conn = get_db()
    conn.execute("""
        INSERT INTO diagnostic_runs (user_id, device_id, tool, status, finished_at)
        VALUES (?, ?, 'full_suite', 'complete', datetime('now'))
    """, (g.current_user["id"], device_id))
    conn.commit()
    conn.close()

    return success({
        "device_id":  device_id,
        "malware":    malware,
        "dns":        dns,
        "phishing":   phishing,
        "updates":    updates,
        "video":      video,
        "zero_perm":  zeroperm,
        "ran_at":     datetime.now(timezone.utc).isoformat(),
    })


# ═══════════════════════════════════════════════════════════════════════
# A. BEHAVIORAL MALWARE AUDITOR
# ═══════════════════════════════════════════════════════════════════════

@diag_bp.route("/malware/scan", methods=["GET"])
@jwt_required
def malware_scan():
    device_id = request.args.get("device_id")
    if not device_id:
        return error("device_id query param required", 422)
    if not _require_device(device_id):
        return error("Device not found", 404)

    hours = min(int(request.args.get("hours", 24)), 168)
    result = run_malware_scan(device_id, window_hours=hours)
    return success(result)


@diag_bp.route("/malware/quarantine", methods=["POST"])
@jwt_required
def quarantine():
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["device_id", "app_uid"])
    if not ok:
        return error(msg, 422)
    if not _require_device(data["device_id"]):
        return error("Device not found", 404)

    result = quarantine_app(
        data["device_id"],
        data["app_uid"],
        data.get("app_name", data["app_uid"]),
        data.get("reason", "Anomalous background data usage detected by AiTelDa Malware Auditor"),
    )
    return success(result, message="App quarantined — network permissions revoked", status=201)


@diag_bp.route("/malware/release", methods=["POST"])
@jwt_required
def release():
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["device_id", "app_uid"])
    if not ok:
        return error(msg, 422)
    if not _require_device(data["device_id"]):
        return error("Device not found", 404)

    result = release_quarantine(data["device_id"], data["app_uid"])
    return success(result, message="App released from quarantine")


@diag_bp.route("/malware/quarantined", methods=["GET"])
@jwt_required
def list_quarantined():
    device_id = request.args.get("device_id")
    if not device_id:
        return error("device_id query param required", 422)
    if not _require_device(device_id):
        return error("Device not found", 404)

    apps = get_quarantined_apps(device_id)
    return success({"quarantined_apps": apps, "count": len(apps)})


# ═══════════════════════════════════════════════════════════════════════
# B. DNS BLACKHOLE ENGINE
# ═══════════════════════════════════════════════════════════════════════

@diag_bp.route("/dns/stats", methods=["GET"])
@jwt_required
def dns_stats():
    device_id = request.args.get("device_id")
    if not device_id:
        return error("device_id query param required", 422)
    if not _require_device(device_id):
        return error("Device not found", 404)

    days = min(int(request.args.get("days", 30)), 90)
    return success(get_dns_stats(device_id, days=days))


@diag_bp.route("/dns/check", methods=["POST"])
@jwt_required
def dns_check():
    """Check whether a domain is blacklisted."""
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "").strip().lower()
    if not domain:
        return error("domain is required", 422)

    result = check_dns_domain(domain)

    # If the device wants to log the block event
    if result["blocked"] and data.get("device_id"):
        if _require_device(data["device_id"]):
            log_dns_block(
                data["device_id"],
                domain,
                result.get("category", "tracker"),
                int(data.get("bytes_saved", 0)),
            )

    return success(result)


@diag_bp.route("/dns/block", methods=["POST"])
@jwt_required
def dns_block_event():
    """Log a DNS block event that happened on-device."""
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["device_id", "domain"])
    if not ok:
        return error(msg, 422)
    if not _require_device(data["device_id"]):
        return error("Device not found", 404)

    log_dns_block(
        data["device_id"],
        data["domain"].lower().strip(),
        data.get("category", "tracker"),
        int(data.get("bytes_saved", 0)),
    )
    return success(message="DNS block event logged", status=201)


@diag_bp.route("/dns/blacklist", methods=["GET"])
@jwt_required
def dns_blacklist():
    category = request.args.get("category")
    limit = min(int(request.args.get("limit", 100)), 1000)
    offset = int(request.args.get("offset", 0))
    return success(get_blacklist(category=category, limit=limit, offset=offset))


@diag_bp.route("/dns/blacklist", methods=["POST"])
@jwt_required
def add_blacklist_domain():
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["domain", "category"])
    if not ok:
        return error(msg, 422)

    valid_cats = ("tracker", "analytics", "advertising", "malware", "phishing")
    if data["category"] not in valid_cats:
        return error(f"category must be one of: {', '.join(valid_cats)}", 422)

    result = add_to_blacklist(data["domain"], data["category"], source="user")
    return success(result, status=201)


# ═══════════════════════════════════════════════════════════════════════
# C. PHISHING & FRAUD INTERCEPTOR
# ═══════════════════════════════════════════════════════════════════════

@diag_bp.route("/phishing/check", methods=["POST"])
@jwt_required
def phishing_check():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return error("url is required", 422)

    result = check_url_safety(url)

    # Auto-log intercepts
    if not result["safe"] and result["action"] == "blocked" and data.get("device_id"):
        if _require_device(data["device_id"]):
            log_phishing_intercept(
                data["device_id"],
                url,
                result["threat_type"],
                result["source"],
                int(data.get("bytes_prevented", 0)),
            )

    return success(result)


@diag_bp.route("/phishing/report", methods=["POST"])
@jwt_required
def phishing_report():
    """Report a phishing intercept event that occurred on-device."""
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["device_id", "url", "threat_type"])
    if not ok:
        return error(msg, 422)
    if not _require_device(data["device_id"]):
        return error("Device not found", 404)

    log_phishing_intercept(
        data["device_id"],
        data["url"],
        data["threat_type"],
        data.get("source_list", "aitelda"),
        int(data.get("bytes_prevented", 0)),
    )

    # Also add the domain to user's local blocklist awareness
    return success(message="Phishing intercept logged", status=201)


@diag_bp.route("/phishing/events", methods=["GET"])
@jwt_required
def phishing_events():
    device_id = request.args.get("device_id")
    if not device_id:
        return error("device_id query param required", 422)
    if not _require_device(device_id):
        return error("Device not found", 404)

    days = min(int(request.args.get("days", 30)), 90)
    limit = min(int(request.args.get("limit", 50)), 200)
    return success(get_phishing_events(device_id, days=days, limit=limit))


# ═══════════════════════════════════════════════════════════════════════
# D. UPDATE GUARDIAN
# ═══════════════════════════════════════════════════════════════════════

@diag_bp.route("/updates/queue", methods=["GET"])
@jwt_required
def updates_queue_get():
    device_id = request.args.get("device_id")
    if not device_id:
        return error("device_id query param required", 422)
    if not _require_device(device_id):
        return error("Device not found", 404)
    return success(get_update_queue(device_id))


@diag_bp.route("/updates/queue", methods=["POST"])
@jwt_required
def updates_queue_add():
    """
    Device reports a pending update that's being held.
    { "device_id", "app_uid", "app_name", "update_type", "size_bytes", "policy" }
    """
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["device_id", "app_uid", "size_bytes"])
    if not ok:
        return error(msg, 422)
    if not _require_device(data["device_id"]):
        return error("Device not found", 404)

    update_type = data.get("update_type", "app")
    if update_type not in ("app", "os", "system"):
        update_type = "app"

    policy = data.get("policy", "wifi_only")
    valid_policies = ("wifi_only", "always_allow", "always_block", "manual")
    if policy not in valid_policies:
        policy = "wifi_only"

    result = queue_update(
        device_id=data["device_id"],
        app_uid=data["app_uid"],
        app_name=data.get("app_name", data["app_uid"]),
        update_type=update_type,
        size_bytes=int(data["size_bytes"]),
        policy=policy,
    )
    return success(result, message="Update intercepted and queued", status=201)


@diag_bp.route("/updates/approve", methods=["POST"])
@jwt_required
def updates_approve():
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["device_id", "app_uid"])
    if not ok:
        return error(msg, 422)
    if not _require_device(data["device_id"]):
        return error("Device not found", 404)

    result = approve_update(
        data["device_id"],
        data["app_uid"],
        release_now=data.get("release_now", False),
    )
    return success(result, message="Update approved — will release on next Wi-Fi connection")


@diag_bp.route("/updates/policy", methods=["POST"])
@jwt_required
def updates_set_policy():
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["device_id", "app_uid", "policy"])
    if not ok:
        return error(msg, 422)
    if not _require_device(data["device_id"]):
        return error("Device not found", 404)

    valid = ("wifi_only", "always_allow", "always_block", "manual")
    if data["policy"] not in valid:
        return error(f"policy must be one of: {', '.join(valid)}", 422)

    try:
        result = set_update_policy(data["device_id"], data["app_uid"], data["policy"])
        return success(result, message=f"Policy updated to '{data['policy']}'")
    except ValueError as e:
        return error(str(e), 422)


# ═══════════════════════════════════════════════════════════════════════
# E. VIDEO RESOLUTION GOVERNOR
# ═══════════════════════════════════════════════════════════════════════

@diag_bp.route("/video/settings", methods=["GET"])
@jwt_required
def video_settings_get():
    device_id = request.args.get("device_id")
    if not device_id:
        return error("device_id query param required", 422)
    if not _require_device(device_id):
        return error("Device not found", 404)

    settings = get_video_settings(device_id)
    return success({"device_id": device_id, "settings": settings, "app_count": len(settings)})


@diag_bp.route("/video/set-quality", methods=["POST"])
@jwt_required
def video_set_quality():
    """
    { "device_id": "...", "app_uid": "com.zhiliaoapp.musically", "max_quality": "480p" }
    """
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["device_id", "app_uid", "max_quality"])
    if not ok:
        return error(msg, 422)
    if not _require_device(data["device_id"]):
        return error("Device not found", 404)

    valid_qualities = ("240p", "480p", "720p", "1080p")
    if data["max_quality"] not in valid_qualities:
        return error(f"max_quality must be one of: {', '.join(valid_qualities)}", 422)

    try:
        result = set_video_quality(data["device_id"], data["app_uid"], data["max_quality"])
        return success(result, message=f"Video quality capped at {data['max_quality']}")
    except ValueError as e:
        return error(str(e), 422)


@diag_bp.route("/video/log-savings", methods=["POST"])
@jwt_required
def video_log_savings():
    """Device reports bytes saved after a governed video session."""
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["device_id", "app_uid", "bytes_saved"])
    if not ok:
        return error(msg, 422)
    if not _require_device(data["device_id"]):
        return error("Device not found", 404)

    from app.services.diagnostics import log_video_bytes_saved
    log_video_bytes_saved(data["device_id"], data["app_uid"], int(data["bytes_saved"]))
    return success(message="Video savings logged")


# ═══════════════════════════════════════════════════════════════════════
# F. ZERO-PERM AUDIT
# ═══════════════════════════════════════════════════════════════════════

@diag_bp.route("/zeroperm/audit", methods=["POST"])
@jwt_required
def zeroperm_audit():
    """
    Run a zero-perm audit for a list of apps.
    {
      "device_id": "...",
      "apps": [
        {
          "app_uid": "com.example.flashlight",
          "app_name": "Torch Flashlight Pro",
          "data_used_bytes": 356515840,
          "permissions": ["READ_CONTACTS", "ACCESS_FINE_LOCATION", "CAMERA", "READ_SMS"],
          "app_category": "flashlight"
        }
      ]
    }
    """
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["device_id", "apps"])
    if not ok:
        return error(msg, 422)
    if not _require_device(data["device_id"]):
        return error("Device not found", 404)

    if not isinstance(data["apps"], list) or len(data["apps"]) == 0:
        return error("apps must be a non-empty array", 422)

    result = run_zero_perm_audit(data["device_id"], data["apps"])
    return success(result, message=f"Audit complete — {result['apps_audited']} apps analysed", status=201)


@diag_bp.route("/zeroperm/check", methods=["POST"])
@jwt_required
def zeroperm_check():
    """
    Stateless single-app risk check (no persistence).
    """
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["app_uid", "data_used_bytes", "permissions"])
    if not ok:
        return error(msg, 422)

    result = calculate_risk_score(
        app_uid=data["app_uid"],
        app_name=data.get("app_name", data["app_uid"]),
        data_used_bytes=int(data["data_used_bytes"]),
        permissions=data.get("permissions", []),
        app_category=data.get("app_category", "unknown"),
    )
    return success(result)


@diag_bp.route("/zeroperm/history", methods=["GET"])
@jwt_required
def zeroperm_history():
    device_id = request.args.get("device_id")
    if not device_id:
        return error("device_id query param required", 422)
    if not _require_device(device_id):
        return error("Device not found", 404)

    limit = min(int(request.args.get("limit", 20)), 100)
    history = get_audit_history(device_id, limit=limit)
    return success({"history": history, "count": len(history)})
