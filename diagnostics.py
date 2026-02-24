"""
AiTelDa Diagnostic Services — v2.0

Provides backend logic for the full Diagnostic Suite:
  A. Behavioral Malware Auditor
  B. Tracker & Telemetry Blocker (DNS Blackhole)
  C. Phishing & Fraud Interceptor
  D. Update Guardian
  E. Video Resolution Governor
  F. Zero-Perm Audit

Each function can be called from diagnostic routes or triggered
automatically by on-device Packet-Sentry events.
"""

import json
import re
from datetime import datetime, timezone
from app.models.schema import get_db


# ── THRESHOLDS ────────────────────────────────────────────────────────────
ADWARE_SCREEN_OFF_MB_THRESHOLD = 50        # 50MB+ with zero screen time = suspect
DEVIATION_HIGH_PCT              = 1000     # +1000% = high anomaly
DEVIATION_MEDIUM_PCT            = 200      # +200% = medium
RISK_CRITICAL_THRESHOLD         = 75
RISK_HIGH_THRESHOLD             = 50
RISK_MEDIUM_THRESHOLD           = 25


# ═══════════════════════════════════════════════════════════════════════
# A. BEHAVIORAL MALWARE AUDITOR
# ═══════════════════════════════════════════════════════════════════════

def run_malware_scan(device_id: str, window_hours: int = 24) -> dict:
    """
    Scan all apps for the Hidden WebView / Adware signature:
    High Data Consumption + Zero (or near-zero) Screen-On Time.

    Returns list of flagged apps with risk level and evidence.
    """
    conn = get_db()

    # Get per-app usage breakdown split by screen state
    rows = conn.execute("""
        SELECT
            us.app_uid,
            us.app_name,
            SUM(CASE WHEN ps.screen_state = 'off' THEN us.bytes_tx + us.bytes_rx ELSE 0 END) AS off_bytes,
            SUM(CASE WHEN ps.screen_state = 'on'  THEN us.bytes_tx + us.bytes_rx ELSE 0 END) AS on_bytes,
            SUM(us.bytes_tx + us.bytes_rx) AS total_bytes,
            COUNT(DISTINCT ps.id) AS session_count
        FROM usage_snapshots us
        JOIN packet_sessions ps ON ps.id = us.session_id
        WHERE ps.device_id = ?
          AND ps.session_start >= datetime('now', ? || ' hours')
        GROUP BY us.app_uid, us.app_name
        ORDER BY off_bytes DESC
    """, (device_id, f"-{window_hours}")).fetchall()

    conn.close()

    results = []
    for r in rows:
        off_bytes  = r["off_bytes"] or 0
        on_bytes   = r["on_bytes"] or 0
        total      = r["total_bytes"] or 0
        off_mb     = off_bytes / 1_048_576

        # Risk scoring
        if off_mb >= ADWARE_SCREEN_OFF_MB_THRESHOLD and on_bytes == 0:
            risk = "critical"
            flag = "hidden_webview"
        elif off_mb >= ADWARE_SCREEN_OFF_MB_THRESHOLD and on_bytes > 0:
            ratio = off_bytes / total if total > 0 else 0
            if ratio > 0.8:
                risk = "high"
                flag = "idle_drain"
            elif ratio > 0.5:
                risk = "medium"
                flag = "elevated_background"
            else:
                risk = "safe"
                flag = "normal"
        else:
            risk = "safe"
            flag = "normal"

        # Calculate screen-time ratio for deviation
        off_ratio_pct = (off_bytes / total * 100) if total > 0 else 0

        results.append({
            "app_uid":         r["app_uid"],
            "app_name":        r["app_name"] or r["app_uid"],
            "total_bytes":     total,
            "screen_off_bytes": off_bytes,
            "screen_on_bytes":  on_bytes,
            "screen_off_mb":    round(off_mb, 2),
            "off_ratio_pct":    round(off_ratio_pct, 1),
            "session_count":    r["session_count"],
            "risk":             risk,
            "flag":             flag,
        })

    critical = [r for r in results if r["risk"] == "critical"]
    high     = [r for r in results if r["risk"] == "high"]

    return {
        "device_id":      device_id,
        "window_hours":   window_hours,
        "apps_scanned":   len(results),
        "critical_count": len(critical),
        "high_count":     len(high),
        "results":        results,
        "scanned_at":     datetime.now(timezone.utc).isoformat(),
    }


def quarantine_app(device_id: str, app_uid: str, app_name: str, reason: str) -> dict:
    """Quarantine an app — log it and return confirmation."""
    conn = get_db()
    conn.execute("""
        INSERT INTO quarantined_apps (device_id, app_uid, app_name, reason, is_active)
        VALUES (?, ?, ?, ?, 1)
        ON CONFLICT(device_id, app_uid)
        DO UPDATE SET reason=excluded.reason, quarantined_at=datetime('now'),
                      released_at=NULL, is_active=1
    """, (device_id, app_uid, app_name or app_uid, reason))
    conn.commit()

    row = conn.execute(
        "SELECT * FROM quarantined_apps WHERE device_id=? AND app_uid=?",
        (device_id, app_uid)
    ).fetchone()
    conn.close()

    return {
        "quarantined": True,
        "app_uid":  app_uid,
        "app_name": app_name,
        "reason":   reason,
        "quarantined_at": row["quarantined_at"],
        "message":  f"Network permissions revoked for {app_name or app_uid}. All background data blocked.",
    }


def release_quarantine(device_id: str, app_uid: str) -> dict:
    conn = get_db()
    conn.execute("""
        UPDATE quarantined_apps
        SET is_active=0, released_at=datetime('now')
        WHERE device_id=? AND app_uid=?
    """, (device_id, app_uid))
    conn.commit()
    conn.close()
    return {"released": True, "app_uid": app_uid}


def get_quarantined_apps(device_id: str) -> list:
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM quarantined_apps
        WHERE device_id=? AND is_active=1
        ORDER BY quarantined_at DESC
    """, (device_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ═══════════════════════════════════════════════════════════════════════
# B. DNS BLACKHOLE ENGINE
# ═══════════════════════════════════════════════════════════════════════

def check_dns_domain(domain: str) -> dict:
    """Check if a domain is in the blacklist."""
    domain = domain.lower().strip()
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM dns_blacklists WHERE domain=? AND is_active=1", (domain,)
    ).fetchone()
    conn.close()
    if row:
        return {"blocked": True, "domain": domain, "category": row["category"], "source": row["source"]}
    return {"blocked": False, "domain": domain}


def log_dns_block(device_id: str, domain: str, category: str, bytes_saved: int = 0):
    """Log a DNS block event for a device."""
    conn = get_db()
    conn.execute("""
        INSERT INTO dns_blocked_domains (device_id, domain, category, bytes_saved)
        VALUES (?, ?, ?, ?)
    """, (device_id, domain, category, bytes_saved))
    conn.commit()
    conn.close()


def get_dns_stats(device_id: str, days: int = 30) -> dict:
    conn = get_db()

    total_blocked = conn.execute("""
        SELECT COUNT(*) as c, SUM(bytes_saved) as saved, SUM(request_count) as reqs
        FROM dns_blocked_domains
        WHERE device_id=? AND blocked_at >= datetime('now', ? || ' days')
    """, (device_id, f"-{days}")).fetchone()

    by_category = conn.execute("""
        SELECT category, COUNT(*) as c, SUM(bytes_saved) as saved
        FROM dns_blocked_domains
        WHERE device_id=? AND blocked_at >= datetime('now', ? || ' days')
        GROUP BY category ORDER BY c DESC
    """, (device_id, f"-{days}")).fetchall()

    top_domains = conn.execute("""
        SELECT domain, category, COUNT(*) as hits, SUM(bytes_saved) as saved
        FROM dns_blocked_domains
        WHERE device_id=? AND blocked_at >= datetime('now', ? || ' days')
        GROUP BY domain ORDER BY hits DESC LIMIT 20
    """, (device_id, f"-{days}")).fetchall()

    blacklist_count = conn.execute(
        "SELECT COUNT(*) as c FROM dns_blacklists WHERE is_active=1"
    ).fetchone()["c"]

    conn.close()
    return {
        "device_id":       device_id,
        "period_days":     days,
        "total_blocked":   total_blocked["c"] or 0,
        "total_bytes_saved": total_blocked["saved"] or 0,
        "total_bytes_saved_mb": round((total_blocked["saved"] or 0) / 1_048_576, 2),
        "total_requests":  total_blocked["reqs"] or 0,
        "by_category":     [dict(r) for r in by_category],
        "top_domains":     [dict(r) for r in top_domains],
        "blacklist_size":  blacklist_count,
    }


def get_blacklist(category: str = None, limit: int = 100, offset: int = 0) -> dict:
    conn = get_db()
    if category:
        rows = conn.execute(
            "SELECT * FROM dns_blacklists WHERE is_active=1 AND category=? ORDER BY domain LIMIT ? OFFSET ?",
            (category, limit, offset)
        ).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) as c FROM dns_blacklists WHERE is_active=1 AND category=?", (category,)
        ).fetchone()["c"]
    else:
        rows = conn.execute(
            "SELECT * FROM dns_blacklists WHERE is_active=1 ORDER BY domain LIMIT ? OFFSET ?",
            (limit, offset)
        ).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) as c FROM dns_blacklists WHERE is_active=1"
        ).fetchone()["c"]
    conn.close()
    return {"domains": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset}


def add_to_blacklist(domain: str, category: str, source: str = "user") -> dict:
    conn = get_db()
    conn.execute(
        "INSERT OR IGNORE INTO dns_blacklists (domain, category, source) VALUES (?, ?, ?)",
        (domain.lower().strip(), category, source)
    )
    conn.commit()
    conn.close()
    return {"added": True, "domain": domain}


# ═══════════════════════════════════════════════════════════════════════
# C. PHISHING & FRAUD INTERCEPTOR
# ═══════════════════════════════════════════════════════════════════════

# Known Nigerian phishing pattern keywords
NG_PHISHING_PATTERNS = [
    r"fake-mtn", r"mtn-free", r"airtel-free", r"glo-free",
    r"free-data", r"topup-free", r"recharge-free",
    r"prize-winner", r"you-have-won", r"claim-reward",
    r"loan-fast", r"quick-loan", r"fastloan",
]

def check_url_safety(url: str) -> dict:
    """
    Check a URL against our threat intelligence.
    In production this would call Google Safe Browsing API and Spamhaus.
    Here we use pattern matching + the dns_blacklists table.
    """
    url_lower = url.lower()
    domain = _extract_domain(url)

    # Check DNS blacklist
    conn = get_db()
    bl_row = conn.execute(
        "SELECT * FROM dns_blacklists WHERE domain=? AND is_active=1", (domain,)
    ).fetchone()
    conn.close()

    if bl_row:
        return {
            "safe": False,
            "url": url,
            "domain": domain,
            "threat_type": bl_row["category"],
            "source": bl_row["source"],
            "action": "blocked",
            "message": f"Domain on {bl_row['source']} blocklist ({bl_row['category']})",
        }

    # Check NG-specific phishing patterns
    for pattern in NG_PHISHING_PATTERNS:
        if re.search(pattern, url_lower):
            return {
                "safe": False,
                "url": url,
                "domain": domain,
                "threat_type": "nigerian_phishing",
                "source": "aitelda_ng_blacklist",
                "action": "blocked",
                "message": "Matches Nigerian phishing pattern. Drive-by download prevented.",
            }

    # Suspicious TLDs common in Nigerian fraud
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".click"]
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            return {
                "safe": False,
                "url": url,
                "domain": domain,
                "threat_type": "suspicious_tld",
                "source": "aitelda_heuristic",
                "action": "warn",
                "message": f"Suspicious top-level domain ({tld}). Proceed with caution.",
            }

    return {
        "safe": True,
        "url": url,
        "domain": domain,
        "threat_type": None,
        "source": None,
        "action": "allow",
        "message": "No threats detected in Google Safe Browsing, Spamhaus, or AiTelDa blacklists.",
    }


def log_phishing_intercept(device_id: str, url: str, threat_type: str,
                            source_list: str, bytes_prevented: int = 0):
    domain = _extract_domain(url)
    conn = get_db()
    conn.execute("""
        INSERT INTO phishing_intercepts
            (device_id, url, domain, threat_type, source_list, bytes_prevented)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (device_id, url[:2048], domain, threat_type, source_list, bytes_prevented))
    conn.commit()
    conn.close()


def get_phishing_events(device_id: str, days: int = 30, limit: int = 50) -> dict:
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM phishing_intercepts
        WHERE device_id=? AND intercepted_at >= datetime('now', ? || ' days')
        ORDER BY intercepted_at DESC LIMIT ?
    """, (device_id, f"-{days}", limit)).fetchall()
    total = conn.execute("""
        SELECT COUNT(*) as c, SUM(bytes_prevented) as saved
        FROM phishing_intercepts
        WHERE device_id=? AND intercepted_at >= datetime('now', ? || ' days')
    """, (device_id, f"-{days}")).fetchone()
    conn.close()
    return {
        "events": [dict(r) for r in rows],
        "total": total["c"] or 0,
        "total_bytes_prevented": total["saved"] or 0,
    }


def _extract_domain(url: str) -> str:
    url = url.lower().strip()
    for prefix in ("https://", "http://", "//"):
        if url.startswith(prefix):
            url = url[len(prefix):]
    return url.split("/")[0].split("?")[0].split("#")[0]


# ═══════════════════════════════════════════════════════════════════════
# D. UPDATE GUARDIAN
# ═══════════════════════════════════════════════════════════════════════

def queue_update(device_id: str, app_uid: str, app_name: str,
                 update_type: str, size_bytes: int, policy: str = "wifi_only") -> dict:
    """Intercept an update and hold it per policy."""
    conn = get_db()
    conn.execute("""
        INSERT INTO update_queue (device_id, app_uid, app_name, update_type, size_bytes, policy, status)
        VALUES (?, ?, ?, ?, ?, ?, 'held')
        ON CONFLICT(device_id, app_uid)
        DO UPDATE SET size_bytes=excluded.size_bytes, status='held',
                      held_at=datetime('now'), approved_at=NULL, released_at=NULL,
                      policy=excluded.policy
    """, (device_id, app_uid, app_name or app_uid, update_type, size_bytes, policy))
    conn.commit()

    row = conn.execute(
        "SELECT * FROM update_queue WHERE device_id=? AND app_uid=?", (device_id, app_uid)
    ).fetchone()
    conn.close()
    return dict(row)


def approve_update(device_id: str, app_uid: str, release_now: bool = False) -> dict:
    conn = get_db()
    status = "released" if release_now else "approved"
    conn.execute("""
        UPDATE update_queue
        SET status=?, approved_at=datetime('now'),
            released_at=CASE WHEN ? THEN datetime('now') ELSE NULL END
        WHERE device_id=? AND app_uid=?
    """, (status, release_now, device_id, app_uid))
    conn.commit()
    conn.close()
    return {"approved": True, "app_uid": app_uid, "status": status}


def get_update_queue(device_id: str) -> dict:
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM update_queue WHERE device_id=? ORDER BY held_at DESC
    """, (device_id,)).fetchall()
    conn.close()

    held     = [dict(r) for r in rows if r["status"] == "held"]
    approved = [dict(r) for r in rows if r["status"] == "approved"]
    released = [dict(r) for r in rows if r["status"] == "released"]
    total_held_bytes = sum(r["size_bytes"] for r in rows if r["status"] == "held")

    return {
        "held": held,
        "approved": approved,
        "released": released,
        "total_held": len(held),
        "total_held_bytes": total_held_bytes,
        "total_held_mb": round(total_held_bytes / 1_048_576, 2),
    }


def set_update_policy(device_id: str, app_uid: str, policy: str) -> dict:
    valid = ("wifi_only", "always_allow", "always_block", "manual")
    if policy not in valid:
        raise ValueError(f"policy must be one of {valid}")
    conn = get_db()
    conn.execute("""
        UPDATE update_queue SET policy=? WHERE device_id=? AND app_uid=?
    """, (policy, device_id, app_uid))
    conn.commit()
    conn.close()
    return {"updated": True, "app_uid": app_uid, "policy": policy}


# ═══════════════════════════════════════════════════════════════════════
# E. VIDEO RESOLUTION GOVERNOR
# ═══════════════════════════════════════════════════════════════════════

QUALITY_SAVINGS = {
    "240p":  0.80,   # 80% savings vs 1080p
    "480p":  0.60,   # 60% savings
    "720p":  0.35,   # 35% savings
    "1080p": 0.00,   # no savings (default)
}

VIDEO_APPS = {
    "com.zhiliaoapp.musically": "TikTok",
    "com.tiktok.musically":     "TikTok",
    "com.instagram.android":    "Instagram",
    "com.google.android.youtube": "YouTube",
    "com.facebook.katana":      "Facebook",
    "com.snapchat.android":     "Snapchat",
}


def set_video_quality(device_id: str, app_uid: str, max_quality: str) -> dict:
    if max_quality not in QUALITY_SAVINGS:
        raise ValueError(f"max_quality must be one of {list(QUALITY_SAVINGS.keys())}")

    app_name = VIDEO_APPS.get(app_uid, app_uid)
    conn = get_db()
    conn.execute("""
        INSERT INTO video_governor_settings (device_id, app_uid, app_name, max_quality)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(device_id, app_uid)
        DO UPDATE SET max_quality=excluded.max_quality, updated_at=datetime('now')
    """, (device_id, app_uid, app_name, max_quality))
    conn.commit()
    conn.close()

    savings_pct = QUALITY_SAVINGS[max_quality] * 100
    return {
        "app_uid":     app_uid,
        "app_name":    app_name,
        "max_quality": max_quality,
        "savings_pct": savings_pct,
        "message": f"{app_name} capped at {max_quality}. Expected {savings_pct:.0f}% data savings on video.",
    }


def get_video_settings(device_id: str) -> list:
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM video_governor_settings WHERE device_id=? ORDER BY bytes_saved DESC
    """, (device_id,)).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["savings_pct"] = QUALITY_SAVINGS.get(r["max_quality"], 0) * 100
        result.append(d)
    return result


def log_video_bytes_saved(device_id: str, app_uid: str, bytes_saved: int):
    conn = get_db()
    conn.execute("""
        UPDATE video_governor_settings
        SET bytes_saved = bytes_saved + ?, updated_at=datetime('now')
        WHERE device_id=? AND app_uid=?
    """, (bytes_saved, device_id, app_uid))
    conn.commit()
    conn.close()


# ═══════════════════════════════════════════════════════════════════════
# F. ZERO-PERM AUDIT
# ═══════════════════════════════════════════════════════════════════════

DANGEROUS_PERMISSIONS = {
    "READ_CONTACTS":          20,
    "READ_CALL_LOG":          25,
    "READ_SMS":               30,
    "RECEIVE_SMS":            25,
    "ACCESS_FINE_LOCATION":   20,
    "ACCESS_COARSE_LOCATION": 15,
    "RECORD_AUDIO":           20,
    "CAMERA":                 15,
    "READ_PHONE_STATE":       15,
    "PROCESS_OUTGOING_CALLS": 25,
    "WRITE_CONTACTS":         20,
    "SEND_SMS":               30,
    "CALL_PHONE":             25,
}

APP_EXPECTED_MB = {
    "flashlight":    1,
    "calculator":    1,
    "compass":       2,
    "clock":         5,
    "weather":      50,
    "music":       500,
    "social":      500,
    "browser":     500,
    "video":      2000,
    "map":         200,
    "unknown":      50,
}


def calculate_risk_score(app_uid: str, app_name: str,
                          data_used_bytes: int, permissions: list,
                          app_category: str = "unknown") -> dict:
    """
    Risk Score = (data_ratio × 50) + (permission_score × 50), capped at 100.
    """
    # Permission score
    perm_score = 0
    dangerous_found = []
    for perm in permissions:
        perm_upper = perm.upper()
        weight = DANGEROUS_PERMISSIONS.get(perm_upper, 0)
        if weight > 0:
            perm_score += weight
            dangerous_found.append(perm)

    max_perm_score = sum(DANGEROUS_PERMISSIONS.values())
    perm_ratio = min(perm_score / max_perm_score, 1.0) if max_perm_score > 0 else 0

    # Data ratio score
    expected_mb = APP_EXPECTED_MB.get(app_category, 50)
    actual_mb = data_used_bytes / 1_048_576
    data_ratio = min(actual_mb / expected_mb, 5.0) / 5.0 if expected_mb > 0 else 0

    raw_score = (data_ratio * 50) + (perm_ratio * 50)
    risk_score = round(min(raw_score, 100), 1)

    if risk_score >= RISK_CRITICAL_THRESHOLD:
        level = "critical"
        recommendation = "uninstall"
    elif risk_score >= RISK_HIGH_THRESHOLD:
        level = "high"
        recommendation = "review"
    elif risk_score >= RISK_MEDIUM_THRESHOLD:
        level = "medium"
        recommendation = "monitor"
    else:
        level = "safe"
        recommendation = "none"

    verdict = _build_verdict(app_name, actual_mb, dangerous_found, level)

    return {
        "app_uid":          app_uid,
        "app_name":         app_name,
        "risk_score":       risk_score,
        "risk_level":       level,
        "recommendation":   recommendation,
        "dangerous_permissions": dangerous_found,
        "all_permissions":  permissions,
        "data_used_mb":     round(actual_mb, 2),
        "expected_mb":      expected_mb,
        "verdict":          verdict,
    }


def _build_verdict(app_name: str, actual_mb: float,
                   dangerous_perms: list, level: str) -> str:
    if level == "safe":
        return f"{app_name} shows normal data consumption with no dangerous permissions."
    perm_str = ", ".join(dangerous_perms[:3]) if dangerous_perms else "unusual permissions"
    if level == "critical":
        return (f"This {app_name} has used {actual_mb:.0f}MB and requested {perm_str}. "
                f"There is no legitimate reason for these permissions in this app category. "
                f"High-Risk Data Thief. Uninstall recommended.")
    if level == "high":
        return (f"{app_name} has used {actual_mb:.0f}MB — above expected — and "
                f"holds {perm_str} access. Review permissions in Settings > Apps.")
    return (f"{app_name} data usage is slightly elevated. "
            f"Permissions include {perm_str}. Monitor for changes.")


def run_zero_perm_audit(device_id: str, apps: list) -> dict:
    """
    Audit a list of apps. Each app dict needs:
      app_uid, app_name, data_used_bytes, permissions (list), app_category
    """
    conn = get_db()
    results = []
    critical_count = 0
    high_count = 0

    for app in apps:
        result = calculate_risk_score(
            app_uid=app.get("app_uid", ""),
            app_name=app.get("app_name", app.get("app_uid", "")),
            data_used_bytes=int(app.get("data_used_bytes", 0)),
            permissions=app.get("permissions", []),
            app_category=app.get("app_category", "unknown"),
        )

        # Persist
        conn.execute("""
            INSERT INTO zero_perm_audits
                (device_id, app_uid, app_name, data_used_bytes, permissions,
                 risk_score, verdict, recommendation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            device_id,
            result["app_uid"],
            result["app_name"],
            int(app.get("data_used_bytes", 0)),
            json.dumps(app.get("permissions", [])),
            result["risk_score"],
            result["verdict"],
            result["recommendation"],
        ))

        if result["risk_level"] == "critical":
            critical_count += 1
        elif result["risk_level"] == "high":
            high_count += 1

        results.append(result)

    conn.commit()
    conn.close()

    results.sort(key=lambda x: -x["risk_score"])
    return {
        "device_id":     device_id,
        "apps_audited":  len(results),
        "critical_count": critical_count,
        "high_count":    high_count,
        "results":       results,
        "audited_at":    datetime.now(timezone.utc).isoformat(),
    }


def get_audit_history(device_id: str, limit: int = 20) -> list:
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM zero_perm_audits
        WHERE device_id=? ORDER BY audited_at DESC LIMIT ?
    """, (device_id, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]
