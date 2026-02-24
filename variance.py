"""
AiTelDa Variance Calculation Service

Core engine for:
  V = |D_device - D_telco|

Also handles:
  - Rolling 7-day baseline updates per app
  - Idle-state anomaly threshold checks (>25% deviation)
  - Variance threshold evaluation (>5% = suspected over-billing)
"""

import os
from datetime import datetime, timezone, timedelta
from app.models.schema import get_db

VARIANCE_THRESHOLD = float(os.environ.get("VARIANCE_THRESHOLD", 0.05))   # 5%
ANOMALY_THRESHOLD  = float(os.environ.get("ANOMALY_THRESHOLD",  0.25))   # 25%
BASELINE_DAYS      = int(os.environ.get("BASELINE_DAYS",        7))


# ---------------------------------------------------------------------------
# Baseline maintenance
# ---------------------------------------------------------------------------

def update_baseline(conn, device_id: str, app_uid: str, bytes_used: int):
    """
    Incrementally update the rolling average daily bytes for an app.
    Uses exponential moving average with BASELINE_DAYS as the window.
    """
    alpha = 2 / (BASELINE_DAYS + 1)  # EMA smoothing factor

    existing = conn.execute(
        "SELECT * FROM app_baselines WHERE device_id = ? AND app_uid = ?",
        (device_id, app_uid),
    ).fetchone()

    if not existing:
        conn.execute(
            """INSERT INTO app_baselines (device_id, app_uid, avg_daily_bytes, sample_days)
               VALUES (?, ?, ?, 1)""",
            (device_id, app_uid, bytes_used),
        )
    else:
        new_avg = int(alpha * bytes_used + (1 - alpha) * existing["avg_daily_bytes"])
        new_samples = min(existing["sample_days"] + 1, BASELINE_DAYS * 10)
        conn.execute(
            """UPDATE app_baselines
               SET avg_daily_bytes = ?, sample_days = ?, last_updated = datetime('now')
               WHERE device_id = ? AND app_uid = ?""",
            (new_avg, new_samples, device_id, app_uid),
        )


def get_baselines(device_id: str) -> dict:
    """Return {app_uid: avg_daily_bytes} for all apps on this device."""
    conn = get_db()
    rows = conn.execute(
        "SELECT app_uid, avg_daily_bytes, sample_days FROM app_baselines WHERE device_id = ?",
        (device_id,),
    ).fetchall()
    conn.close()
    return {r["app_uid"]: {"avg_daily_bytes": r["avg_daily_bytes"], "sample_days": r["sample_days"]} for r in rows}


# ---------------------------------------------------------------------------
# Core variance calculation
# ---------------------------------------------------------------------------

def calculate_variance(device_id: str, period_start: str, period_end: str) -> dict:
    """
    Calculate billing variance for a device over a given period.

    Returns a dict with:
      - device_bytes       : total bytes recorded on-device
      - telco_bytes        : total bytes reported by telco
      - variance_bytes     : absolute difference
      - variance_pct       : percentage difference relative to telco report
      - is_over_billing    : True if variance_pct > VARIANCE_THRESHOLD
      - app_breakdown      : per-app contribution to device bytes
      - anomaly_events     : anomaly events in the period
      - telco_report_id    : the matched telco report id
    """
    conn = get_db()

    # --- Device-side total (D_device) ---
    sessions = conn.execute(
        """SELECT id, total_bytes_tx, total_bytes_rx
           FROM packet_sessions
           WHERE device_id = ?
             AND session_start >= ?
             AND (session_end <= ? OR session_end IS NULL)""",
        (device_id, period_start, period_end),
    ).fetchall()

    session_ids = [s["id"] for s in sessions]
    device_bytes = sum(s["total_bytes_tx"] + s["total_bytes_rx"] for s in sessions)

    # Per-app breakdown
    app_breakdown = []
    if session_ids:
        placeholders = ",".join("?" * len(session_ids))
        app_rows = conn.execute(
            f"""SELECT app_uid, app_name,
                       SUM(bytes_tx + bytes_rx) as total_bytes,
                       SUM(bytes_tx) as tx, SUM(bytes_rx) as rx
                FROM usage_snapshots
                WHERE session_id IN ({placeholders})
                GROUP BY app_uid, app_name
                ORDER BY total_bytes DESC""",
            session_ids,
        ).fetchall()
        app_breakdown = [dict(r) for r in app_rows]

    # --- Telco-side total (D_telco) ---
    # Find the most recent telco report that covers this period
    telco_report = conn.execute(
        """SELECT * FROM telco_reports
           WHERE device_id = ?
             AND (
               (billing_period_start >= ? AND billing_period_end <= ?)
               OR report_date BETWEEN ? AND ?
             )
           ORDER BY created_at DESC LIMIT 1""",
        (device_id, period_start, period_end, period_start, period_end),
    ).fetchone()

    telco_bytes = telco_report["bytes_reported"] if telco_report else 0
    telco_report_id = telco_report["id"] if telco_report else None

    # --- V = |D_device - D_telco| ---
    variance_bytes = abs(device_bytes - telco_bytes)
    variance_pct = (variance_bytes / telco_bytes) if telco_bytes > 0 else 0.0
    is_over_billing = variance_pct > VARIANCE_THRESHOLD and device_bytes < telco_bytes

    # --- Anomaly events in period ---
    anomaly_events = conn.execute(
        """SELECT app_uid, detected_at, baseline_bytes, actual_bytes,
                  deviation_pct, severity, screen_state
           FROM anomaly_events
           WHERE device_id = ?
             AND detected_at BETWEEN ? AND ?
           ORDER BY deviation_pct DESC""",
        (device_id, period_start, period_end),
    ).fetchall()

    conn.close()

    return {
        "device_bytes": device_bytes,
        "telco_bytes": telco_bytes,
        "variance_bytes": variance_bytes,
        "variance_pct": round(variance_pct * 100, 4),   # as percentage
        "variance_threshold_pct": VARIANCE_THRESHOLD * 100,
        "is_suspected_overbilling": is_over_billing,
        "telco_report_id": telco_report_id,
        "sessions_analysed": len(sessions),
        "period_start": period_start,
        "period_end": period_end,
        "app_breakdown": app_breakdown,
        "anomaly_events": [dict(e) for e in anomaly_events],
    }


def check_anomaly_threshold(baseline_bytes: int, actual_bytes: int) -> dict:
    """
    Stateless helper: given a baseline and actual reading,
    return whether an anomaly threshold is exceeded.
    """
    if baseline_bytes == 0:
        return {"is_anomaly": False, "deviation_pct": 0.0, "severity": "none"}

    deviation = (actual_bytes - baseline_bytes) / baseline_bytes
    is_anomaly = deviation > ANOMALY_THRESHOLD

    if deviation < 0.5:
        severity = "low"
    elif deviation < 2.0:
        severity = "medium"
    else:
        severity = "high"

    return {
        "is_anomaly": is_anomaly,
        "deviation_pct": round(deviation * 100, 2),
        "severity": severity if is_anomaly else "none",
        "threshold_pct": ANOMALY_THRESHOLD * 100,
    }
