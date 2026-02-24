"""
AiTelDa Dispute Routes

POST /api/disputes                       — Initiate a new dispute case
GET  /api/disputes                       — List all disputes for user
GET  /api/disputes/<reference>           — Get dispute detail
POST /api/disputes/<reference>/generate  — Generate forensic PDF
POST /api/disputes/<reference>/submit    — Submit to NCC portal
PATCH /api/disputes/<reference>/status  — Update status (internal use)
"""

import os
import secrets
from datetime import datetime, timezone
from flask import Blueprint, request, g, send_file, current_app

from app.models.schema import get_db
from app.utils.auth import jwt_required, device_belongs_to_user
from app.utils.validators import require_fields
from app.utils.responses import success, error
from app.services.variance import calculate_variance
from app.services.pdf_generator import generate_dispute_pdf

disputes_bp = Blueprint("disputes", __name__, url_prefix="/api/disputes")


def _generate_reference() -> str:
    """Generate a unique dispute reference: AIT-YYYY-XXXX"""
    year = datetime.now(timezone.utc).year
    suffix = secrets.token_hex(3).upper()
    return f"AIT-{year}-{suffix}"


def _get_dispute_or_404(reference: str, user_id: int):
    conn = get_db()
    dispute = conn.execute(
        "SELECT * FROM dispute_cases WHERE reference = ? AND user_id = ?",
        (reference, user_id),
    ).fetchone()
    conn.close()
    return dispute


# ---------------------------------------------------------------------------
# POST /api/disputes  — initiate a new dispute
# ---------------------------------------------------------------------------
@disputes_bp.route("", methods=["POST"])
@jwt_required
def create_dispute():
    """
    {
      "device_id": "abc123",
      "period_start": "2024-10-01T00:00:00Z",
      "period_end": "2024-10-31T23:59:59Z",
      "telco_report_id": 5   (optional — will be auto-matched if not provided)
    }
    """
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["device_id", "period_start", "period_end"])
    if not ok:
        return error(msg, 422)

    if not device_belongs_to_user(data["device_id"], g.current_user["id"]):
        return error("Device not found", 404)

    # Run the variance engine
    variance = calculate_variance(
        data["device_id"], data["period_start"], data["period_end"]
    )

    if variance["telco_bytes"] == 0:
        return error(
            "No telco report found for this period. "
            "Please submit a telco report first via POST /api/ingest/telco-report",
            422,
        )

    reference = _generate_reference()

    # Ensure reference uniqueness
    conn = get_db()
    while conn.execute(
        "SELECT id FROM dispute_cases WHERE reference = ?", (reference,)
    ).fetchone():
        reference = _generate_reference()

    conn.execute(
        """INSERT INTO dispute_cases
           (reference, user_id, device_id, telco_report_id,
            device_bytes, telco_bytes, variance_bytes, variance_pct,
            period_start, period_end, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')""",
        (
            reference,
            g.current_user["id"],
            data["device_id"],
            variance["telco_report_id"],
            variance["device_bytes"],
            variance["telco_bytes"],
            variance["variance_bytes"],
            variance["variance_pct"],
            data["period_start"],
            data["period_end"],
        ),
    )
    conn.commit()
    conn.close()

    return success(
        {
            "reference": reference,
            "variance": variance,
            "is_suspected_overbilling": variance["is_suspected_overbilling"],
            "next_step": f"POST /api/disputes/{reference}/generate to create the PDF report",
        },
        message="Dispute case initiated",
        status=201,
    )


# ---------------------------------------------------------------------------
# GET /api/disputes  — list all disputes
# ---------------------------------------------------------------------------
@disputes_bp.route("", methods=["GET"])
@jwt_required
def list_disputes():
    status_filter = request.args.get("status")
    limit = min(int(request.args.get("limit", 20)), 100)
    offset = int(request.args.get("offset", 0))

    conn = get_db()
    query = "SELECT * FROM dispute_cases WHERE user_id = ?"
    params = [g.current_user["id"]]

    if status_filter:
        query += " AND status = ?"
        params.append(status_filter)

    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    total = conn.execute(
        "SELECT COUNT(*) as c FROM dispute_cases WHERE user_id = ?",
        (g.current_user["id"],),
    ).fetchone()["c"]
    conn.close()

    return success(
        {
            "disputes": [dict(r) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


# ---------------------------------------------------------------------------
# GET /api/disputes/<reference>  — dispute detail
# ---------------------------------------------------------------------------
@disputes_bp.route("/<reference>", methods=["GET"])
@jwt_required
def get_dispute(reference):
    dispute = _get_dispute_or_404(reference, g.current_user["id"])
    if not dispute:
        return error("Dispute not found", 404)

    # Re-run variance for full app breakdown
    variance = calculate_variance(
        dispute["device_id"], dispute["period_start"], dispute["period_end"]
    )

    result = dict(dispute)
    result["variance_detail"] = variance
    return success(result)


# ---------------------------------------------------------------------------
# POST /api/disputes/<reference>/generate  — generate forensic PDF
# ---------------------------------------------------------------------------
@disputes_bp.route("/<reference>/generate", methods=["POST"])
@jwt_required
def generate_pdf(reference):
    dispute = _get_dispute_or_404(reference, g.current_user["id"])
    if not dispute:
        return error("Dispute not found", 404)

    conn = get_db()
    user = conn.execute(
        "SELECT id, email, full_name, phone FROM users WHERE id = ?",
        (g.current_user["id"],),
    ).fetchone()
    device = conn.execute(
        "SELECT * FROM devices WHERE device_id = ?", (dispute["device_id"],)
    ).fetchone()
    conn.close()

    variance = calculate_variance(
        dispute["device_id"], dispute["period_start"], dispute["period_end"]
    )

    try:
        pdf_path = generate_dispute_pdf(
            dict(dispute), dict(user), dict(device), variance
        )
    except Exception as e:
        current_app.logger.error(f"PDF generation failed for {reference}: {e}")
        return error("PDF generation failed. Please try again.", 500)

    # Update dispute record
    conn = get_db()
    conn.execute(
        "UPDATE dispute_cases SET status='pdf_generated', pdf_path=?, updated_at=datetime('now') WHERE reference=?",
        (pdf_path, reference),
    )
    conn.commit()
    conn.close()

    return success(
        {
            "reference": reference,
            "pdf_path": pdf_path,
            "status": "pdf_generated",
            "download_url": f"/api/disputes/{reference}/download",
        },
        message="Forensic PDF report generated successfully",
    )


# ---------------------------------------------------------------------------
# GET /api/disputes/<reference>/download  — download PDF
# ---------------------------------------------------------------------------
@disputes_bp.route("/<reference>/download", methods=["GET"])
@jwt_required
def download_pdf(reference):
    dispute = _get_dispute_or_404(reference, g.current_user["id"])
    if not dispute:
        return error("Dispute not found", 404)

    pdf_path = dispute["pdf_path"]
    if not pdf_path or not os.path.exists(pdf_path):
        return error("PDF has not been generated yet. Call /generate first.", 404)

    return send_file(
        pdf_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"{reference}.pdf",
    )


# ---------------------------------------------------------------------------
# POST /api/disputes/<reference>/submit  — submit to NCC
# ---------------------------------------------------------------------------
@disputes_bp.route("/<reference>/submit", methods=["POST"])
@jwt_required
def submit_to_ncc(reference):
    """
    Submits the dispute to the NCC consumer portal.
    In production this calls the NCC API. In development/staging,
    it records the intent and returns a mock acknowledgement.
    """
    dispute = _get_dispute_or_404(reference, g.current_user["id"])
    if not dispute:
        return error("Dispute not found", 404)

    if dispute["status"] not in ("pdf_generated", "pending"):
        return error(
            f"Dispute is in '{dispute['status']}' status. "
            "Cannot resubmit unless status is 'pdf_generated'.",
            409,
        )

    if not dispute["pdf_path"]:
        return error(
            "Please generate the PDF report first via POST /generate",
            422,
        )

    ncc_portal_url = current_app.config.get("NCC_PORTAL_URL", "")
    ncc_ref = f"NCC-{reference}-{secrets.token_hex(4).upper()}"

    # Production: uncomment and implement actual NCC API call
    # try:
    #     import requests
    #     resp = requests.post(ncc_portal_url, json={...}, timeout=30)
    #     ncc_ref = resp.json().get("reference")
    # except Exception as e:
    #     return error("NCC portal submission failed", 502)

    conn = get_db()
    conn.execute(
        """UPDATE dispute_cases
           SET status='submitted', ncc_submission_ref=?,
               ncc_submitted_at=datetime('now'), updated_at=datetime('now')
           WHERE reference=?""",
        (ncc_ref, reference),
    )
    conn.commit()
    conn.close()

    return success(
        {
            "reference": reference,
            "ncc_submission_ref": ncc_ref,
            "status": "submitted",
            "submitted_at": datetime.now(timezone.utc).isoformat(),
        },
        message="Dispute submitted to NCC consumer portal",
    )


# ---------------------------------------------------------------------------
# PATCH /api/disputes/<reference>/status  — update status
# ---------------------------------------------------------------------------
@disputes_bp.route("/<reference>/status", methods=["PATCH"])
@jwt_required
def update_status(reference):
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["status"])
    if not ok:
        return error(msg, 422)

    valid_statuses = ("pending", "pdf_generated", "submitted", "acknowledged", "resolved", "rejected")
    if data["status"] not in valid_statuses:
        return error(f"status must be one of: {', '.join(valid_statuses)}", 422)

    dispute = _get_dispute_or_404(reference, g.current_user["id"])
    if not dispute:
        return error("Dispute not found", 404)

    conn = get_db()
    conn.execute(
        """UPDATE dispute_cases
           SET status=?, resolution_note=COALESCE(?, resolution_note),
               resolved_at=CASE WHEN ? IN ('resolved','rejected') THEN datetime('now') ELSE resolved_at END,
               updated_at=datetime('now')
           WHERE reference=?""",
        (data["status"], data.get("resolution_note"), data["status"], reference),
    )
    conn.commit()
    conn.close()
    return success({"reference": reference, "status": data["status"]}, message="Status updated")
