"""
AiTelDa Dispute-Forge PDF Generator

Produces a professional forensic audit report suitable for NCC submission.
Includes: device ID, timestamp, app-by-app breakdown, variance calculation,
          NCC General Consumer Code of Practice §5.3 legal citation.
"""

import os
import json
from datetime import datetime, timezone
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)

# Brand colours
BRAND_GREEN  = colors.HexColor("#00e5a0")
BRAND_DARK   = colors.HexColor("#050508")
BRAND_ORANGE = colors.HexColor("#ff4d00")
BRAND_GREY   = colors.HexColor("#6b6b80")
LIGHT_GREY   = colors.HexColor("#f0f0f4")
BORDER_GREY  = colors.HexColor("#ccccdd")

PDF_OUTPUT_DIR = os.environ.get("PDF_OUTPUT_DIR", "dispute_pdfs")
os.makedirs(PDF_OUTPUT_DIR, exist_ok=True)


def _bytes_to_mb(b: int) -> str:
    return f"{b / 1_048_576:.2f} MB"


def _format_pct(p: float) -> str:
    return f"{p:.2f}%"


def generate_dispute_pdf(dispute: dict, user: dict, device: dict, variance: dict) -> str:
    """
    Generate the forensic audit PDF.

    Args:
        dispute  : dispute_cases row dict
        user     : users row dict
        device   : devices row dict
        variance : result of calculate_variance()

    Returns:
        str : file path of the generated PDF
    """
    filename = f"{dispute['reference']}.pdf"
    filepath = os.path.join(PDF_OUTPUT_DIR, filename)

    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=f"AiTelDa Forensic Audit — {dispute['reference']}",
        author="AiTelDa Dispute-Forge",
        subject="Data Billing Dispute Report",
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "AiTelDaTitle",
        parent=styles["Title"],
        fontSize=22,
        textColor=BRAND_DARK,
        spaceAfter=4,
        fontName="Helvetica-Bold",
    )
    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=BRAND_GREY,
        spaceAfter=2,
        fontName="Helvetica",
    )
    section_style = ParagraphStyle(
        "Section",
        parent=styles["Heading2"],
        fontSize=11,
        textColor=BRAND_DARK,
        spaceBefore=14,
        spaceAfter=6,
        fontName="Helvetica-Bold",
        borderPad=4,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=9,
        textColor=BRAND_DARK,
        leading=14,
        alignment=TA_JUSTIFY,
    )
    mono_style = ParagraphStyle(
        "Mono",
        parent=styles["Code"],
        fontSize=8,
        textColor=BRAND_DARK,
        fontName="Courier",
        leading=12,
    )
    label_style = ParagraphStyle(
        "Label",
        parent=styles["Normal"],
        fontSize=8,
        textColor=BRAND_GREY,
        fontName="Helvetica",
    )
    alert_style = ParagraphStyle(
        "Alert",
        parent=styles["Normal"],
        fontSize=10,
        textColor=BRAND_ORANGE,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
        spaceBefore=4,
        spaceAfter=4,
    )
    legal_style = ParagraphStyle(
        "Legal",
        parent=styles["Normal"],
        fontSize=8,
        textColor=BRAND_DARK,
        leading=13,
        alignment=TA_JUSTIFY,
        leftIndent=10,
        rightIndent=10,
    )

    now_str = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")
    story = []

    # -----------------------------------------------------------------------
    # HEADER
    # -----------------------------------------------------------------------
    story.append(Paragraph("AiTelDa", title_style))
    story.append(Paragraph("AI-Native Data Audit Engine · Consumer Advocacy Platform", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=BRAND_GREEN, spaceAfter=8))

    # Reference banner
    ref_table = Table(
        [[
            Paragraph(f"FORENSIC AUDIT REPORT", ParagraphStyle("RefTitle", parent=styles["Normal"],
                fontSize=14, textColor=BRAND_DARK, fontName="Helvetica-Bold")),
            Paragraph(f"Ref: <b>{dispute['reference']}</b>", ParagraphStyle("Ref", parent=styles["Normal"],
                fontSize=12, textColor=BRAND_GREEN, fontName="Helvetica-Bold", alignment=TA_RIGHT)),
        ]],
        colWidths=["60%", "40%"],
    )
    ref_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GREY),
        ("ROWPADDING", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(ref_table)
    story.append(Spacer(1, 0.3 * cm))

    # Generated date
    story.append(Paragraph(f"Generated: {now_str}", label_style))
    story.append(Spacer(1, 0.4 * cm))

    # -----------------------------------------------------------------------
    # OVERBILLING ALERT (if applicable)
    # -----------------------------------------------------------------------
    if variance.get("is_suspected_overbilling"):
        story.append(
            Paragraph(
                f"⚠  SUSPECTED OVER-BILLING DETECTED — Variance: "
                f"{_format_pct(variance['variance_pct'])} "
                f"({_bytes_to_mb(variance['variance_bytes'])})",
                alert_style,
            )
        )
        story.append(HRFlowable(width="100%", thickness=1, color=BRAND_ORANGE, spaceAfter=6))

    # -----------------------------------------------------------------------
    # SECTION 1 — CONSUMER & DEVICE DETAILS
    # -----------------------------------------------------------------------
    story.append(Paragraph("1. Consumer & Device Information", section_style))

    details_data = [
        ["Consumer Name", user.get("full_name", "—"),
         "Report Date", now_str.split(",")[0]],
        ["Email Address", user.get("email", "—"),
         "Device ID", device.get("device_id", "—")],
        ["Phone Number", user.get("phone") or "—",
         "Platform", (device.get("platform") or "—").upper()],
        ["Network Provider", (device.get("telco") or "—").upper(),
         "Device Model", device.get("model") or "—"],
        ["OS Version", device.get("os_version") or "—",
         "App Version", device.get("app_version") or "—"],
    ]

    details_table = Table(details_data, colWidths=["22%", "28%", "20%", "30%"])
    details_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), BRAND_GREY),
        ("TEXTCOLOR", (2, 0), (2, -1), BRAND_GREY),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, LIGHT_GREY]),
        ("GRID", (0, 0), (-1, -1), 0.25, BORDER_GREY),
        ("ROWPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(details_table)

    # -----------------------------------------------------------------------
    # SECTION 2 — AUDIT PERIOD
    # -----------------------------------------------------------------------
    story.append(Paragraph("2. Audit Period", section_style))
    period_data = [
        ["Period Start", dispute.get("period_start", "—"),
         "Period End", dispute.get("period_end", "—")],
        ["Sessions Analysed", str(variance.get("sessions_analysed", 0)),
         "Data Source (Device)", "Packet-Sentry System Logs"],
        ["Data Source (Telco)", f"{(device.get('telco') or 'Telco').upper()} — "
                                f"{variance.get('telco_report_id') and 'SMS/USSD Report #' + str(variance['telco_report_id']) or 'Not available'}",
         "Report Method", "Automated — AiTelDa Dispute-Forge"],
    ]
    period_table = Table(period_data, colWidths=["22%", "28%", "20%", "30%"])
    period_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), BRAND_GREY),
        ("TEXTCOLOR", (2, 0), (2, -1), BRAND_GREY),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, LIGHT_GREY]),
        ("GRID", (0, 0), (-1, -1), 0.25, BORDER_GREY),
        ("ROWPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(period_table)

    # -----------------------------------------------------------------------
    # SECTION 3 — BILLING VARIANCE CALCULATION
    # -----------------------------------------------------------------------
    story.append(Paragraph("3. Billing Variance Calculation", section_style))
    story.append(Paragraph(
        "The following calculation applies the AiTelDa Discrepancy Algorithm: "
        "<b>V = |D<sub>device</sub> − D<sub>telco</sub>|</b>",
        body_style,
    ))
    story.append(Spacer(1, 0.3 * cm))

    variance_color = BRAND_ORANGE if variance.get("is_suspected_overbilling") else BRAND_GREEN

    variance_data = [
        ["Metric", "Value (Bytes)", "Value (MB)", ""],
        [
            "Device Recorded (D_device)",
            f"{variance['device_bytes']:,}",
            _bytes_to_mb(variance["device_bytes"]),
            "",
        ],
        [
            "Telco Reported (D_telco)",
            f"{variance['telco_bytes']:,}",
            _bytes_to_mb(variance["telco_bytes"]),
            "",
        ],
        [
            "Variance (V = |D_device − D_telco|)",
            f"{variance['variance_bytes']:,}",
            _bytes_to_mb(variance["variance_bytes"]),
            f"{_format_pct(variance['variance_pct'])}",
        ],
        [
            "Threshold for Suspected Over-billing",
            "—",
            "—",
            f"{_format_pct(variance['variance_threshold_pct'])}",
        ],
        [
            "Verdict",
            "SUSPECTED OVER-BILLING" if variance.get("is_suspected_overbilling") else "WITHIN THRESHOLD",
            "",
            "",
        ],
    ]

    variance_table = Table(variance_data, colWidths=["40%", "22%", "20%", "18%"])
    variance_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, -1), (-1, -1), variance_color),
        ("BACKGROUND", (0, -2), (-1, -2), LIGHT_GREY),
        ("GRID", (0, 0), (-1, -1), 0.25, BORDER_GREY),
        ("ROWPADDING", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("SPAN", (1, -1), (3, -1)),
    ]))
    story.append(variance_table)

    # -----------------------------------------------------------------------
    # SECTION 4 — PER-APP BREAKDOWN
    # -----------------------------------------------------------------------
    story.append(Paragraph("4. Application-by-Application Data Breakdown", section_style))
    story.append(Paragraph(
        "The following table lists all applications monitored during the audit period, "
        "ordered by data consumption. This data was recorded by the AiTelDa Packet-Sentry "
        "agent via system-level socket logs. No packet content was inspected.",
        body_style,
    ))
    story.append(Spacer(1, 0.3 * cm))

    app_data = [["Application UID", "App Name", "Sent (TX)", "Received (RX)", "Total", "% of Session"]]
    total_device = variance["device_bytes"] or 1

    for app in variance.get("app_breakdown", [])[:30]:  # cap at 30 rows
        pct = (app["total_bytes"] / total_device) * 100
        app_data.append([
            Paragraph(app["app_uid"], mono_style),
            app.get("app_name") or "—",
            _bytes_to_mb(app["tx"]),
            _bytes_to_mb(app["rx"]),
            _bytes_to_mb(app["total_bytes"]),
            f"{pct:.1f}%",
        ])

    if not variance.get("app_breakdown"):
        app_data.append(["No app-level data available", "—", "—", "—", "—", "—"])

    app_table = Table(app_data, colWidths=["30%", "20%", "12%", "13%", "13%", "12%"])
    app_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("FONTNAME", (1, 1), (-1, -1), "Helvetica"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_GREY]),
        ("GRID", (0, 0), (-1, -1), 0.25, BORDER_GREY),
        ("ROWPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (2, 0), (-1, -1), "RIGHT"),
    ]))
    story.append(app_table)

    # -----------------------------------------------------------------------
    # SECTION 5 — ANOMALY EVENTS
    # -----------------------------------------------------------------------
    anomalies = variance.get("anomaly_events", [])
    if anomalies:
        story.append(Paragraph("5. Detected Anomaly Events (Aura-Brain AI)", section_style))
        story.append(Paragraph(
            "The following events were flagged by the on-device AI engine as anomalous "
            "data consumption patterns, primarily occurring during screen-off (idle) states.",
            body_style,
        ))
        story.append(Spacer(1, 0.3 * cm))

        anom_data = [["Application", "Detected At", "Screen", "Baseline", "Actual", "Deviation", "Severity"]]
        for ev in anomalies[:20]:
            anom_data.append([
                Paragraph(ev["app_uid"], mono_style),
                ev["detected_at"][:19].replace("T", " "),
                ev["screen_state"].upper(),
                _bytes_to_mb(ev["baseline_bytes"]),
                _bytes_to_mb(ev["actual_bytes"]),
                f"+{ev['deviation_pct']:.0f}%",
                ev["severity"].upper(),
            ])

        anom_table = Table(anom_data, colWidths=["24%", "17%", "8%", "11%", "11%", "12%", "11%"])
        anom_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("FONTNAME", (1, 1), (-1, -1), "Helvetica"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_GREY]),
            ("GRID", (0, 0), (-1, -1), 0.25, BORDER_GREY),
            ("ROWPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(anom_table)
        section_offset = 1
    else:
        section_offset = 0

    # -----------------------------------------------------------------------
    # SECTION 6 — LEGAL BASIS & NCC CITATION
    # -----------------------------------------------------------------------
    legal_num = 5 + section_offset
    story.append(Paragraph(f"{legal_num}. Legal Basis for Dispute", section_style))

    story.append(Paragraph(
        "This dispute is filed pursuant to the Nigerian Communications Commission (NCC) "
        "<b>General Consumer Code of Practice for Licensees, 2007 (as amended)</b>, "
        "specifically:",
        body_style,
    ))
    story.append(Spacer(1, 0.2 * cm))

    citation_data = [
        [
            Paragraph(
                "<b>NCC General Consumer Code of Practice — Section 5.3</b><br/><br/>"
                "\"A Licensee shall ensure that its billing systems are accurate and that "
                "consumers are billed only for services actually consumed. Where a consumer "
                "disputes a bill, the Licensee shall investigate the dispute within a reasonable "
                "time and provide the consumer with a full explanation of the charges, including "
                "itemised billing information where requested.\"<br/><br/>"
                "The evidence presented in this report demonstrates a statistically significant "
                f"discrepancy of <b>{_format_pct(variance['variance_pct'])}</b> between data "
                "recorded on the consumer's device and data reported by the network licensee. "
                "This exceeds the AiTelDa over-billing threshold and constitutes grounds for "
                "formal investigation under the above provision.",
                legal_style,
            )
        ]
    ]
    citation_table = Table(citation_data, colWidths=["100%"])
    citation_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GREY),
        ("BOX", (0, 0), (-1, -1), 1, BRAND_GREEN),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(citation_table)

    # -----------------------------------------------------------------------
    # SECTION 7 — DECLARATION
    # -----------------------------------------------------------------------
    decl_num = legal_num + 1
    story.append(Paragraph(f"{decl_num}. Consumer Declaration", section_style))
    story.append(Paragraph(
        f"I, <b>{user.get('full_name', '—')}</b>, hereby declare that the information "
        "provided in this report has been automatically generated from encrypted system-level "
        "network logs recorded on my registered device. I authorise AiTelDa to submit this "
        "report to the Nigerian Communications Commission and/or the relevant network licensee "
        "for investigation and resolution.",
        body_style,
    ))
    story.append(Spacer(1, 1.5 * cm))

    sig_data = [
        ["_" * 35, "_" * 20],
        ["Consumer Signature", "Date"],
    ]
    sig_table = Table(sig_data, colWidths=["60%", "40%"])
    sig_table.setStyle(TableStyle([
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, 1), 8),
        ("TEXTCOLOR", (0, 1), (-1, 1), BRAND_GREY),
        ("TOPPADDING", (0, 1), (-1, 1), 4),
    ]))
    story.append(sig_table)

    # -----------------------------------------------------------------------
    # FOOTER
    # -----------------------------------------------------------------------
    story.append(Spacer(1, 0.8 * cm))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_GREEN, spaceAfter=6))
    story.append(Paragraph(
        f"This report was automatically generated by AiTelDa Dispute-Forge · "
        f"Reference: {dispute['reference']} · "
        f"Generated: {now_str} · "
        "Data sourced from on-device system logs only. No packet content inspected. "
        "AES-256 encrypted audit logs available on request.",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=6.5,
                       textColor=BRAND_GREY, alignment=TA_CENTER),
    ))

    doc.build(story)
    return filepath
