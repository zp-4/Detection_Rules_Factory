"""One-page executive summary PDF (fpdf2)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from fpdf import FPDF


def build_executive_pdf(metrics: Dict[str, Any], title: str = "Executive summary") -> bytes:
    """Build a simple PDF from metrics dict (from collect_executive_metrics)."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Detection Rules Factory", ln=True, align="C")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, title, ln=True, align="C")
    pdf.ln(4)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    pdf.set_font("Helvetica", "I", 9)
    pdf.cell(0, 6, f"Generated: {ts}", ln=True)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Key metrics", ln=True)
    pdf.set_font("Helvetica", "", 10)

    lines = [
        f"Use cases: {metrics.get('use_case_count', 0)}",
        f"Detection rules (active catalogue): {metrics.get('rule_count', 0)}",
        f"MITRE techniques (use-case claims): {metrics.get('techniques_claimed_use_cases', 0)}",
        f"MITRE techniques (with rules): {metrics.get('techniques_with_rules', 0)}",
        f"Enabled rules: {metrics.get('enabled_rules', 0)}",
        f"Disabled rules: {metrics.get('disabled_rules', 0)}",
        f"Rules tagged to_improve: {metrics.get('rules_to_improve', 0)}",
        f"Retired (operational) in active view: {metrics.get('retired_active_view', 0)}",
        f"Archived rules (total): {metrics.get('archived_total', 0)}",
    ]
    for line in lines:
        pdf.cell(0, 6, line, ln=True)

    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Rules by platform", ln=True)
    pdf.set_font("Helvetica", "", 10)
    plats = metrics.get("platforms") or {}
    if not plats:
        pdf.cell(0, 6, "(none)", ln=True)
    else:
        for plat, cnt in list(plats.items())[:20]:
            pdf.cell(0, 6, f"  - {plat}: {cnt}", ln=True)
        if len(plats) > 20:
            pdf.cell(0, 6, f"  ... +{len(plats) - 20} more platforms", ln=True)

    raw = pdf.output(dest="S")
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    return str(raw).encode("latin-1", errors="replace")
