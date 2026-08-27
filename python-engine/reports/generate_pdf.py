"""PDF report generator for NetShield AI security reports.

Uses ReportLab to produce a multi-page PDF with:
- Cover page with title and timestamp.
- Executive summary (total packets, attack %, threat level).
- Attack breakdown table.
- Top 10 attacker IPs table.
- Security recommendations.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from database import Database

logger = logging.getLogger(__name__)

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
    Paragraph,
    PageBreak,
)


class ReportGenerator:
    """Generates a PDF security report from database statistics.

    Args:
        database: Database instance for querying attack data.
    """

    def __init__(self, database: Database) -> None:
        """Initialize the report generator.

        Args:
            database: Database instance for querying attack data.
        """
        self._db: Database = database

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, output_dir: str = "reports") -> str:
        """Generate a multi-page PDF security report.

        Args:
            output_dir: Directory to save the report in. Created if missing.

        Returns:
            Absolute file path to the generated PDF.
        """
        os.makedirs(output_dir, exist_ok=True)
        timestamp_str = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        filename = f"netshield_report_{timestamp_str}.pdf"
        filepath = os.path.join(output_dir, filename)

        doc = SimpleDocTemplate(
            filepath,
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )

        styles = getSampleStyleSheet()
        story: list[Any] = []

        # Gather data (handle empty DB gracefully)
        stats = self._safe_get_stats()
        threat_level = self._safe_get_threat_level()
        attack_summary = self._safe_get_attack_summary()
        top_attackers = self._safe_get_top_attackers()

        # --- Cover Page ---
        story.append(Spacer(1, 2 * inch))
        story.append(
            Paragraph(
                "NetShield AI<br/>Security Report",
                styles["Title"],
            )
        )
        story.append(Spacer(1, 0.5 * inch))
        story.append(
            Paragraph(
                f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
                styles["Normal"],
            )
        )
        story.append(PageBreak())

        # --- Executive Summary ---
        story.append(Paragraph("Executive Summary", styles["Heading1"]))
        story.append(Spacer(1, 0.2 * inch))

        total = stats.get("total", 0)
        attacks = stats.get("attacks", 0)
        normal = stats.get("normal", 0)
        attack_pct = (attacks / total * 100) if total > 0 else 0.0

        summary_lines = [
            f"Total Packets Analysed: {total}",
            f"Normal Traffic: {normal}",
            f"Attacks Detected: {attacks}",
            f"Attack Percentage: {attack_pct:.2f}%",
            f"Current Threat Level: {threat_level}",
        ]
        for line in summary_lines:
            story.append(Paragraph(line, styles["Normal"]))
            story.append(Spacer(1, 0.1 * inch))

        story.append(Spacer(1, 0.3 * inch))

        # --- Attack Breakdown Table ---
        story.append(Paragraph("Attack Breakdown", styles["Heading1"]))
        story.append(Spacer(1, 0.2 * inch))

        if attack_summary:
            breakdown_data = [["Attack Type", "Count", "Percentage"]]
            for item in attack_summary:
                breakdown_data.append(
                    [item["attack_type"], str(item["count"]), f"{item['percentage']:.2f}%"]
                )
            breakdown_table = Table(breakdown_data, colWidths=[3 * inch, 1.5 * inch, 1.5 * inch])
            breakdown_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 11),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#e8eaf6")),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#e8eaf6")]),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ]
                )
            )
            story.append(breakdown_table)
        else:
            story.append(
                Paragraph("No attacks detected in the database.", styles["Normal"])
            )

        story.append(Spacer(1, 0.4 * inch))

        # --- Top 10 Attacker IPs ---
        story.append(Paragraph("Top 10 Attacker IPs", styles["Heading1"]))
        story.append(Spacer(1, 0.2 * inch))

        if top_attackers:
            attacker_data = [["Rank", "Source IP", "Attack Count"]]
            for idx, item in enumerate(top_attackers[:10], start=1):
                attacker_data.append([str(idx), item["src_ip"], str(item["count"])])
            attacker_table = Table(attacker_data, colWidths=[1 * inch, 3.5 * inch, 1.5 * inch])
            attacker_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#b71c1c")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 11),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#ffebee")]),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ]
                )
            )
            story.append(attacker_table)
        else:
            story.append(
                Paragraph("No attacker IPs recorded.", styles["Normal"])
            )

        story.append(Spacer(1, 0.4 * inch))

        # --- Security Recommendations ---
        story.append(Paragraph("Security Recommendations", styles["Heading1"]))
        story.append(Spacer(1, 0.2 * inch))

        recommendations = self._build_recommendations(threat_level, attack_summary)
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", styles["Normal"]))
            story.append(Spacer(1, 0.05 * inch))

        doc.build(story)
        logger.info("Report generated at %s", filepath)
        return os.path.abspath(filepath)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _safe_get_stats(self) -> dict[str, Any]:
        """Safely fetch stats, returning empty dict on failure.

        Returns:
            Stats dictionary or empty dict.
        """
        try:
            return self._db.get_stats()
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to fetch stats: %s", exc)
            return {}

    def _safe_get_threat_level(self) -> str:
        """Safely fetch threat level.

        Returns:
            Threat level string or "UNKNOWN".
        """
        try:
            return self._db.get_threat_level()
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to fetch threat level: %s", exc)
            return "UNKNOWN"

    def _safe_get_attack_summary(self) -> list[dict[str, Any]]:
        """Safely fetch attack summary.

        Returns:
            List of attack summary dicts or empty list.
        """
        try:
            return self._db.get_attack_summary()
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to fetch attack summary: %s", exc)
            return []

    def _safe_get_top_attackers(self) -> list[dict[str, Any]]:
        """Safely fetch top attackers.

        Returns:
            List of attacker dicts or empty list.
        """
        try:
            return self._db.get_top_attackers(limit=10)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to fetch top attackers: %s", exc)
            return []

    @staticmethod
    def _build_recommendations(
        threat_level: str,
        attack_summary: list[dict[str, Any]],
    ) -> list[str]:
        """Generate security recommendations based on threat data.

        Args:
            threat_level: Current threat level (SAFE/ELEVATED/CRITICAL).
            attack_summary: Attack type breakdown.

        Returns:
            List of recommendation strings.
        """
        recommendations: list[str] = []

        if threat_level == "CRITICAL":
            recommendations.append(
                "Threat level is CRITICAL. Initiate immediate incident response."
            )
            recommendations.append(
                "Consider isolating affected network segments and blocking top attacker IPs."
            )
        elif threat_level == "ELEVATED":
            recommendations.append(
                "Threat level is ELEVATED. Increase monitoring of suspicious traffic."
            )

        attack_types = [a["attack_type"] for a in attack_summary]
        if "DDoS" in attack_types:
            recommendations.append(
                "DDoS attacks detected. Ensure rate limiting and DDoS mitigation are active."
            )
        if "BruteForce" in attack_types:
            recommendations.append(
                "Brute-force attacks detected. Enforce strong password policies and account lockout."
            )
        if "PortScan" in attack_types:
            recommendations.append(
                "Port scanning detected. Review firewall rules and close unused ports."
            )
        if "Bot" in attack_types:
            recommendations.append(
                "Botnet activity detected. Quarantine affected hosts and investigate C2 communication."
            )
        if "Infiltration" in attack_types:
            recommendations.append(
                "Infiltration attempts detected. Conduct a full forensic audit of affected systems."
            )
        if "WebAttack" in attack_types:
            recommendations.append(
                "Web attacks detected. Deploy WAF rules and audit web application logs."
            )
        if "DoS" in attack_types:
            recommendations.append(
                "Denial-of-service attacks detected. Verify service availability and load balancing."
            )
        if "Heartbleed" in attack_types:
            recommendations.append(
                "Heartbleed exploit attempts detected. Patch OpenSSL on all servers immediately."
            )

        if not recommendations:
            recommendations.append(
                "No critical threats detected. Maintain regular monitoring and keep systems patched."
            )

        recommendations.append(
            "Regularly update intrusion detection model signatures and review alert configurations."
        )
        return recommendations
