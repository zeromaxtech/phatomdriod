"""
PhantomDroid — Report Generator
Feeds full scan session to Claude API and generates
a professional forensic security report as PDF.
"""

from narrator import call_gemini
import json
import os
from datetime import datetime
from fpdf import FPDF
from dotenv import load_dotenv
from prompts import REPORT_SYSTEM, REPORT_USER_TEMPLATE

load_dotenv()


class ReportGenerator:
    def __init__(self):
        pass

    def generate(self, session_data: dict) -> dict:
        """
        Generate full forensic report from session data.
        Returns parsed report dict.
        """
        events = session_data.get("events", [])
        permissions = session_data.get("permissions", [])
        network = session_data.get("network", [])
        duration = session_data.get("duration_minutes", 0)
        device_id = session_data.get("device_id", "unknown")

        print("[+] Generating AI forensic report...")

        try:
            raw = call_gemini(
                system_prompt=REPORT_SYSTEM,
                user_prompt=REPORT_USER_TEMPLATE.format(
                    device_id=device_id,
                    duration=duration,
                    event_count=len(events),
                    events_json=json.dumps(events[:30], indent=2),
                    permissions_json=json.dumps(permissions[:10], indent=2),
                    network_json=json.dumps(network[:10], indent=2)
                ),
                json_mode=True
            )
            report = json.loads(raw)
            report["generated_at"] = datetime.now().isoformat()
            report["device_id"] = device_id
            return report

        except Exception as e:
            print(f"[-] Report generation failed: {e}")
            return None

    def export_pdf(self, report: dict, output_path: str = None) -> str:
        """
        Export the report dict to a professional PDF.
        Returns path to the PDF file.
        """
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"phantomdroid_report_{timestamp}.pdf"

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # ── HEADER ──
        pdf.set_font("Helvetica", "B", 24)
        pdf.set_text_color(0, 255, 100)
        pdf.cell(0, 12, "👻 PHANTOMDROID", ln=True, align="C")
        pdf.set_font("Helvetica", "", 12)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 8, "Android Security Forensic Report", ln=True, align="C")
        pdf.cell(0, 6, f"Generated: {report.get('generated_at', '')[:19]}", ln=True, align="C")
        pdf.ln(8)

        # Risk level banner
        risk = report.get("overall_risk", "UNKNOWN")
        risk_colors = {
            "CRITICAL": (220, 50, 50),
            "HIGH": (220, 120, 50),
            "MEDIUM": (220, 180, 50),
            "LOW": (50, 180, 100)
        }
        r, g, b = risk_colors.get(risk, (100, 100, 100))
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, f"  OVERALL RISK: {risk}", ln=True, fill=True)
        pdf.ln(4)

        def section_header(title):
            pdf.set_text_color(30, 30, 30)
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_fill_color(230, 230, 230)
            pdf.cell(0, 8, f"  {title}", ln=True, fill=True)
            pdf.ln(2)

        def body_text(text):
            pdf.set_text_color(50, 50, 50)
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(0, 6, text)
            pdf.ln(2)

        # ── EXECUTIVE SUMMARY ──
        section_header("EXECUTIVE SUMMARY")
        body_text(report.get("executive_summary", "No summary available."))

        # ── TOP THREATS ──
        section_header("TOP THREATS")
        for threat in report.get("top_threats", []):
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(180, 0, 0)
            pdf.cell(0, 6, f"  ⚠ {threat.get('app', '')} — {threat.get('severity', '')}", ln=True)
            body_text(f"    {threat.get('explanation', '')}")

        # ── APP RISK PROFILES ──
        section_header("APP RISK PROFILES")
        for app in report.get("app_profiles", []):
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(30, 30, 30)
            score = app.get("risk_score", 0)
            pdf.cell(0, 6, f"  {app.get('app', '')}  [Score: {score}/100]", ln=True)
            body_text(f"    {app.get('verdict', '')}")

        # ── RECOMMENDATIONS ──
        section_header("RECOMMENDATIONS")
        for i, rec in enumerate(report.get("recommendations", []), 1):
            body_text(f"  {i}. {rec}")

        # ── FOOTER ──
        pdf.ln(6)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 6, "PhantomDroid — Ethical Security Research Tool. For authorized use only.", ln=True, align="C")

        pdf.output(output_path)
        print(f"[+] Report exported: {output_path}")
        return output_path
