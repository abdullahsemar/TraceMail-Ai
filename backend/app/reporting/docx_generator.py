import os
from datetime import datetime, timedelta, timezone
from typing import Dict, Any
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from sqlalchemy.orm import Session
from app.config import settings
from app.database.models import EmailRecord, ForensicCase, WeeklyReport

class WeeklyReportGenerator:
    """
    Generates weekly security reports.
    Accurately reflects non-quarantining pre-delivery proxy inspection, flagging,
    warning header injection, and retrospective mailbox analysis.
    """

    @classmethod
    def generate_report(cls, db: Session, days: int = 7) -> Dict[str, Any]:
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)
        
        emails = db.query(EmailRecord).filter(EmailRecord.created_at >= start_date).all()
        total_count = len(emails)
        
        # Source breakdown
        smtp_emails = [e for e in emails if e.source == "SMTP_GATEWAY"]
        gmail_emails = [e for e in emails if e.source in ["GMAIL", "GMAIL_API"]]
        
        safe_count = sum(1 for e in emails if e.risk_severity == "LOW")
        suspicious_count = sum(1 for e in emails if e.risk_severity == "MEDIUM")
        high_critical_count = sum(1 for e in emails if e.risk_severity in ["HIGH", "CRITICAL"])
        
        bec_count = sum(1 for e in emails if e.threat_classification == "BUSINESS_EMAIL_COMPROMISE")
        phishing_count = sum(1 for e in emails if e.threat_classification == "PHISHING")
        cred_theft_count = sum(1 for e in emails if e.threat_classification in ["CREDENTIAL_PHISHING", "CREDENTIAL_THEFT"])
        impersonation_count = sum(1 for e in emails if e.threat_classification == "IMPERSONATION")
        fraud_count = sum(1 for e in emails if e.threat_classification == "FINANCIAL_FRAUD")
        malware_count = sum(1 for e in emails if e.threat_classification in ["MALICIOUS_ATTACHMENT", "MALWARE"])
        
        # Non-quarantining operational metrics
        flagged_count = sum(1 for e in emails if e.action_taken in ["FLAG", "FLAG_AND_ALERT"])
        delivered_clean_count = sum(1 for e in emails if e.action_taken == "ALLOW")
        
        doc = Document()
        
        title = doc.add_heading("TraceMail AI", level=0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        
        subtitle = doc.add_paragraph("Weekly Email Security Intelligence & Forensic Report")
        subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
        subtitle.runs[0].font.size = Pt(14)
        subtitle.runs[0].font.color.rgb = RGBColor(100, 100, 100)
        
        doc.add_paragraph(f"Report Period: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}")
        doc.add_paragraph(f"Generated At: {end_date.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        doc.add_paragraph("Classification: CONFIDENTIAL // SOC INTERNAL USE ONLY")
        
        doc.add_heading("1. Executive Summary & KPIs", level=1)
        doc.add_paragraph(
            f"During this reporting period, TraceMail AI screened {total_count} total messages across "
            f"Pre-Delivery SMTP Proxies ({len(smtp_emails)} messages) and Retrospective Mailbox Ingestion ({len(gmail_emails)} messages)."
        )
        
        table = doc.add_table(rows=1, cols=4)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        hdr_cells = table.rows[0].cells
        hdr_cells[0].text = "Security Ingestion Metric"
        hdr_cells[1].text = "Count"
        hdr_cells[2].text = "Threat Classification"
        hdr_cells[3].text = "Count"
        
        row_data = [
            ("SMTP Pre-Delivery Emails Screened", str(len(smtp_emails)), "Business Email Compromise (BEC)", str(bec_count)),
            ("Retrospective Mailbox Ingestion", str(len(gmail_emails)), "Phishing / Social Eng.", str(phishing_count)),
            ("High-Risk Messages Flagged & Alerted", str(high_critical_count), "Credential Phishing", str(cred_theft_count)),
            ("Suspicious Messages Flagged", str(suspicious_count), "Executive Impersonation", str(impersonation_count)),
            ("Delivered Cleanly", str(delivered_clean_count), "Financial / Invoice Fraud", str(fraud_count)),
            ("Total Flagged for Review", str(flagged_count), "Malicious Payloads", str(malware_count))
        ]
        
        for cat, cnt, t_cat, t_cnt in row_data:
            row = table.add_row().cells
            row[0].text = cat
            row[1].text = cnt
            row[2].text = t_cat
            row[3].text = t_cnt
            
        doc.add_heading("2. Defensive Action Breakdown", level=1)
        doc.add_paragraph(f"- SMTP Pre-Delivery Proxy: Analyzed and forwarded messages with injected risk warning metadata for {flagged_count} flagged threats.")
        doc.add_paragraph(f"- Retrospective Mailbox APIs: Evaluated {len(gmail_emails)} mailbox messages, correlating organizational communication baselines.")
        
        doc.add_heading("3. Major Security Incidents & Forensic Cases", level=1)
        
        threat_emails = [e for e in emails if e.risk_severity in ["HIGH", "CRITICAL"]]
        if not threat_emails:
            doc.add_paragraph("No critical security incidents occurred during this period.")
        else:
            for idx, th in enumerate(threat_emails[:10], start=1):
                p = doc.add_paragraph()
                p.add_run(f"Case {idx}: [{th.gateway_message_id}] {th.threat_classification} (Risk: {th.final_risk_score}/100)\n").bold = True
                p.add_run(f"Sender: {th.mail_from}\n")
                p.add_run(f"Subject: {th.subject}\n")
                p.add_run(f"Action Taken: {th.action_taken} | State: {th.processing_state}\n")
                p.add_run(f"Evidence SHA-256: {th.evidence_sha256}\n")
        
        os.makedirs(settings.REPORTS_DIR, exist_ok=True)
        report_filename = f"TraceMail_Security_Report_{end_date.strftime('%Y%m%d_%H%M%S')}.docx"
        report_path = os.path.join(settings.REPORTS_DIR, report_filename)
        
        doc.save(report_path)
        
        stats_summary = {
            "total_emails": total_count,
            "smtp_count": len(smtp_emails),
            "gmail_count": len(gmail_emails),
            "safe": safe_count,
            "suspicious": suspicious_count,
            "high_critical": high_critical_count,
            "flagged": flagged_count,
            "delivered": delivered_clean_count,
            "bec": bec_count,
            "phishing": phishing_count,
            "credential_theft": cred_theft_count,
            "impersonation": impersonation_count,
            "fraud": fraud_count,
            "malware": malware_count
        }
        
        weekly_report = WeeklyReport(
            report_title=f"TraceMail Security Report: {start_date.strftime('%b %d')} - {end_date.strftime('%b %d, %Y')}",
            period_start=start_date,
            period_end=end_date,
            file_path=report_path,
            stats_json=stats_summary
        )
        db.add(weekly_report)
        db.commit()
        db.refresh(weekly_report)
        
        return {
            "id": weekly_report.id,
            "title": weekly_report.report_title,
            "file_path": report_path,
            "filename": report_filename,
            "stats": stats_summary
        }
