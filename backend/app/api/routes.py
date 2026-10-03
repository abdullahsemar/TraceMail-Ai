import os
from fastapi import APIRouter, Depends, HTTPException, Query, Body
from fastapi.responses import StreamingResponse, FileResponse
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
import asyncio

from app.database.session import get_db
from app.database.models import (
    EmailRecord, EmailEvidence, AnalysisResult, AuthenticationResult,
    RelayHop, OriginAssessment, IOC, ForensicCase, AnalystFeedback,
    Campaign, CampaignLink, AuditEvent, WeeklyReport, MailConnection, SenderBaseline
)
from app.gateway.handler import InboundPipelineProcessor
from app.reporting.docx_generator import WeeklyReportGenerator
from app.core.audit import AuditLogger
from app.core.events import broadcaster
from app.api.routes_gmail import router as gmail_router
from app.connectors.gmail import gmail_connector
from app.gateway.downstream import DownstreamRelayClient
from app.config import settings

api_router = APIRouter()
api_router.include_router(gmail_router, prefix="/connectors/gmail", tags=["Gmail Connector"])

# ----------------- SYSTEM HEALTH -----------------
@api_router.get("/health")
def get_system_health(db: Session = Depends(get_db)):
    # 1. DB check
    db_status = "healthy"
    try:
        db.execute("SELECT 1")
    except Exception:
        db_status = "error"

    # 2. DistilBERT check
    from app.engines.threat_ml import HybridThreatEngine
    distilbert_status = HybridThreatEngine.get_model_status()

    # 3. Gmail status (Graceful NOT_CONFIGURED when OAuth credentials are absent)
    gmail_status = "not_configured"
    if gmail_connector.is_connected():
        gmail_status = "connected"
    elif gmail_connector.is_configured():
        gmail_status = "configured_disconnected"

    # 4. SMTP Gateway status
    smtp_status = "running" if settings.SMTP_GATEWAY_ENABLED else "disabled"

    # 5. Downstream SMTP status
    downstream_status = "configured" if DownstreamRelayClient.is_configured() else "not_configured"

    # 6. Telegram status
    telegram_status = "connected" if (settings.TELEGRAM_ENABLED and settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_CHAT_ID) else "not_configured"

    # 7. GeoIP status
    geoip_status = "configured" if (settings.MAXMIND_DB_PATH and os.path.exists(settings.MAXMIND_DB_PATH)) else "not_configured"

    return {
        "status": "HEALTHY" if db_status == "healthy" else "DEGRADED",
        "backend": "healthy",
        "database": db_status,
        "distilbert": distilbert_status,
        "gmail": gmail_status,
        "smtp_gateway": smtp_status,
        "downstream_smtp": downstream_status,
        "telegram": telegram_status,
        "geoip": geoip_status,
        "deployment_mode": settings.TRACEMAIL_DEPLOYMENT_MODE,
        "version": settings.VERSION
    }

# ----------------- SMTP DIAGNOSTICS & STATUS -----------------
@api_router.get("/smtp/status")
def get_smtp_status(db: Session = Depends(get_db)):
    """
    Returns live SMTP gateway listener parameters and downstream relay configuration state.
    Does NOT expose credentials or secret tokens.
    """
    flagged_count = db.query(EmailRecord).filter(EmailRecord.action_taken.in_(["FLAG", "FLAG_AND_ALERT"])).count()
    return {
        "gateway_enabled": settings.SMTP_GATEWAY_ENABLED,
        "gateway_host": settings.SMTP_GATEWAY_HOST,
        "gateway_port": settings.SMTP_GATEWAY_PORT,
        "downstream_host": settings.DOWNSTREAM_SMTP_HOST,
        "downstream_port": settings.DOWNSTREAM_SMTP_PORT,
        "downstream_configured": DownstreamRelayClient.is_configured(),
        "downstream_tls": settings.DOWNSTREAM_SMTP_USE_TLS,
        "downstream_starttls": getattr(settings, "DOWNSTREAM_SMTP_STARTTLS", False),
        "flagged_count": flagged_count
    }

@api_router.post("/smtp/test-downstream")
async def test_downstream_smtp():
    """
    Performs real TCP/DNS/TLS handshake test against the configured downstream SMTP server.
    Does NOT inject, fabricate, or relay any fake test emails.
    """
    res = await DownstreamRelayClient.test_connection()
    return res

# ----------------- STATS & DASHBOARD -----------------
@api_router.get("/dashboard/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    from datetime import datetime, timezone
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    total_emails = db.query(EmailRecord).count()
    today_count = db.query(EmailRecord).filter(EmailRecord.created_at >= today_start).count()
    
    safe_emails = db.query(EmailRecord).filter(EmailRecord.risk_severity == "LOW").count()
    suspicious_emails = db.query(EmailRecord).filter(EmailRecord.risk_severity == "MEDIUM").count()
    high_threats = db.query(EmailRecord).filter(EmailRecord.risk_severity == "HIGH").count()
    critical_threats = db.query(EmailRecord).filter(EmailRecord.risk_severity == "CRITICAL").count()
    total_threats = high_threats + critical_threats

    gmail_count = db.query(EmailRecord).filter(EmailRecord.source.in_(["GMAIL_API", "GMAIL"])).count()
    smtp_count = db.query(EmailRecord).filter(EmailRecord.source.in_(["SMTP_GATEWAY", "SMTP"])).count()
    
    flagged_for_review = db.query(EmailRecord).filter(
        (EmailRecord.risk_severity.in_(["HIGH", "CRITICAL"])) | (EmailRecord.review_status == "UNREVIEWED")
    ).count()
    active_cases = db.query(ForensicCase).filter(ForensicCase.status.in_(["UNREVIEWED", "OPEN", "IN_REVIEW"])).count()
    active_campaigns = db.query(Campaign).filter(Campaign.status == "ACTIVE").count()
    
    # Accurate Classification breakdown from actual database records
    classifications = {
        "BUSINESS_EMAIL_COMPROMISE": db.query(EmailRecord).filter(
            EmailRecord.threat_classification == "BUSINESS_EMAIL_COMPROMISE",
            EmailRecord.risk_severity.in_(["HIGH", "CRITICAL"])
        ).count(),
        "PHISHING": db.query(EmailRecord).filter(
            EmailRecord.threat_classification == "PHISHING",
            EmailRecord.risk_severity.in_(["HIGH", "CRITICAL"])
        ).count(),
        "CREDENTIAL_PHISHING": db.query(EmailRecord).filter(
            EmailRecord.threat_classification.in_(["CREDENTIAL_PHISHING", "CREDENTIAL_THEFT"]),
            EmailRecord.risk_severity.in_(["HIGH", "CRITICAL"])
        ).count(),
        "IMPERSONATION": db.query(EmailRecord).filter(
            EmailRecord.threat_classification == "IMPERSONATION"
        ).count(),
        "FINANCIAL_FRAUD": db.query(EmailRecord).filter(
            EmailRecord.threat_classification == "FINANCIAL_FRAUD"
        ).count(),
        "MALICIOUS_ATTACHMENT": db.query(EmailRecord).filter(
            EmailRecord.threat_classification.in_(["MALICIOUS_ATTACHMENT", "MALWARE"])
        ).count(),
        "SUSPICIOUS_ANOMALY": suspicious_emails,
        "LEGITIMATE": safe_emails
    }

    return {
        "gateway_status": "ONLINE" if settings.SMTP_GATEWAY_ENABLED else "OFFLINE",
        "gateway_port": settings.SMTP_GATEWAY_PORT,
        "downstream_port": settings.DOWNSTREAM_SMTP_PORT,
        "total_emails": total_emails,
        "today": today_count,
        "safe_emails": safe_emails,
        "suspicious_emails": suspicious_emails,
        "high_threats": high_threats,
        "critical_threats": critical_threats,
        "total_threats": total_threats,
        "gmail_count": gmail_count,
        "smtp_count": smtp_count,
        "flagged_for_review": flagged_for_review,
        "active_cases": active_cases,
        "active_campaigns": active_campaigns,
        "classifications": classifications
    }

# ----------------- REAL-TIME SSE STREAM -----------------
@api_router.get("/events/stream")
async def events_stream():
    queue = broadcaster.subscribe_sse()
    
    async def event_generator():
        try:
            yield "event: PING\ndata: {\"status\": \"connected\"}\n\n"
            while True:
                data = await queue.get()
                yield data
        except asyncio.CancelledError:
            broadcaster.unsubscribe_sse(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

# ----------------- EMAILS & INBOX / INVESTIGATIONS -----------------
@api_router.get("/emails")
def list_emails(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    limit: Optional[int] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    q = db.query(EmailRecord).order_by(EmailRecord.created_at.desc())
    
    if severity and severity.upper() != "ALL":
        sev_upper = severity.upper()
        if sev_upper == "LOW":
            q = q.filter(EmailRecord.risk_severity.in_(["LOW", "SAFE"]))
        elif sev_upper == "MEDIUM":
            q = q.filter(EmailRecord.risk_severity.in_(["MEDIUM", "SUSPICIOUS"]))
        else:
            q = q.filter(EmailRecord.risk_severity == sev_upper)
            
    if source and source.upper() != "ALL":
        src_upper = source.upper()
        if "GMAIL" in src_upper:
            q = q.filter(EmailRecord.source.in_(["GMAIL_API", "GMAIL"]))
        elif "SMTP" in src_upper:
            q = q.filter(EmailRecord.source.in_(["SMTP_GATEWAY", "SMTP"]))
        else:
            q = q.filter(EmailRecord.source == src_upper)
            
    if search and search.strip():
        term = f"%{search.strip()}%"
        q = q.filter(
            (EmailRecord.subject.ilike(term)) |
            (EmailRecord.mail_from.ilike(term)) |
            (EmailRecord.rcpt_to.ilike(term)) |
            (EmailRecord.gateway_message_id.ilike(term)) |
            (EmailRecord.threat_classification.ilike(term))
        )
    
    total = q.count()
    effective_limit = limit if limit is not None else page_size
    offset = (page - 1) * effective_limit if limit is None else 0
    
    emails = q.offset(offset).limit(effective_limit).all()
    results = []
    for e in emails:
        src = "GMAIL" if "GMAIL" in (e.source or "").upper() else "SMTP"
        results.append({
            "id": e.id,
            "gateway_message_id": e.gateway_message_id,
            "source": e.source,
            "source_display": src,
            "mail_from": e.mail_from,
            "sender": e.mail_from,
            "rcpt_to": e.rcpt_to,
            "subject": e.subject,
            "processing_state": e.processing_state,
            "review_status": e.review_status,
            "risk_score": e.final_risk_score,
            "final_risk_score": e.final_risk_score,
            "risk_severity": e.risk_severity,
            "threat_classification": e.threat_classification,
            "threat_probability": e.threat_probability,
            "evidence_confidence": e.evidence_confidence,
            "impact_score": e.impact_score,
            "origin_confidence": e.origin_confidence,
            "action_taken": e.action_taken,
            "created_at": e.created_at.isoformat() if e.created_at else None
        })
        
    total_pages = max(1, (total + effective_limit - 1) // effective_limit)
    
    return {
        "items": results,
        "total": total,
        "page": page,
        "page_size": effective_limit,
        "total_pages": total_pages
    }

@api_router.get("/emails/{email_id}")
def get_email_details(email_id: str, db: Session = Depends(get_db)):
    email = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
        
    evidence = email.evidence
    analysis = email.analysis
    auth = email.auth_results
    origin = email.origin_assessment
    hops = db.query(RelayHop).filter(RelayHop.email_id == email_id).order_by(RelayHop.hop_order.asc()).all()
    iocs = db.query(IOC).filter(IOC.email_id == email_id).all()
    case = email.case
    feedback = email.feedback_entries

    # Lookup behavioral baseline for sender
    sender_clean = email.mail_from.strip().lower()
    baseline = db.query(SenderBaseline).filter(SenderBaseline.sender_email == sender_clean).first()
    sample_count = baseline.total_messages_seen if baseline else 1

    return {
        "id": email.id,
        "gateway_message_id": email.gateway_message_id,
        "source": email.source,
        "mail_from": email.mail_from,
        "sender_display_name": email.sender_display_name,
        "reply_to": email.reply_to,
        "return_path": email.return_path,
        "rcpt_to": email.rcpt_to,
        "subject": email.subject,
        "date_header": email.date_header,
        "processing_state": email.processing_state,
        "review_status": email.review_status,
        "evidence_sha256": email.evidence_sha256,
        "sentinel_score": email.sentinel_score,
        "sentinel_decision": email.sentinel_decision,
        "final_risk_score": email.final_risk_score,
        "risk_severity": email.risk_severity,
        "threat_classification": email.threat_classification,
        "confidence_score": email.confidence_score,
        "threat_probability": email.threat_probability,
        "evidence_confidence": email.evidence_confidence,
        "impact_score": email.impact_score,
        "origin_confidence": email.origin_confidence,
        "recommended_action": email.recommended_action,
        "action_taken": email.action_taken,
        "action_reason": email.action_reason,
        "created_at": email.created_at.isoformat() if email.created_at else None,
        "evidence": {
            "sha256": evidence.sha256_hash if evidence else None,
            "raw_size": evidence.raw_size_bytes if evidence else 0,
            "body_text": evidence.extracted_body_text if evidence else "",
            "body_html_sanitized": evidence.extracted_body_html_sanitized if evidence else "",
            "attachments": evidence.attachments_json if evidence else [],
            "urls": evidence.urls_json if evidence else [],
            "headers": evidence.headers_json if evidence else {}
        } if evidence else None,
        "analysis": {
            "model_version": analysis.model_version if analysis else "TraceMail-Fusion-v2.0",
            "detected_behaviors": analysis.detected_behaviors if analysis else [],
            "supporting_reasons": analysis.supporting_reasons if analysis else [],
            "mitigating_reasons": analysis.mitigating_reasons if analysis else [],
            "uncertainties": analysis.uncertainties if analysis else [],
            "nlp_score": analysis.nlp_score if analysis else 0.0,
            "header_score": analysis.header_anomaly_score if analysis else 0.0,
            "baseline_score": analysis.baseline_anomaly_score if analysis else 0.0,
            "url_score": analysis.url_intel_score if analysis else 0.0,
            "ip_score": analysis.ip_reputation_score if analysis else 0.0,
            "fusion_summary": analysis.fusion_summary if analysis else ""
        } if analysis else None,
        "research_bec_analysis": {
            "methodology": "Sequential detection inspired by Cidon et al., USENIX Security 2019",
            "stage_a_impersonation_score": round(min(1.0, (analysis.header_anomaly_score if analysis else 0.0) / 25.0), 2),
            "stage_b_content_risk": round(min(1.0, (analysis.nlp_score if analysis else 0.0) / 25.0), 2),
            "sender_corporate_domain": "@" in sender_clean and any(sender_clean.endswith(d) for d in ["organization.local", "example.com", "example.org"]),
            "historical_sample_count": sample_count,
            "baseline_maturity": "MATURE" if sample_count >= 25 else ("DEVELOPING" if sample_count >= 5 else "COLD_START"),
            "reply_to_anomaly": bool(email.reply_to and email.reply_to.lower() != sender_clean)
        },
        "authentication": {
            "spf_result": auth.spf_result if auth else "UNKNOWN",
            "spf_domain": auth.spf_domain if auth else None,
            "dkim_result": auth.dkim_result if auth else "UNKNOWN",
            "dkim_domain": auth.dkim_domain if auth else None,
            "dmarc_result": auth.dmarc_result if auth else "UNKNOWN",
            "dmarc_policy": auth.dmarc_policy if auth else None,
            "arc_result": auth.arc_result if auth else "NONE",
            "auth_summary": auth.auth_summary if auth else ""
        } if auth else None,
        "origin_assessment": {
            "earliest_observable_ip": origin.earliest_observable_ip if origin else None,
            "country": origin.country if origin else "Unknown",
            "country_code": origin.country_code if origin else "??",
            "region": origin.region if origin else None,
            "city": origin.city if origin else None,
            "asn": origin.asn if origin else None,
            "asn_org": origin.asn_org if origin else None,
            "isp": origin.isp if origin else None,
            "is_cloud": origin.is_cloud if origin else False,
            "is_vpn": origin.is_vpn if origin else False,
            "is_tor": origin.is_tor if origin else False,
            "is_proxy": origin.is_proxy if origin else False,
            "confidence_score": origin.origin_confidence_score if origin else 0.0,
            "confidence_level": origin.origin_confidence_level if origin else "MEDIUM",
            "explanation": origin.confidence_explanation if origin else "",
            "infrastructure_label": origin.infrastructure_label if origin else "Probable Observable Infrastructure"
        } if origin else None,
        "relay_hops": [
            {
                "order": h.hop_order,
                "ip": h.ip_address,
                "from_host": h.from_host,
                "by_host": h.by_host,
                "is_public": h.is_public
            } for h in hops
        ],
        "iocs": [{"type": i.ioc_type, "value": i.ioc_value, "reputation": i.reputation} for i in iocs],
        "case": {
            "case_number": case.case_number,
            "status": case.status,
            "priority": case.priority,
            "assigned_analyst": case.assigned_analyst,
            "summary": case.summary
        } if case else None,
        "feedback": [
            {
                "id": f.id,
                "verdict_label": f.verdict_label,
                "analyst_name": f.analyst_name,
                "notes": f.notes,
                "created_at": f.created_at.isoformat()
            } for f in feedback
        ]
    }

# ----------------- REVIEW QUEUE & ANALYST WORKFLOW (REPLACES QUARANTINE) -----------------
@api_router.get("/review-queue")
def list_review_queue(db: Session = Depends(get_db)):
    """
    Review Queue: List of flagged and high-risk emails requiring analyst investigation.
    This is an analytical triage workspace, NOT an email holding/quarantine area.
    """
    cases = db.query(ForensicCase).order_by(ForensicCase.created_at.desc()).all()
    results = []
    for c in cases:
        e = c.email
        if not e:
            continue
        results.append({
            "case_id": c.id,
            "case_number": c.case_number,
            "email_id": e.id,
            "gateway_message_id": e.gateway_message_id,
            "source": e.source,
            "sender": e.mail_from,
            "recipient": e.rcpt_to,
            "subject": e.subject,
            "risk_score": e.final_risk_score,
            "threat_classification": e.threat_classification,
            "severity": e.risk_severity,
            "threat_probability": e.threat_probability,
            "evidence_confidence": e.evidence_confidence,
            "review_status": c.status,
            "assigned_analyst": c.assigned_analyst,
            "evidence_sha256": e.evidence_sha256,
            "created_at": c.created_at.isoformat() if c.created_at else None
        })
    return results

@api_router.post("/review-queue/{case_id}/review")
def update_case_review_status(
    case_id: str,
    payload: dict = Body(...),
    db: Session = Depends(get_db)
):
    """
    Updates the review status of an incident case in the Review Queue.
    Allowed statuses: UNREVIEWED, IN_REVIEW, CONFIRMED_THREAT, FALSE_POSITIVE, RESOLVED.
    """
    case = db.query(ForensicCase).filter(ForensicCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    new_status = payload.get("status", "IN_REVIEW").upper()
    valid_statuses = {"UNREVIEWED", "IN_REVIEW", "CONFIRMED_THREAT", "FALSE_POSITIVE", "RESOLVED"}
    if new_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status '{new_status}'. Allowed: {valid_statuses}")

    case.status = new_status
    if "analyst" in payload:
        case.assigned_analyst = payload["analyst"]
    if "notes" in payload:
        case.notes = payload["notes"]

    # Also synchronize email review_status
    if case.email:
        case.email.review_status = new_status

    # Record Audit Event
    AuditLogger.log_event(
        db=db,
        event_type="ANALYST_REVIEWED",
        target_resource=case.case_number,
        details={"new_status": new_status, "analyst": case.assigned_analyst, "notes": case.notes}
    )

    db.commit()
    return {"status": "SUCCESS", "case_number": case.case_number, "new_status": new_status}

@api_router.post("/cases/{case_id}/feedback")
def submit_analyst_feedback(
    case_id: str,
    payload: dict = Body(...),
    db: Session = Depends(get_db)
):
    """
    Records structured analyst feedback (CONFIRMED_THREAT, FALSE_POSITIVE, BENIGN, NEEDS_REVIEW).
    Stored safely for offline calibration and dataset exports; does NOT immediately poison active models.
    """
    case = db.query(ForensicCase).filter(ForensicCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    verdict_label = payload.get("verdict_label", "CONFIRMED_THREAT").upper()
    analyst_name = payload.get("analyst_name", "SOC_ANALYST")
    notes = payload.get("notes", "")

    feedback = AnalystFeedback(
        case_id=case.id,
        email_id=case.email_id,
        verdict_label=verdict_label,
        analyst_name=analyst_name,
        notes=notes
    )
    db.add(feedback)

    # Update case status accordingly
    if verdict_label in ["CONFIRMED_THREAT", "FALSE_POSITIVE"]:
        case.status = verdict_label
        if case.email:
            case.email.review_status = verdict_label

    AuditLogger.log_event(
        db=db,
        event_type="ANALYST_FEEDBACK_RECORDED",
        target_resource=case.case_number,
        details={"verdict_label": verdict_label, "analyst": analyst_name}
    )

    db.commit()
    return {"status": "SUCCESS", "feedback_id": feedback.id, "verdict_label": verdict_label}

# ----------------- CASES -----------------
@api_router.get("/cases")
def list_cases(db: Session = Depends(get_db)):
    cases = db.query(ForensicCase).order_by(ForensicCase.created_at.desc()).all()
    results = []
    for c in cases:
        e = c.email
        results.append({
            "id": c.id,
            "case_number": c.case_number,
            "email_id": c.email_id,
            "status": c.status,
            "priority": c.priority,
            "assigned_analyst": c.assigned_analyst,
            "summary": c.summary,
            "subject": e.subject if e else "",
            "sender": e.mail_from if e else "",
            "risk_score": e.final_risk_score if e else 0.0,
            "threat_classification": e.threat_classification if e else "UNKNOWN",
            "origin_confidence": e.origin_confidence if e else 0.0,
            "created_at": c.created_at.isoformat() if c.created_at else None
        })
    return results

# ----------------- CAMPAIGNS -----------------
@api_router.get("/campaigns")
def list_campaigns(db: Session = Depends(get_db)):
    campaigns = db.query(Campaign).all()
    results = []
    for c in campaigns:
        links = db.query(CampaignLink).filter(CampaignLink.campaign_id == c.id).all()
        results.append({
            "id": c.id,
            "name": c.name,
            "threat_type": c.threat_type,
            "description": c.description,
            "status": c.status,
            "total_incidents": c.total_incidents,
            "correlation_confidence": c.correlation_confidence,
            "shared_indicators": c.shared_indicators,
            "links": [{"source": l.source_node, "target": l.target_node, "type": l.link_type} for l in links]
        })
    return results

# ----------------- THREAT INTEL IOCs -----------------
@api_router.get("/threat-intel/iocs")
def list_iocs(db: Session = Depends(get_db)):
    iocs = db.query(IOC).order_by(IOC.created_at.desc()).limit(100).all()
    return [{"id": i.id, "type": i.ioc_type, "value": i.ioc_value, "reputation": i.reputation, "created_at": i.created_at.isoformat() if i.created_at else None} for i in iocs]

# ----------------- AUDIT TRAIL -----------------
@api_router.get("/audit/events")
def list_audit_events(db: Session = Depends(get_db)):
    events = db.query(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(100).all()
    return [
        {
            "id": e.id,
            "event_type": e.event_type,
            "actor": e.actor,
            "target_resource": e.target_resource,
            "details": e.details,
            "event_hash": e.event_hash,
            "prev_event_hash": e.prev_event_hash,
            "created_at": e.created_at.isoformat() if e.created_at else None
        } for e in events
    ]

@api_router.get("/audit/verify-chain")
def verify_audit_integrity(db: Session = Depends(get_db)):
    return AuditLogger.verify_chain_integrity(db)

# ----------------- REPORTS -----------------
@api_router.get("/reports")
def list_reports(db: Session = Depends(get_db)):
    reports = db.query(WeeklyReport).order_by(WeeklyReport.created_at.desc()).all()
    return [
        {
            "id": r.id,
            "title": r.report_title,
            "period_start": r.period_start.isoformat(),
            "period_end": r.period_end.isoformat(),
            "stats": r.stats_json,
            "filename": r.file_path.split("/")[-1].split("\\")[-1],
            "created_at": r.created_at.isoformat()
        } for r in reports
    ]

@api_router.post("/reports/generate")
def trigger_report_generation(db: Session = Depends(get_db)):
    return WeeklyReportGenerator.generate_report(db, days=7)

@api_router.get("/reports/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db)):
    r = db.query(WeeklyReport).filter(WeeklyReport.id == report_id).first()
    if not r or not os.path.exists(r.file_path):
        raise HTTPException(status_code=404, detail="Report file not found")
    return FileResponse(
        r.file_path, 
        filename=os.path.basename(r.file_path), 
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )

# ----------------- NOTIFICATIONS / TELEGRAM -----------------
@api_router.post("/notifications/telegram/test")
async def test_telegram_connection():
    """
    Dedicated connection test endpoint.
    Sends a test verification message to the configured Telegram chat.
    Does NOT create EmailRecord, ForensicCase, Campaign, or affect stats.
    """
    from app.notifications.telegram import TelegramNotifier
    result = await TelegramNotifier.send_test_message()
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Telegram test failed."))
    return result

# ----------------- CONNECTORS -----------------
@api_router.get("/connectors")
def list_connectors(db: Session = Depends(get_db)):
    standard_connectors = [
        {
            "id": "smtp-gateway-primary",
            "provider_type": "SMTP_GATEWAY",
            "account_email": "inbound-security@organization.local",
            "status": "CONNECTED",
            "sync_mode": "PRE_DELIVERY_INSPECTION_AND_FLAGGING",
            "description": "Port 1025 Pre-Delivery SMTP Security Proxy"
        },
        {
            "id": "gmail-oauth-1",
            "provider_type": "GMAIL",
            "account_email": "workspace-sec@example.com",
            "status": "NOT_CONFIGURED",
            "sync_mode": "PUBSUB_PUSH_MONITORING",
            "description": "Google Workspace / Gmail Retrospective Ingestion"
        },
        {
            "id": "m365-graph-1",
            "provider_type": "OUTLOOK",
            "account_email": "m365-audit@example.com",
            "status": "NOT_CONFIGURED",
            "sync_mode": "GRAPH_WEBHOOK_NOTIFICATIONS",
            "description": "Microsoft 365 / Outlook Graph API Connector"
        },
        {
            "id": "yahoo-imap-1",
            "provider_type": "YAHOO",
            "account_email": "corp-yahoo@example.com",
            "status": "NOT_CONFIGURED",
            "sync_mode": "IMAP_IDLE_OR_POLLING",
            "description": "Yahoo Mail / Generic IMAP Provider"
        }
    ]
    return standard_connectors
