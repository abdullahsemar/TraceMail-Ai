import logging
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from app.database.session import SessionLocal
from app.database.models import EmailRecord, ForensicCase
from app.engines.threat_intel import ThreatIntelligenceProvider
from app.core.audit import AuditLogger
from app.core.events import broadcaster

logger = logging.getLogger("tracemail.retrospective")

class ContinuousRetrospectiveScanner:
    @classmethod
    async def run_rescan(cls) -> dict:
        db: Session = SessionLocal()
        try:
            lookback_cutoff = datetime.now(timezone.utc) - timedelta(days=30)
            emails = db.query(EmailRecord).filter(EmailRecord.created_at >= lookback_cutoff).all()
            
            rescanned_count = len(emails)
            updated_cases_count = 0
            retrospective_alerts = []
            
            for email in emails:
                sender_domain = email.mail_from.split("@")[-1] if "@" in email.mail_from else ""
                domain_intel = ThreatIntelligenceProvider.check_domain_reputation(sender_domain)
                
                origin_ip = email.origin_assessment.earliest_observable_ip if email.origin_assessment else None
                ip_intel = ThreatIntelligenceProvider.check_ip_reputation(origin_ip) if origin_ip else {"status": "UNKNOWN"}
                
                newly_flagged = False
                reasons = []
                
                if domain_intel.get("status") == "KNOWN_BAD" and email.risk_severity != "CRITICAL":
                    newly_flagged = True
                    reasons.append(f"Retrospective Intel Hit: Sender domain '{sender_domain}' now flagged as KNOWN_BAD on threat feed")
                    
                if ip_intel.get("status") == "KNOWN_BAD" and email.risk_severity != "CRITICAL":
                    newly_flagged = True
                    reasons.append(f"Retrospective Intel Hit: Origin IP '{origin_ip}' now listed as malicious infrastructure")

                if newly_flagged:
                    updated_cases_count += 1
                    email.final_risk_score = max(email.final_risk_score, 88.0)
                    email.risk_severity = "CRITICAL"
                    email.action_reason = f"Re-scored via Retrospective Threat Intelligence: {'; '.join(reasons)}"
                    
                    existing_case = db.query(ForensicCase).filter(ForensicCase.email_id == email.id).first()
                    if existing_case:
                        existing_case.status = "OPEN"
                        existing_case.priority = "CRITICAL"
                        existing_case.notes = (existing_case.notes or "") + f"\n[Retrospective Alert]: {'; '.join(reasons)}"
                    else:
                        case_num = f"RETRO-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{email.id[:6].upper()}"
                        db.add(ForensicCase(
                            case_number=case_num,
                            email_id=email.id,
                            status="OPEN",
                            priority="CRITICAL",
                            summary=f"Retrospective threat match for {email.subject}"
                        ))
                        
                    AuditLogger.log_event(
                        db=db,
                        event_type="RETROSPECTIVE_THREAT_REOPENED",
                        target_resource=email.gateway_message_id,
                        details={"reasons": reasons, "new_risk": email.final_risk_score}
                    )
                    
                    alert_payload = {
                        "id": email.id,
                        "gateway_message_id": email.gateway_message_id,
                        "subject": email.subject,
                        "sender": email.mail_from,
                        "risk_score": email.final_risk_score,
                        "severity": "CRITICAL",
                        "top_reasons": reasons,
                        "type": "RETROSPECTIVE_HIT"
                    }
                    retrospective_alerts.append(alert_payload)
                    await broadcaster.broadcast("RETROSPECTIVE_ALERT", alert_payload)

            db.commit()
            logger.info(f"Retrospective scan completed: {rescanned_count} emails checked, {updated_cases_count} cases reopened.")
            return {
                "rescanned_count": rescanned_count,
                "reopened_cases_count": updated_cases_count,
                "alerts": retrospective_alerts
            }
        finally:
            db.close()
