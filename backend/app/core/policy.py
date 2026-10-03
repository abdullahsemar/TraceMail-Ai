import logging
from typing import Dict, Any, Optional
from app.config import settings

logger = logging.getLogger("tracemail.core.policy")

class PolicyEngine:
    """
    Non-Quarantining Policy Engine:
    Translates Multi-Engine Risk Verdicts into Operational Actions.
    
    Principles:
    - TraceMail operates as a NON-QUARANTINING pre-delivery inspection, flagging,
      warning, alerting and forensic investigation platform.
    - ALL messages remain deliverable to the downstream MTA unless downstream delivery itself fails.
    
    New Action Model:
    - LOW:      ALLOW           -> Forward normally downstream
    - MEDIUM:   FLAG            -> Add TraceMail warning metadata headers, forward downstream
    - HIGH:     FLAG_AND_ALERT  -> Add strong warning headers, create case in Review Queue, Telegram alert, forward
    - CRITICAL: FLAG_AND_ALERT  -> Add critical warning headers, create case in Review Queue, Telegram alert, forward
    """

    @classmethod
    def evaluate_policy(
        cls,
        verdict: Dict[str, Any],
        source: str = "SMTP_GATEWAY"
    ) -> Dict[str, Any]:
        severity = verdict.get("risk_severity", "LOW")
        risk_score = verdict.get("final_risk_score", 0.0)
        classification = verdict.get("threat_classification", "LEGITIMATE")

        action_taken = "ALLOW"
        action_reason = "Clean communication baseline; approved for downstream delivery."
        processing_state = "DELIVERED"
        should_forward_downstream = True
        should_quarantine = False # Completely removed from TraceMail policy path
        should_alert_telegram = False
        should_create_case = False

        # 1. Telegram Notification Policy Evaluation (HIGH / CRITICAL)
        min_sev = getattr(settings, "TELEGRAM_MIN_SEVERITY", "HIGH").upper()
        if min_sev == "ALL":
            should_alert_telegram = True
        elif min_sev == "MEDIUM" and severity in ["MEDIUM", "HIGH", "CRITICAL"]:
            should_alert_telegram = True
        elif severity in ["HIGH", "CRITICAL"]:
            should_alert_telegram = True

        # 2. Forensic Case / Review Queue Creation Policy
        if severity in ["HIGH", "CRITICAL"]:
            should_create_case = True
            processing_state = "REVIEW_REQUIRED"
        elif severity == "MEDIUM" or risk_score >= 30.0:
            should_create_case = True
            processing_state = "FLAGGED"
        else:
            processing_state = "DELIVERED"

        # 3. Action Mapping by Severity (Symmetric across SMTP and Ingested sources)
        if severity in ["HIGH", "CRITICAL"]:
            action_taken = "FLAG_AND_ALERT"
            action_reason = f"High-risk {classification} detected (Risk: {risk_score}/100); warning headers injected, SOC alerted."
        elif severity == "MEDIUM":
            action_taken = "FLAG"
            action_reason = f"Suspicious behavioral or identity anomaly ({classification}); warning headers injected."
        else:
            action_taken = "ALLOW"
            action_reason = "Verified clean communication baseline; forwarded downstream."

        # In Gmail API post-delivery mode, forwarding downstream is not applicable
        if source in ["GMAIL", "GMAIL_API"]:
            should_forward_downstream = False

        return {
            "action": action_taken,
            "action_taken": action_taken,
            "action_reason": action_reason,
            "processing_state": processing_state,
            "should_forward_downstream": should_forward_downstream,
            "should_quarantine": should_quarantine,
            "should_alert_telegram": should_alert_telegram,
            "should_create_case": should_create_case
        }
