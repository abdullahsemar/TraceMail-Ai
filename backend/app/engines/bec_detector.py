import logging
from typing import Dict, Any, List, Optional
from app.core.evidence import Evidence

logger = logging.getLogger("tracemail.engines.bec_detector")

class SequentialBECDetector:
    """
    Research Principle 1: Sequential Detection Engine
    
    Research basis:
    - Asaf Cidon et al., "High Precision Detection of Business Email Compromise",
      USENIX Security 2019, Section 4.3 & Section 5:
      Splits BEC detection into:
      STAGE A: Impersonation / Metadata Analysis (sender identity, corporate domain status,
               historical name/address pairing, Reply-To frequency)
      STAGE B: Content + Link Analysis (financial request, wire transfer, urgency, suspicious URLs)
      
    Key Design Rules:
    - If Stage A indicates significant impersonation probability AND Stage B finds sensitive content/lures,
      strengthens Business Email Compromise classification.
    - Low impersonation probability does NOT prevent independent generic phishing, malware, or
      attachment detectors from executing.
    """

    @classmethod
    def evaluate_sequential_bec(
        cls,
        behavioral_results: Dict[str, Any],
        content_results: Dict[str, Any],
        header_results: Dict[str, Any],
        url_results: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        evidence_list: List[Evidence] = []

        impersonation_prob = float(behavioral_results.get("impersonation_probability", 0.0))
        sample_count = int(behavioral_results.get("sample_count", 0))
        baseline_maturity = behavioral_results.get("baseline_maturity", "COLD_START")
        
        detected_behaviors = content_results.get("detected_behaviors", [])
        has_financial_lure = any(b in ["PAYMENT_DIVERSION", "GIFT_CARD_FRAUD", "PII_THEFT_REQUEST"] for b in detected_behaviors)
        has_urgency_pressure = any(b in ["URGENCY_PRESSURE", "EXECUTIVE_PRESSURE", "SECRECY_REQUEST"] for b in detected_behaviors)
        has_rapport = "RAPPORT_AVAILABILITY" in detected_behaviors

        # URL features
        urls_analyzed = url_results.get("urls_analyzed", []) if url_results else []
        has_suspicious_url = any(u.get("is_suspicious") for u in urls_analyzed)

        # Stage A + Stage B Sequential Synthesis
        is_bec_candidate = False
        bec_confidence = 0.0
        reason = ""

        if impersonation_prob >= 0.40 and has_financial_lure:
            is_bec_candidate = True
            bec_confidence = min(0.98, 0.60 + (impersonation_prob * 0.35))
            reason = "High impersonation probability combined with financial routing modification request"
        elif impersonation_prob >= 0.30 and (has_urgency_pressure or has_rapport) and has_financial_lure:
            is_bec_candidate = True
            bec_confidence = 0.88
            reason = "Impersonation cues combined with executive urgency and wire/payment request"
        elif impersonation_prob >= 0.50 and (has_rapport or has_urgency_pressure):
            is_bec_candidate = True
            bec_confidence = 0.75
            reason = "Suspicious external identity pairing using executive rapport/availability lure"

        if is_bec_candidate:
            evidence_list.append(Evidence(
                engine="IDENTITY",
                type="SEQUENTIAL_BEC_SYNTHESIS",
                semantic_group="bec_reasoning",
                independence_group="sequential_bec",
                value={
                    "impersonation_probability": impersonation_prob,
                    "financial_lure": has_financial_lure,
                    "urgency": has_urgency_pressure,
                    "rapport": has_rapport
                },
                severity=0.92 if has_financial_lure else 0.75,
                confidence=bec_confidence,
                reliability=0.92,
                freshness=1.0,
                direction="SUPPORTING",
                description=f"Sequential BEC Detection: {reason} (Stage A Impersonation: {int(impersonation_prob * 100)}%)",
                source="SEQUENTIAL_BEC_DETECTOR",
                research_provenance="CIDON_2019_SEQUENTIAL_DETECTION"
            ))

        return {
            "is_bec_candidate": is_bec_candidate,
            "impersonation_probability": impersonation_prob,
            "stage_a_impersonation_score": impersonation_prob,
            "stage_b_content_risk": 0.85 if has_financial_lure else (0.50 if has_urgency_pressure else 0.10),
            "stage_b_link_risk": 0.80 if has_suspicious_url else 0.0,
            "bec_synthesis_confidence": bec_confidence,
            "methodology_note": "Sequential two-stage reasoning inspired by Cidon et al., USENIX Security 2019",
            "evidence": evidence_list
        }


# Backwards compatibility alias
BECDetectionEngine = SequentialBECDetector

