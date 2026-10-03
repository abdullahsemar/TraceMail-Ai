import math
from typing import Dict, Any, List, Optional
from collections import defaultdict
from app.core.evidence import Evidence
from app.core.policy import PolicyEngine

class EvidenceFusionEngine:
    """
    Research-Grounded Dependency-Aware Evidence Fusion Engine:
    
    Principles:
    - Evidence strength: severity * confidence * reliability * freshness
    - Independence Grouping & Diminishing Returns (prevents collinear signals from compounding)
    - Mitigating evidence reduces accumulated threat rather than contributing positive risk
    - Separate calculations for:
      * Threat Probability (0.0 - 1.0)
      * Evidence Confidence (0.0 - 1.0)
      * Impact Score (0.0 - 1.0)
      * Operational Risk Score (0 - 100)
    - Strict Verdict Consistency: LOW risk emails NEVER output threat classifications like
      CREDENTIAL_PHISHING or BUSINESS_EMAIL_COMPROMISE as their final classification.
    - Transparent Explainability: Top Supporting, Top Mitigating, and Baseline Uncertainties.
    """

    CATEGORY_WEIGHTS = {
        "CONTENT_NLP": 25.0,
        "IDENTITY": 15.0,
        "BEHAVIOR": 15.0,
        "AUTHENTICATION": 10.0,
        "URL": 10.0,
        "ATTACHMENT": 10.0,
        "DOMAIN": 10.0,
        "RELAY_INFRASTRUCTURE": 10.0,
        "THREAT_INTELLIGENCE": 10.0,
        "CAMPAIGN": 10.0
    }

    @classmethod
    def fuse(
        cls,
        evidence_items: List[Evidence],
        origin_assessment: Optional[Dict[str, Any]] = None,
        auth_results: Optional[Dict[str, Any]] = None,
        behavioral_results: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Fuses heterogeneous evidence objects and produces a consistent explainable verdict.
        """
        supporting_by_cat: Dict[str, List[Evidence]] = defaultdict(list)
        mitigating_by_cat: Dict[str, List[Evidence]] = defaultdict(list)
        uncertainties: List[str] = []

        # 1. Partition by Direction
        for ev in evidence_items:
            cat = ev.engine.upper()
            if cat not in cls.CATEGORY_WEIGHTS:
                cat = "CONTENT_NLP"

            if ev.direction == "SUPPORTING":
                supporting_by_cat[cat].append(ev)
            elif ev.direction == "MITIGATING":
                mitigating_by_cat[cat].append(ev)

        # Record behavioral baseline maturity uncertainties
        if behavioral_results:
            maturity = behavioral_results.get("baseline_maturity", "COLD_START")
            samples = behavioral_results.get("sample_count", 0)
            if maturity == "COLD_START":
                uncertainties.append(f"Cold-start sender baseline: only {samples} historical messages observed")
            elif maturity == "DEVELOPING":
                uncertainties.append(f"Developing behavioral baseline ({samples} messages)")

        # 2. Dependency-Aware Group Deduplication & Probabilistic Accumulation
        deduplicated_supporting: Dict[str, List[Evidence]] = {}
        category_risk_scores: Dict[str, float] = {}

        for cat, items in supporting_by_cat.items():
            # Group by independence_group (or semantic_group / type fallback)
            groups: Dict[str, List[Evidence]] = defaultdict(list)
            for it in items:
                grp = it.independence_group or it.semantic_group or it.type
                groups[grp].append(it)

            deduped_items: List[Evidence] = []
            group_strengths: List[float] = []

            for grp_name, grp_evs in groups.items():
                # Strongest finding in the group
                best_ev = max(grp_evs, key=lambda x: x.severity * x.confidence * x.reliability * x.freshness)
                deduped_items.append(best_ev)
                strength = best_ev.severity * best_ev.confidence * best_ev.reliability * best_ev.freshness
                group_strengths.append(min(1.0, max(0.0, strength)))

            deduplicated_supporting[cat] = deduped_items

            # Damped probabilistic union within category: 1 - prod(1 - 0.85 * strength_i)
            if group_strengths:
                prod_term = 1.0
                for s in group_strengths:
                    prod_term *= (1.0 - (s * 0.85))
                cat_accum = 1.0 - prod_term
            else:
                cat_accum = 0.0

            max_weight = cls.CATEGORY_WEIGHTS.get(cat, 10.0)
            category_risk_scores[cat] = cat_accum * max_weight

        # 3. Mitigating Factor Discounting (Applies as reducing factor)
        total_mitigating_strength = 0.0
        for cat, items in mitigating_by_cat.items():
            for m in items:
                m_strength = m.confidence * m.reliability * m.freshness * 5.0
                total_mitigating_strength += m_strength

        # 4. Multi-Factor Critical Threat Triggers Check
        all_supporting = [e for cat_evs in deduplicated_supporting.values() for e in cat_evs]
        
        has_payment_diversion = any(e.type in ["PAYMENT_DIVERSION", "GIFT_CARD_FRAUD"] for e in all_supporting)
        has_pii_request = any(e.type == "PII_THEFT_REQUEST" for e in all_supporting)
        has_credential_harvest = any(e.type in ["CREDENTIAL_REQUEST", "DISTILBERT_PHISHING_PROBABILITY"] for e in all_supporting)
        has_malicious_attachment = any(e.type in ["DANGEROUS_ATTACHMENT_EXTENSION", "DOUBLE_EXTENSION_SPOOFING", "ATTACHMENT_MIME_MISMATCH"] for e in all_supporting)
        has_lookalike_domain = any(e.type in ["BRAND_LOOKALIKE_DOMAIN", "BRAND_LOOKALIKE_URL", "DISPLAY_NAME_EMAIL_INJECTION"] for e in all_supporting)
        has_reply_to_mismatch = any(e.type in ["REPLY_TO_DOMAIN_MISMATCH", "UNUSUAL_REPLY_TO_DOMAIN"] for e in all_supporting)
        has_sequential_bec = any(e.type == "SEQUENTIAL_BEC_SYNTHESIS" for e in all_supporting)

        raw_score = sum(category_risk_scores.values())

        # Apply Mitigating Discount safely (cap discount at 65% of raw score if malicious indicators exist)
        discount = min(total_mitigating_strength, raw_score * 0.65) if (has_payment_diversion or has_malicious_attachment or has_sequential_bec) else min(total_mitigating_strength, raw_score * 0.90)
        accumulated_risk = max(0.0, raw_score - discount)

        # Specific Floor Enforcement for Confirmed Multi-Factor Attack Patterns
        if has_malicious_attachment:
            accumulated_risk = max(accumulated_risk, 85.0)
        elif has_sequential_bec or (has_payment_diversion and (has_reply_to_mismatch or has_lookalike_domain or raw_score >= 35.0)):
            accumulated_risk = max(accumulated_risk, 82.0)
        elif has_pii_request and (has_reply_to_mismatch or has_lookalike_domain or raw_score >= 30.0):
            accumulated_risk = max(accumulated_risk, 80.0)
        elif has_credential_harvest and (has_lookalike_domain or raw_score >= 32.0):
            accumulated_risk = max(accumulated_risk, 78.0)
        elif has_lookalike_domain and raw_score >= 25.0:
            accumulated_risk = max(accumulated_risk, 65.0)

        final_risk_score = round(max(0.0, min(100.0, accumulated_risk)), 1)

        # 5. Determine Threat Probability, Impact Score, and Evidence Confidence
        threat_probability = round(min(1.0, final_risk_score / 100.0), 3)

        # Impact Score based on attack consequence
        if has_payment_diversion or has_sequential_bec or has_malicious_attachment:
            impact_score = 0.95 # Direct financial loss or endpoint compromise
        elif has_credential_harvest or has_pii_request:
            impact_score = 0.90 # Account takeover or identity theft
        elif has_lookalike_domain or has_reply_to_mismatch:
            impact_score = 0.70 # Brand/identity deception
        elif final_risk_score >= 30.0:
            impact_score = 0.40 # Anomaly / unverified origin
        else:
            impact_score = 0.05 # Low impact / benign communication

        # Evidence Confidence
        if all_supporting:
            evidence_confidence = round(sum(e.confidence * e.reliability for e in all_supporting) / len(all_supporting), 2)
        else:
            evidence_confidence = 0.92 if not all_supporting else 0.70

        # 6. Strict Verdict Consistency & Final Classification Mapping
        # Consistency Rule: Severity and Classification MUST be mutually consistent with Risk Score!
        if final_risk_score >= 80.0:
            risk_severity = "CRITICAL"
        elif final_risk_score >= 60.0:
            risk_severity = "HIGH"
        elif final_risk_score >= 30.0:
            risk_severity = "MEDIUM"
        else:
            risk_severity = "LOW"

        # Map Final Classification strictly bounded by severity:
        if risk_severity in ["HIGH", "CRITICAL"]:
            if has_malicious_attachment:
                threat_classification = "MALICIOUS_ATTACHMENT"
            elif has_sequential_bec or has_payment_diversion:
                threat_classification = "BUSINESS_EMAIL_COMPROMISE"
            elif has_pii_request:
                threat_classification = "BUSINESS_EMAIL_COMPROMISE"
            elif has_credential_harvest:
                threat_classification = "CREDENTIAL_PHISHING"
            elif has_lookalike_domain:
                threat_classification = "IMPERSONATION"
            else:
                threat_classification = "PHISHING"
        elif risk_severity == "MEDIUM":
            if has_lookalike_domain:
                threat_classification = "IMPERSONATION"
            else:
                threat_classification = "SUSPICIOUS_ANOMALY"
        else:
            # LOW severity: MUST NEVER show CREDENTIAL_PHISHING or BEC as final verdict!
            if final_risk_score < 15.0:
                threat_classification = "LEGITIMATE"
            else:
                threat_classification = "NO_CONFIRMED_THREAT"

        # 7. Explainability Lists (Top Supporting, Top Mitigating, Uncertainties)
        top_supporting = [e.description for e in sorted(all_supporting, key=lambda x: x.severity * x.confidence, reverse=True)[:6]]
        all_mitigating_evs = [e for cat_evs in mitigating_by_cat.values() for e in cat_evs]
        top_mitigating = [e.description for e in sorted(all_mitigating_evs, key=lambda x: x.confidence * x.reliability, reverse=True)[:5]]

        if not top_supporting and threat_classification in ["LEGITIMATE", "NO_CONFIRMED_THREAT"]:
            top_supporting = ["Normal organizational communication baseline verified"]

        # Origin / Infrastructure Confidence
        origin = origin_assessment or {}
        infra_conf = origin.get("origin_confidence_score", 40.0) / 100.0
        geo_conf = 0.85 if origin.get("country") and origin.get("country") != "UNKNOWN" else 0.15

        policy_eval = PolicyEngine.evaluate_policy({
            "final_risk_score": final_risk_score,
            "risk_severity": risk_severity,
            "threat_classification": threat_classification
        })

        return {
            "final_risk_score": final_risk_score,
            "operational_risk_score": final_risk_score,
            "risk_severity": risk_severity,
            "threat_classification": threat_classification,
            "policy_action": policy_eval.get("action_taken", "ALLOW"),
            "threat_probability": threat_probability,
            "evidence_confidence": evidence_confidence,
            "impact_score": impact_score,
            "infrastructure_confidence": round(infra_conf, 2),
            "geolocation_confidence": round(geo_conf, 2),
            "top_reasons": top_supporting,
            "top_supporting_evidence": top_supporting,
            "mitigating_reasons": top_mitigating,
            "top_mitigating_evidence": top_mitigating,
            "uncertainties": uncertainties,
            "category_scores": {k: round(v, 1) for k, v in category_risk_scores.items()},
            "deduplicated_evidence_count": len(all_supporting),
            "raw_evidence_count": len(evidence_items)
        }
