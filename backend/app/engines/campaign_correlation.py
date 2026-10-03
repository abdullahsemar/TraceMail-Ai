import re
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set, Tuple
from sqlalchemy.orm import Session
from app.core.evidence import Evidence
from app.database.models import Campaign, CampaignLink, EmailRecord

logger = logging.getLogger("tracemail.engines.campaign_correlation")

class FuzzyCampaignCorrelationEngine:
    """
    TraceMail Extension: Cross-Platform Fuzzy Campaign Correlation Engine.
    
    Architectural distinction:
    - SHA-256: Immutable cryptographic integrity & exact artifact matching.
    - Fuzzy Fingerprint (SimHash/MinHash): Near-duplicate fuzzy clustering across
      polymorphic lures, subject variants, and shared threat infrastructure.
      
    NOTE: This is a TraceMail extension and is NOT from Cidon et al. 2019.
    """

    # Configurable similarity correlation thresholds
    SIMILARITY_REVIEW_THRESHOLD = 0.70
    SIMILARITY_STRONG_THRESHOLD = 0.85

    @classmethod
    def compute_text_simhash(cls, text: str, hash_bits: int = 64) -> str:
        """
        Computes a 64-bit SimHash fingerprint for normalized text tokens.
        Near-identical texts produce small Hamming distances.
        """
        if not text or not text.strip():
            return "0" * (hash_bits // 4)

        # 1. Normalize text: remove numbers, punctuation, lowercase
        clean = re.sub(r'\d+', '', text.lower())
        tokens = re.findall(r'\b[a-zA-Z]{3,}\b', clean)
        if not tokens:
            return "0" * (hash_bits // 4)

        # 2. Token frequency weighting
        freqs: Dict[str, int] = {}
        for t in tokens:
            freqs[t] = freqs.get(t, 0) + 1

        # 3. 64-bit vector accumulation
        v = [0] * hash_bits
        for token, weight in freqs.items():
            # Hash token with MD5 to get 128-bit hash, take lower 64 bits
            h_int = int(hashlib.md5(token.encode('utf-8')).hexdigest()[:16], 16)
            for i in range(hash_bits):
                bit = (h_int >> i) & 1
                if bit == 1:
                    v[i] += weight
                else:
                    v[i] -= weight

        # 4. Generate fingerprint hex
        fingerprint = 0
        for i in range(hash_bits):
            if v[i] > 0:
                fingerprint |= (1 << i)

        return f"{fingerprint:016x}"

    @classmethod
    def simhash_similarity(cls, hash1: str, hash2: str, hash_bits: int = 64) -> float:
        """
        Calculates similarity coefficient (0.0 to 1.0) based on Hamming distance.
        """
        if not hash1 or not hash2 or len(hash1) != len(hash2):
            return 0.0
        try:
            val1 = int(hash1, 16)
            val2 = int(hash2, 16)
            xor_val = val1 ^ val2
            hamming_distance = bin(xor_val).count('1')
            similarity = 1.0 - (hamming_distance / float(hash_bits))
            return max(0.0, min(1.0, similarity))
        except ValueError:
            return 0.0

    @classmethod
    def extract_campaign_features(cls, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extracts multi-dimensional features for fuzzy campaign clustering.
        """
        body_text = email_data.get("body_text", "")
        subject = email_data.get("subject", "")
        sender_email = email_data.get("sender_email", "")
        sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
        reply_to = email_data.get("reply_to", "") or ""
        reply_to_domain = reply_to.split("@")[-1].lower() if "@" in reply_to else ""

        # Normalize subject template (replace numbers, dates, references)
        subject_template = re.sub(r'#?\d+', '<NUM>', subject.lower().strip())
        subject_template = re.sub(r'\b(mon|tue|wed|thu|fri|sat|sun|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\b', '<DATE>', subject_template)

        # Extract URL pattern hostnames
        url_domains = []
        for u in email_data.get("urls", []):
            raw = u.get("url", "")
            match = re.search(r'https?://([^/:\s]+)', raw)
            if match:
                url_domains.append(match.group(1).lower())

        # Extract attachment SHA-256s
        att_hashes = [a.get("sha256") for a in email_data.get("attachments", []) if a.get("sha256")]

        simhash = cls.compute_text_simhash(f"{subject}\n{body_text}")

        return {
            "simhash": simhash,
            "subject_template": subject_template,
            "sender_domain": sender_domain,
            "reply_to_domain": reply_to_domain,
            "url_domains": sorted(list(set(url_domains))),
            "attachment_hashes": att_hashes,
            "threat_classification": email_data.get("threat_classification", "UNKNOWN")
        }

    @classmethod
    def correlate_with_existing_campaigns(
        cls,
        db: Session,
        email_data: Dict[str, Any],
        min_risk_threshold: float = 40.0
    ) -> Dict[str, Any]:
        """
        Evaluates incoming email against active campaigns in the database.
        Emits Standardized Evidence V2 when significant near-duplicate similarity is observed.
        """
        evidence_list: List[Evidence] = []
        features = cls.extract_campaign_features(email_data)
        current_simhash = features["simhash"]
        current_dom = features["sender_domain"]
        current_reply_dom = features["reply_to_domain"]
        current_urls = set(features["url_domains"])
        current_att_hashes = set(features["attachment_hashes"])

        active_campaigns = db.query(Campaign).filter(Campaign.status == "ACTIVE").all()

        best_campaign = None
        best_similarity = 0.0
        shared_indicators: Dict[str, Any] = {}

        for camp in active_campaigns:
            camp_ind = camp.shared_indicators or {}
            camp_simhash = camp_ind.get("simhash", "")
            camp_urls = set(camp_ind.get("url_domains", []))
            camp_dom = camp_ind.get("sender_domain", "")
            camp_reply_dom = camp_ind.get("reply_to_domain", "")
            camp_att_hashes = set(camp_ind.get("attachment_hashes", []))

            # 1. Compute text structural similarity via SimHash
            text_sim = cls.simhash_similarity(current_simhash, camp_simhash)

            # 2. Infrastructure & artifact overlaps
            url_overlap = len(current_urls.intersection(camp_urls)) > 0
            domain_overlap = bool(current_dom and current_dom == camp_dom)
            reply_overlap = bool(current_reply_dom and current_reply_dom == camp_reply_dom)
            att_overlap = len(current_att_hashes.intersection(camp_att_hashes)) > 0

            # Composite fuzzy correlation score
            score = (text_sim * 0.50) + \
                    (0.20 if url_overlap else 0.0) + \
                    (0.15 if domain_overlap else 0.0) + \
                    (0.10 if reply_overlap else 0.0) + \
                    (0.25 if att_overlap else 0.0)
            score = min(1.0, score)

            if score > best_similarity:
                best_similarity = score
                best_campaign = camp
                shared_indicators = {
                    "text_similarity": round(text_sim, 2),
                    "shared_urls": list(current_urls.intersection(camp_urls)),
                    "shared_domain": current_dom if domain_overlap else None,
                    "shared_reply_to": current_reply_dom if reply_overlap else None,
                    "shared_attachments": list(current_att_hashes.intersection(camp_att_hashes))
                }

        # If similarity meets threshold, produce Evidence
        matched_campaign_id = None
        if best_campaign and best_similarity >= cls.SIMILARITY_REVIEW_THRESHOLD:
            matched_campaign_id = best_campaign.id
            is_strong = best_similarity >= cls.SIMILARITY_STRONG_THRESHOLD

            evidence_list.append(Evidence(
                engine="CAMPAIGN",
                type="FUZZY_CAMPAIGN_CLUSTER_MATCH",
                semantic_group="campaign_correlation",
                independence_group="campaign_intel",
                value=best_campaign.name,
                severity=0.85 if is_strong else 0.65,
                confidence=round(best_similarity, 2),
                reliability=0.90,
                freshness=1.0,
                direction="SUPPORTING",
                description=f"Correlated with active threat campaign '{best_campaign.name}' (Fuzzy similarity: {round(best_similarity * 100, 1)}%)",
                source="FUZZY_CAMPAIGN_ENGINE",
                research_provenance="TRACEMAIL_FUZZY_CORRELATION"
            ))

            # Update campaign stats in DB
            best_campaign.total_incidents += 1
            best_campaign.last_seen = datetime.now(timezone.utc)
            db.commit()

        elif not best_campaign and email_data.get("final_risk_score", 0.0) >= min_risk_threshold:
            # Optionally create a new candidate campaign fingerprint for emerging clusters
            classification = email_data.get("threat_classification", "SUSPICIOUS")
            if classification in ["BUSINESS_EMAIL_COMPROMISE", "CREDENTIAL_PHISHING", "PHISHING", "IMPERSONATION"]:
                new_camp = Campaign(
                    name=f"Campaign-{features['sender_domain'] or 'Polymorphic'}-{datetime.now(timezone.utc).strftime('%m%d')}",
                    threat_type=classification,
                    description=f"Emerging {classification} campaign cluster detected via fuzzy analysis",
                    total_incidents=1,
                    status="ACTIVE",
                    correlation_confidence=0.85,
                    shared_indicators={
                        "simhash": current_simhash,
                        "sender_domain": current_dom,
                        "reply_to_domain": current_reply_dom,
                        "url_domains": features["url_domains"],
                        "attachment_hashes": features["attachment_hashes"]
                    }
                )
                db.add(new_camp)
                db.commit()
                matched_campaign_id = new_camp.id

        return {
            "matched_campaign_id": matched_campaign_id,
            "campaign_name": best_campaign.name if best_campaign else None,
            "similarity_score": round(best_similarity, 3),
            "shared_indicators": shared_indicators,
            "evidence": evidence_list
        }


# Backwards compatibility alias
CampaignCorrelationEngine = FuzzyCampaignCorrelationEngine

