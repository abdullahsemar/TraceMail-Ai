import re
import unicodedata
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set, Tuple
from sqlalchemy.orm import Session
from app.core.evidence import Evidence
from app.database.models import SenderBaseline

logger = logging.getLogger("tracemail.engines.behavioral_intelligence")

class BehavioralIntelligenceEngine:
    """
    Research-Grounded Organizational Behavioral Intelligence Engine:
    
    Research basis:
    - Cidon et al., USENIX Security 2019, Table 3 & Section 4.4:
      Historical organizational email statistics, sender-name/email pairing frequency,
      Reply-To frequency, corporate domain membership, known legitimate Reply-To services,
      and name/nickname normalization.
      
    TraceMail extensions:
    - Calibrated baseline maturity levels (COLD_START, DEVELOPING, MATURE).
    - Multi-factor anomaly scoring with mitigating historical familiarity.
    - Standardized Evidence V2 emission with research provenance tags.
    - Account takeover behavioral graph fanout indicators.
    """

    # Common English nickname aliases dictionary (Cidon et al. 2019 §4.4)
    NICKNAME_MAP: Dict[str, str] = {
        "bill": "william",
        "billy": "william",
        "will": "william",
        "willy": "william",
        "bob": "robert",
        "bobby": "robert",
        "rob": "robert",
        "robbie": "robert",
        "jim": "james",
        "jimmy": "james",
        "dick": "richard",
        "rick": "richard",
        "ricky": "richard",
        "rich": "richard",
        "dave": "david",
        "davey": "david",
        "mike": "michael",
        "mikey": "michael",
        "dan": "daniel",
        "danny": "daniel",
        "tom": "thomas",
        "tommy": "thomas",
        "chris": "christopher",
        "alex": "alexander",
        "tony": "anthony",
        "joe": "joseph",
        "joey": "joseph",
        "jack": "john",
        "johnny": "john",
        "chuck": "charles",
        "charlie": "charles",
        "steve": "stephen",
        "steven": "stephen",
        "ed": "edward",
        "eddie": "edward",
        "ted": "edward",
        "andy": "andrew",
        "matt": "matthew",
        "ben": "benjamin",
        "benny": "benjamin",
        "sam": "samuel",
        "sammy": "samuel",
        "ken": "kenneth",
        "kenny": "kenneth",
        "larry": "lawrence",
        "ron": "ronald",
        "ronnie": "ronald",
        "al": "albert",
        "albie": "albert",
        "art": "arthur",
        "artie": "arthur"
    }

    # Configurable Known Legitimate Reply-To Services Registry (Cidon et al. 2019 §4.4)
    # These services legitimately send on behalf of employees with different Reply-To addresses.
    KNOWN_REPLY_TO_SERVICES: Set[str] = {
        "linkedin.com", "salesforce.com", "zendesk.com", "hubspot.com",
        "servicenow.com", "atlassian.net", "jira.com", "docusign.net",
        "docusign.com", "workday.com", "mailchimp.com", "intercom-mail.com",
        "greenhouse.io", "lever.co", "slack.com", "zoom.us", "qualtrics.com",
        "freshdesk.com", "mandrillapp.com", "sendgrid.net", "marketo.net"
    }

    # Common corporate role names that should be tracked for generic sender spoofing
    GENERIC_ROLE_NAMES: Set[str] = {
        "it support", "it helpdesk", "human resources", "hr department",
        "payroll", "finance team", "billing department", "security operations",
        "chief executive officer", "executive office", "legal counsel",
        "admin team", "facilities"
    }

    # Known organization corporate domains (configured or inferred)
    CORPORATE_DOMAINS: Set[str] = {
        "organization.local", "example.com", "example.org", "corporate.org", "company.local"
    }

    @classmethod
    def normalize_name(cls, raw_name: str) -> Dict[str, Any]:
        """
        Research-inspired name normalization (Cidon et al. 2019 §4.4):
        - Strips titles, honorifics, and corporate suffixes (e.g. Jr., Sr., III, CEO)
        - Unicode normalization (NFKD)
        - Extracts primary tokens, strips middle initials
        - Standardizes first/last and resolves canonical nicknames
        """
        if not raw_name:
            return {"normalized": "", "tokens": [], "canonical_first": "", "canonical_last": ""}

        # 1. Unicode NFKD normalization
        nfkd_form = unicodedata.normalize('NFKD', raw_name)
        text = "".join([c for c in nfkd_form if not unicodedata.combining(c)])

        # 2. Strip embedded email addresses in display name if present
        text = re.sub(r'[\w\.-]+@[\w\.-]+', '', text)

        # 3. Handle prefixes/honorifics (Dr., Mr., Mrs., Ms., Prof.)
        prefixes = {"dr", "mr", "mrs", "ms", "prof", "rev", "capt"}
        
        # Check if comma indicates "Last, First" format (e.g. "Smith, Jane" -> "Jane Smith")
        if ',' in text:
            parts = [p.strip() for p in text.split(',', 1)]
            if len(parts) == 2 and parts[0] and parts[1]:
                # Reverse into First Last
                text = f"{parts[1]} {parts[0]}"

        # Clean special characters and lowercase
        text = re.sub(r'[^\w\s]', ' ', text).lower().strip()

        # 4. Remove common suffixes and titles
        suffixes = {"jr", "sr", "ii", "iii", "iv", "phd", "md", "esq", "cpa", "ceo", "cfo", "cto", "coo", "vp", "hr"}
        raw_tokens = [t for t in text.split() if t and t not in suffixes and t not in prefixes]

        if not raw_tokens:
            return {"normalized": "", "tokens": [], "canonical_first": "", "canonical_last": "", "original": raw_name}

        first = raw_tokens[0]
        last = raw_tokens[-1] if len(raw_tokens) > 1 else ""

        # Filter single-character middle initials if > 2 tokens
        if len(raw_tokens) > 2:
            meaningful = [t for t in raw_tokens if len(t) > 1]
            if len(meaningful) >= 2:
                first = meaningful[0]
                last = meaningful[-1]

        # Resolve nickname mapping
        canonical_first = cls.NICKNAME_MAP.get(first, first)

        normalized_full = f"{canonical_first} {last}".strip()
        return {
            "normalized": normalized_full,
            "tokens": raw_tokens,
            "canonical_first": canonical_first,
            "canonical_last": last,
            "original": raw_name
        }

    @classmethod
    def is_corporate_domain(cls, domain: str) -> bool:
        """
        Checks whether the sender domain matches configured organizational corporate domains.
        """
        clean_domain = domain.strip().lower()
        return clean_domain in cls.CORPORATE_DOMAINS or any(
            clean_domain.endswith(f".{cd}") for cd in cls.CORPORATE_DOMAINS
        )

    @classmethod
    def is_known_reply_to_service(cls, reply_to_domain: str) -> bool:
        """
        Checks if Reply-To domain is a recognized legitimate enterprise SaaS service.
        """
        clean_rep = reply_to_domain.strip().lower()
        return any(clean_rep == s or clean_rep.endswith(f".{s}") for s in cls.KNOWN_REPLY_TO_SERVICES)

    @classmethod
    def evaluate_behavioral_intelligence(
        cls,
        db: Session,
        sender_email: str,
        sender_display_name: str,
        reply_to: str,
        recipients: List[str],
        observed_ip: str = "",
        observed_asn: str = "",
        observed_country: str = ""
    ) -> Dict[str, Any]:
        """
        Full behavioral intelligence evaluation across organizational communication patterns.
        Emits Standardized Evidence V2 with research provenance citations.
        """
        evidence_list: List[Evidence] = []
        anomalies: List[str] = []
        mitigating_factors: List[str] = []

        sender_email_clean = sender_email.strip().lower()
        sender_domain = sender_email_clean.split("@")[-1] if "@" in sender_email_clean else ""
        reply_to_clean = reply_to.strip().lower() if reply_to else ""
        reply_to_domain = reply_to_clean.split("@")[-1] if "@" in reply_to_clean else ""

        norm_sender = cls.normalize_name(sender_display_name)
        sender_name_norm = norm_sender["normalized"]

        is_corp_sender = cls.is_corporate_domain(sender_domain)

        # 1. Query Sender Baseline from Database
        baseline = db.query(SenderBaseline).filter(SenderBaseline.sender_email == sender_email_clean).first()
        now_dt = datetime.now(timezone.utc)

        sample_count = baseline.total_messages_seen if baseline else 0
        first_seen_dt = baseline.first_seen if baseline else now_dt

        # Compute Baseline Maturity (Cold-Start vs Developing vs Mature)
        if sample_count < 5:
            maturity = "COLD_START"
            behavioral_confidence = 0.25
        elif sample_count < 25:
            maturity = "DEVELOPING"
            behavioral_confidence = 0.65
        else:
            maturity = "MATURE"
            behavioral_confidence = 0.90

        # Feature 1: Corporate Domain Alignment (Cidon et al. 2019 Table 3)
        if is_corp_sender:
            evidence_list.append(Evidence(
                engine="BEHAVIOR",
                type="CORPORATE_DOMAIN_SENDER",
                semantic_group="sender_identity_history",
                independence_group="domain_membership",
                value=sender_domain,
                severity=0.0,
                confidence=0.95,
                reliability=0.95,
                freshness=1.0,
                direction="MITIGATING",
                description=f"Sender domain '{sender_domain}' matches recognized organizational corporate domain",
                source="BEHAVIORAL_BASELINE",
                research_provenance="CIDON_2019_TABLE3"
            ))
            mitigating_factors.append("Sender from corporate domain")

        # Feature 2 & 5: Reply-To Divergence and Known Service Check (Cidon et al. 2019 Table 3 & §4.4)
        if reply_to_clean and reply_to_clean != sender_email_clean:
            is_known_service = cls.is_known_reply_to_service(reply_to_domain)
            if is_known_service:
                # Mitigating evidence: Known legitimate enterprise service (Cidon et al. 2019 §4.4)
                evidence_list.append(Evidence(
                    engine="BEHAVIOR",
                    type="KNOWN_LEGITIMATE_REPLY_TO_SERVICE",
                    semantic_group="reply_to_anomaly",
                    independence_group="reply_to_identity",
                    value=reply_to_domain,
                    severity=0.0,
                    confidence=0.90,
                    reliability=0.90,
                    freshness=1.0,
                    direction="MITIGATING",
                    description=f"Reply-To domain '{reply_to_domain}' belongs to verified legitimate enterprise SaaS provider",
                    source="BEHAVIORAL_PROVIDER_REGISTRY",
                    research_provenance="CIDON_2019_TABLE3"
                ))
                mitigating_factors.append(f"Reply-To is verified enterprise service ({reply_to_domain})")
            else:
                if reply_to_clean != sender_email_clean:
                    anomalies.append(f"Reply-To directs response to external address '{reply_to_clean}'")
                    evidence_list.append(Evidence(
                        engine="BEHAVIOR",
                        type="REPLY_TO_MISMATCH",
                        semantic_group="reply_to_anomaly",
                        independence_group="reply_to_identity",
                        value=reply_to,
                        severity=0.75,
                        confidence=0.95,
                        reliability=0.90,
                        freshness=1.0,
                        direction="SUPPORTING",
                        description=f"Reply-To address '{reply_to}' redirects replies away from sender '{sender_email}'",
                        source="BEHAVIORAL_BASELINE",
                        research_provenance="CIDON_2019_TABLE3"
                    ))

        # Feature 3: Historical Sender-Name and Sender-Address Pairing (Cidon et al. 2019 Table 3)
        if not baseline:
            # Cold-start or new sender
            if sender_name_norm and not is_corp_sender:
                anomalies.append("New external sender-name and email address pairing observed")
                evidence_list.append(Evidence(
                    engine="BEHAVIOR",
                    type="UNSEEN_NAME_ADDRESS_PAIR",
                    semantic_group="sender_identity_history",
                    independence_group="sender_pairing",
                    value=f"{sender_name_norm} <{sender_email_clean}>",
                    severity=0.45,
                    confidence=behavioral_confidence,
                    reliability=0.85,
                    freshness=1.0,
                    direction="SUPPORTING",
                    description=f"Sender identity pairing '{sender_display_name}' <{sender_email_clean}> has no prior history in organization",
                    source="BEHAVIORAL_BASELINE",
                    research_provenance="CIDON_2019_TABLE3"
                ))

            # Record baseline initial state
            baseline = SenderBaseline(
                sender_email=sender_email_clean,
                sender_domain=sender_domain,
                observed_ips=[observed_ip] if observed_ip else [],
                observed_asns=[observed_asn] if observed_asn else [],
                observed_countries=[observed_country] if observed_country else [],
                typical_reply_to_domains=[reply_to_domain] if reply_to_domain else [],
                typical_recipients=recipients or [],
                total_messages_seen=1,
                first_seen=now_dt,
                last_seen=now_dt
            )
            db.add(baseline)
            db.commit()

        else:
            # Existing sender: Check historical pairing and familiarity
            if sample_count >= 10:
                evidence_list.append(Evidence(
                    engine="BEHAVIOR",
                    type="KNOWN_NAME_ADDRESS_PAIR",
                    semantic_group="sender_identity_history",
                    independence_group="sender_pairing",
                    value=sender_email_clean,
                    severity=0.0,
                    confidence=behavioral_confidence,
                    reliability=0.90,
                    freshness=1.0,
                    direction="MITIGATING",
                    description=f"Established sender identity with {sample_count} verified historical messages",
                    source="BEHAVIORAL_BASELINE",
                    research_provenance="CIDON_2019_TABLE3"
                ))
                mitigating_factors.append(f"Established sender history ({sample_count} messages)")

            # Check for infrastructure / behavioral drift
            ips = list(baseline.observed_ips or [])
            asns = list(baseline.observed_asns or [])
            countries = list(baseline.observed_countries or [])
            reply_domains = list(baseline.typical_reply_to_domains or [])
            known_recipients = set(baseline.typical_recipients or [])

            # Check recipient familiarity
            current_rcpt_set = set(r.strip().lower() for r in recipients if r)
            unseen_recipients = current_rcpt_set - known_recipients
            if unseen_recipients and sample_count >= 15:
                # Internal Account Takeover / Fanout Signal (Cidon et al. 2019 §6.1)
                if is_corp_sender and len(unseen_recipients) > 3:
                    anomalies.append(f"Potential account takeover fanout: Internal sender contacting {len(unseen_recipients)} unseen recipients")
                    evidence_list.append(Evidence(
                        engine="BEHAVIOR",
                        type="ACCOUNT_TAKEOVER_FANOUT_ANOMALY",
                        semantic_group="recipient_graph",
                        independence_group="behavioral_fanout",
                        value=list(unseen_recipients),
                        severity=0.82,
                        confidence=behavioral_confidence,
                        reliability=0.88,
                        freshness=1.0,
                        direction="SUPPORTING",
                        description=f"Internal corporate sender suddenly contacted {len(unseen_recipients)} previously uncontacted recipients (fanout anomaly)",
                        source="BEHAVIORAL_GRAPH",
                        research_provenance="CIDON_2019_TEXT_CLASSIFIER_CONCEPT"
                    ))
                else:
                    anomalies.append("New recipient relationship for established sender")
                    evidence_list.append(Evidence(
                        engine="BEHAVIOR",
                        type="NEW_SENDER_FOR_RECIPIENT",
                        semantic_group="recipient_graph",
                        independence_group="recipient_familiarity",
                        value=list(unseen_recipients),
                        severity=0.35,
                        confidence=behavioral_confidence,
                        reliability=0.80,
                        freshness=1.0,
                        direction="SUPPORTING",
                        description=f"First recorded communication between sender and recipient(s): {', '.join(list(unseen_recipients)[:2])}",
                        source="BEHAVIORAL_GRAPH",
                        research_provenance="CIDON_2019_TABLE3"
                    ))
            elif not unseen_recipients and sample_count >= 5:
                mitigating_factors.append("Established sender-recipient communication relationship")
                evidence_list.append(Evidence(
                    engine="BEHAVIOR",
                    type="KNOWN_SENDER_RECIPIENT_RELATIONSHIP",
                    semantic_group="recipient_graph",
                    independence_group="recipient_familiarity",
                    value=recipients,
                    severity=0.0,
                    confidence=behavioral_confidence,
                    reliability=0.88,
                    freshness=1.0,
                    direction="MITIGATING",
                    description="Established sender-recipient communication history in organizational baseline",
                    source="BEHAVIORAL_GRAPH",
                    research_provenance="CIDON_2019_TABLE3"
                ))

            # Check infrastructure anomalies
            if observed_ip and observed_ip not in ips and sample_count >= 10:
                anomalies.append(f"Unusual origin IP infrastructure: {observed_ip}")
                evidence_list.append(Evidence(
                    engine="BEHAVIOR",
                    type="UNUSUAL_ORIGIN_IP",
                    semantic_group="infrastructure_baseline",
                    independence_group="origin_anomaly",
                    value=observed_ip,
                    severity=0.40,
                    confidence=behavioral_confidence,
                    reliability=0.85,
                    freshness=1.0,
                    direction="SUPPORTING",
                    description=f"Origin IP '{observed_ip}' not observed in sender's historical baseline",
                    source="BEHAVIORAL_BASELINE",
                    research_provenance="CIDON_2019_TABLE3"
                ))
                ips.append(observed_ip)

            if observed_country and countries and observed_country not in countries and sample_count >= 10:
                anomalies.append(f"Unusual origin country: '{observed_country}'")
                evidence_list.append(Evidence(
                    engine="BEHAVIOR",
                    type="UNUSUAL_ORIGIN_COUNTRY",
                    semantic_group="infrastructure_baseline",
                    independence_group="origin_anomaly",
                    value=observed_country,
                    severity=0.55,
                    confidence=behavioral_confidence,
                    reliability=0.85,
                    freshness=1.0,
                    direction="SUPPORTING",
                    description=f"Sending origin country '{observed_country}' diverges from typical historical countries ({', '.join(countries)})",
                    source="BEHAVIORAL_BASELINE",
                    research_provenance="CIDON_2019_TABLE3"
                ))
                countries.append(observed_country)

            # Update baseline
            if observed_ip and observed_ip not in ips:
                ips.append(observed_ip)
            if observed_asn and observed_asn not in asns:
                asns.append(observed_asn)
            if observed_country and observed_country not in countries:
                countries.append(observed_country)
            if reply_to_domain and reply_to_domain not in reply_domains:
                reply_domains.append(reply_to_domain)

            baseline.observed_ips = ips
            baseline.observed_asns = asns
            baseline.observed_countries = countries
            baseline.typical_reply_to_domains = reply_domains
            baseline.typical_recipients = list(known_recipients.union(current_rcpt_set))
            baseline.total_messages_seen += 1
            baseline.last_seen = now_dt
            db.commit()

        # Compute Impersonation Probability (Stage A Score - Cidon et al. 2019 §4.3)
        # Combines name-address mismatch, non-corporate sender, reply-to anomaly
        impersonation_score = 0.0
        if not is_corp_sender and norm_sender["normalized"]:
            # External sender using a recognized executive or internal corporate name
            if any(r in sender_display_name.lower() for r in cls.GENERIC_ROLE_NAMES):
                impersonation_score += 0.70
            elif not baseline or sample_count < 3:
                impersonation_score += 0.45
            else:
                impersonation_score += 0.15

        if reply_to_clean and reply_to_clean != sender_email_clean and not cls.is_known_reply_to_service(reply_to_domain):
            impersonation_score += 0.35

        impersonation_probability = min(1.0, round(impersonation_score, 2))

        return {
            "impersonation_probability": impersonation_probability,
            "is_corporate_sender": is_corp_sender,
            "sample_count": sample_count,
            "baseline_maturity": maturity,
            "behavioral_confidence": behavioral_confidence,
            "normalized_name": norm_sender,
            "anomalies": anomalies,
            "mitigating_factors": mitigating_factors,
            "evidence": evidence_list
        }


def normalize_display_name(raw_name: str) -> str:
    """Convenience helper for research name normalization returning canonical full name string."""
    res = BehavioralIntelligenceEngine.normalize_name(raw_name)
    return res.get("normalized", "")

