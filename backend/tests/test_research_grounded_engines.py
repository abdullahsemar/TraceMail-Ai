import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.session import Base
from app.core.evidence import Evidence
from app.engines.behavioral_intelligence import BehavioralIntelligenceEngine, normalize_display_name
from app.engines.bec_detector import SequentialBECDetector, BECDetectionEngine
from app.engines.fusion import EvidenceFusionEngine
from app.engines.campaign_correlation import FuzzyCampaignCorrelationEngine, CampaignCorrelationEngine
from app.core.policy import PolicyEngine
from app.gateway.downstream import DownstreamSMTPRelay

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

def test_name_normalization_and_nicknames():
    # Research basis: Cidon et al. 2019, Section 4.4, [36]
    assert normalize_display_name("Bill Clinton") == "william clinton"
    assert normalize_display_name("Bob Smith, Jr.") == "robert smith"
    assert normalize_display_name("Dr. Jane Doe CEO") == "jane doe"
    assert normalize_display_name("Smith, Jane") == "jane smith"

def test_cidon_reply_to_mismatch_and_known_service(db_session):
    # 1. Suspicious Reply-To mismatch to personal email (Cidon et al. 2019 Table 3)
    res_mismatch = BehavioralIntelligenceEngine.evaluate_behavioral_intelligence(
        db=db_session,
        sender_email="ceo@example.com",
        sender_display_name="CEO John",
        reply_to="ceo.private@outlook.com",
        recipients=["finance@corporate.org"]
    )
    mismatch_ev = [e for e in res_mismatch["evidence"] if e.type == "REPLY_TO_MISMATCH"]
    assert len(mismatch_ev) > 0
    assert mismatch_ev[0].direction == "SUPPORTING"
    assert mismatch_ev[0].research_provenance == "CIDON_2019_TABLE3"

    # 2. Known legitimate Reply-To service (e.g., LinkedIn, Salesforce) provides MITIGATING factor
    res_legit = BehavioralIntelligenceEngine.evaluate_behavioral_intelligence(
        db=db_session,
        sender_email="hr@example.com",
        sender_display_name="HR Team",
        reply_to="notifications@reply.linkedin.com",
        recipients=["employee@corporate.org"]
    )
    legit_ev = [e for e in res_legit["evidence"] if e.type == "KNOWN_LEGITIMATE_REPLY_TO_SERVICE"]
    assert len(legit_ev) > 0
    assert legit_ev[0].direction == "MITIGATING"
    assert legit_ev[0].research_provenance == "CIDON_2019_TABLE3"

def test_cold_start_behavioral_maturity(db_session):
    # Query an unseen sender in fresh DB
    res = BehavioralIntelligenceEngine.evaluate_behavioral_intelligence(
        db=db_session,
        sender_email="vendor@unseen-domain.com",
        sender_display_name="New External Vendor",
        reply_to="",
        recipients=["finance@corporate.org"]
    )
    assert res["baseline_maturity"] in ["COLD_START", "DEVELOPING"]
    assert res["behavioral_confidence"] <= 0.50
    # Cold start must NOT generate severe threat by itself
    for ev in res["evidence"]:
        if ev.type in ["UNSEEN_NAME_ADDRESS_PAIR", "NEW_SENDER_FOR_RECIPIENT"]:
            assert ev.severity <= 0.60

def test_sequential_bec_detection_synthesis():
    behavioral_res = {
        "impersonation_probability": 0.75,
        "sample_count": 2,
        "baseline_maturity": "COLD_START"
    }
    content_res = {
        "detected_behaviors": ["PAYMENT_DIVERSION", "URGENCY_PRESSURE"],
        "is_suspicious": True
    }
    header_res = {"evidence": []}
    
    analysis = SequentialBECDetector.evaluate_sequential_bec(
        behavioral_results=behavioral_res,
        content_results=content_res,
        header_results=header_res
    )
    assert analysis["is_bec_candidate"] is True
    assert analysis["impersonation_probability"] == 0.75
    assert analysis["stage_b_content_risk"] > 0.7
    assert len(analysis["evidence"]) > 0
    assert "Cidon et al." in analysis["methodology_note"]
    assert analysis["evidence"][0].research_provenance == "CIDON_2019_SEQUENTIAL_DETECTION"

def test_verdict_consistency_low_risk():
    # If risk is LOW, threat_classification must be LEGITIMATE or NO_CONFIRMED_THREAT, NEVER CREDENTIAL_PHISHING
    low_ev = [
        Evidence(
            engine="AUTHENTICATION",
            type="SPF_PASS",
            description="SPF passed",
            semantic_group="auth_spf",
            severity=0.0,
            direction="MITIGATING"
        ),
        Evidence(
            engine="CONTENT_AI",
            type="URGENCY_PRESSURE",
            description="Urgency keyword",
            semantic_group="urgency_pressure",
            severity=0.2, # Very weak candidate cue
            direction="SUPPORTING"
        )
    ]
    fusion = EvidenceFusionEngine.fuse(low_ev)
    assert fusion["operational_risk_score"] < 40.0
    assert fusion["risk_severity"] == "LOW"
    assert fusion["threat_classification"] in ["LEGITIMATE", "NO_CONFIRMED_THREAT"]
    assert fusion["policy_action"] == "ALLOW"

def test_fuzzy_campaign_simhash_vs_sha256():
    import hashlib
    text1 = "Urgent: Please wire $45,000 to our updated vendor bank account immediately. Thanks, CEO."
    text2 = "URGENT: Please wire $45,000 to our updated vendor bank account immediately! Thanks, CEO."
    
    sha1 = hashlib.sha256(text1.encode('utf-8')).hexdigest()
    sha2 = hashlib.sha256(text2.encode('utf-8')).hexdigest()
    
    # Cryptographic SHA-256 differs (due to punctuation/casing)
    assert sha1 != sha2
    
    # But SimHash near-duplicate similarity is very high (near 1.0)
    simhash1 = FuzzyCampaignCorrelationEngine.compute_text_simhash(text1)
    simhash2 = FuzzyCampaignCorrelationEngine.compute_text_simhash(text2)
    sim = FuzzyCampaignCorrelationEngine.simhash_similarity(simhash1, simhash2)
    assert sim >= 0.85

def test_downstream_warning_headers_injection():
    verdict = {
        "final_risk_score": 85.0,
        "operational_risk_score": 85.0,
        "risk_severity": "HIGH",
        "threat_classification": "BUSINESS_EMAIL_COMPROMISE",
        "policy_action": "FLAG_AND_ALERT"
    }
    
    raw_in = b"From: attacker@bad.com\r\nTo: target@corp.com\r\nSubject: Invoice\r\n\r\nBody text"
    enriched = DownstreamSMTPRelay.inject_security_headers(raw_in, verdict, case_id="CASE-2026-TEST")
    
    text_out = enriched.decode("utf-8", errors="replace")
    assert "X-TraceMail-Analyzed: true" in text_out
    assert "X-TraceMail-Case-ID: CASE-2026-TEST" in text_out
    assert "X-TraceMail-Risk-Score: 85" in text_out
    assert "X-TraceMail-Severity: HIGH" in text_out
    assert "X-TraceMail-Classification: BUSINESS_EMAIL_COMPROMISE" in text_out
    assert "X-TraceMail-Flagged: true" in text_out

def test_policy_no_quarantine_action():
    # Verify PolicyEngine never emits QUARANTINE, HOLD, or DELETE
    for score, sev in [(10, "LOW"), (55, "MEDIUM"), (85, "HIGH"), (95, "CRITICAL")]:
        pol = PolicyEngine.evaluate_policy({
            "operational_risk_score": score,
            "final_risk_score": score,
            "risk_severity": sev,
            "threat_classification": "BUSINESS_EMAIL_COMPROMISE" if score > 70 else "LEGITIMATE"
        })
        assert pol["action"] in ["ALLOW", "FLAG", "FLAG_AND_ALERT"]
        assert pol["action"] not in ["QUARANTINE", "HOLD", "DELETE"]
