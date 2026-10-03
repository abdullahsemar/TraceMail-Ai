import pytest
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.session import Base, init_db
from app.parsers.rfc822_parser import RFC822Parser
from app.parsers.header_forensics import HeaderForensics
from app.parsers.relay_tracer import RelayTracer
from app.engines.threat_ml import HybridThreatEngine, DistilBERTThreatClassifier
from app.engines.origin import OriginTraceabilityEngine
from app.engines.attachment_analyzer import AttachmentSecurityAnalyzer
from app.engines.url_intel import URLDomainIntelligenceEngine
from app.engines.domain_intel import DomainIntelligenceProvider
from app.engines.fusion import EvidenceFusionEngine
from app.gateway.handler import InboundPipelineProcessor
from app.core.audit import AuditLogger
from app.reporting.docx_generator import WeeklyReportGenerator
from tests.fixtures.test_emails import (
    FIXTURE_LEGITIMATE_BUSINESS,
    FIXTURE_AUTHENTICATED_BEC,
    FIXTURE_CREDENTIAL_PHISHING,
    FIXTURE_EXECUTIVE_IMPERSONATION
)

@pytest.fixture(scope="session", autouse=True)
def setup_db():
    init_db()

def test_rfc822_parser():
    parsed = RFC822Parser.parse_raw_bytes(FIXTURE_LEGITIMATE_BUSINESS)
    assert parsed["sender_email"] == "alice.harper@example.com"
    assert "Q3 Financial Planning" in parsed["subject"]
    assert "agenda for tomorrow" in parsed["body_text"]

def test_header_forensics_auth():
    parsed = RFC822Parser.parse_raw_bytes(FIXTURE_LEGITIMATE_BUSINESS)
    forensics = HeaderForensics.analyze_headers(parsed)
    assert forensics["spf"]["result"] == "PASS"
    assert forensics["dkim"]["result"] == "PASS"
    assert len(forensics["evidence"]) > 0
    # Should have mitigating SPF and DKIM evidence
    mitigating = [e for e in forensics["evidence"] if e.direction == "MITIGATING"]
    assert len(mitigating) >= 2

def test_distilbert_content_evaluation():
    engine = HybridThreatEngine()
    parsed = RFC822Parser.parse_raw_bytes(FIXTURE_AUTHENTICATED_BEC)
    forensics = HeaderForensics.analyze_headers(parsed)
    context = {**parsed, "auth_results": forensics, "header_analysis": forensics}
    res = engine.evaluate(context)
    
    assert "PAYMENT_DIVERSION" in res["detected_behaviors"]
    assert len(res["evidence"]) > 0

def test_origin_and_ssrf_safety():
    assert URLDomainIntelligenceEngine.is_ssrf_safe("127.0.0.1") is False
    assert URLDomainIntelligenceEngine.is_ssrf_safe("169.254.169.254") is False
    assert URLDomainIntelligenceEngine.is_ssrf_safe("10.0.0.5") is False
    assert URLDomainIntelligenceEngine.is_ssrf_safe("example.com") is True
    
    # Verify origin provider returns UNKNOWN when MaxMind database is unconfigured (no fabricated location)
    origin = OriginTraceabilityEngine.assess_origin("198.51.100.25", 2)
    assert origin["country"] == "UNKNOWN"
    assert origin["origin_confidence_score"] > 0
    assert "Observable Infrastructure" in origin["infrastructure_label"]

def test_relay_tracer_ipv4_and_ipv6():
    raw_headers = {
        "Received": [
            "from mail.example.com ([2001:db8:85a3::8a2e:370:7334]) by mx.example.org with ESMTP; Mon, 15 Sep 2026 09:30:00 +0000",
            "from client.local ([192.168.1.50]) by mail.example.com with ESMTP; Mon, 15 Sep 2026 09:29:50 +0000"
        ]
    }
    trace = RelayTracer.trace_relays(raw_headers)
    assert trace["total_hops"] == 2
    assert trace["earliest_observable_ip"] == "2001:db8:85a3::8a2e:370:7334"
    assert trace["earliest_ip_version"] == 6

def test_domain_lookalike_detection():
    dom_res = DomainIntelligenceProvider.analyze_domain("login-microsoft-security.xyz")
    supporting = [e for e in dom_res["evidence"] if e.type == "BRAND_LOOKALIKE_DOMAIN"]
    assert len(supporting) > 0
    assert supporting[0].severity >= 0.80

def test_audit_hash_chain_integrity():
    test_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=test_engine)
    Session = sessionmaker(bind=test_engine)
    db = Session()
    try:
        AuditLogger.log_event(db, "TEST_EVENT_1", "RESOURCE_1", actor="TESTER")
        AuditLogger.log_event(db, "TEST_EVENT_2", "RESOURCE_2", actor="TESTER")
        verification = AuditLogger.verify_chain_integrity(db)
        assert verification["status"] == "VALID"
        assert verification["total_records"] == 2
    finally:
        db.close()

@pytest.mark.asyncio
async def test_end_to_end_inbound_pipeline_smtp_flag_and_forward():
    record = await InboundPipelineProcessor.process_raw_email(
        raw_bytes=FIXTURE_AUTHENTICATED_BEC,
        mail_from="ceo@example.com",
        rcpt_tos=["finance@example.org"],
        source="SMTP_GATEWAY",
        is_demo=False
    )
    
    assert record.threat_classification == "BUSINESS_EMAIL_COMPROMISE"
    assert record.risk_severity in ["HIGH", "CRITICAL"]
    assert record.action_taken == "FLAG_AND_ALERT"
    assert record.processing_state in ["FLAGGED", "REVIEW_REQUIRED", "DELIVERY_FAILED"]
    assert len(record.evidence_sha256) == 64

@pytest.mark.asyncio
async def test_end_to_end_legitimate_email_allowed():
    record = await InboundPipelineProcessor.process_raw_email(
        raw_bytes=FIXTURE_LEGITIMATE_BUSINESS,
        mail_from="alice.harper@example.com",
        rcpt_tos=["bob.smith@example.org"],
        source="SMTP_GATEWAY",
        is_demo=False
    )
    
    assert record.threat_classification == "LEGITIMATE"
    assert record.risk_severity == "LOW"
    assert record.action_taken == "ALLOW"
    assert record.processing_state in ["DELIVERED", "DELIVERY_FAILED"]
