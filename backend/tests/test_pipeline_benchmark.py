import pytest
import os
from app.config import settings
from app.core.evidence import Evidence
from app.engines.fusion import EvidenceFusionEngine
from app.engines.attachment_analyzer import AttachmentSecurityAnalyzer
from app.engines.threat_ml import ContentAnalysisEngine
from app.notifications.telegram import TelegramNotifier
from app.gateway.handler import InboundPipelineProcessor
from app.database.session import init_db
from tests.fixtures.test_emails import (
    FIXTURE_LEGITIMATE_BUSINESS,
    FIXTURE_AUTHENTICATED_BEC,
    FIXTURE_CREDENTIAL_PHISHING,
    FIXTURE_EXECUTIVE_IMPERSONATION
)

@pytest.fixture(scope="session", autouse=True)
def setup_db():
    init_db()

def test_semantic_deduplication_urgency():
    """
    Verifies that repeating urgency words 5 times does NOT create 5 compounding penalties.
    """
    text_single = "Please review the budget by tomorrow."
    text_repeated = "URGENT URGENT: Immediately act now and do this today without delay immediately."

    res_single = ContentAnalysisEngine.evaluate(text_single, {})
    res_repeated = ContentAnalysisEngine.evaluate(text_repeated, {})

    # Fuse evidence for single vs repeated
    fusion_single = EvidenceFusionEngine.fuse(res_single["evidence"])
    fusion_repeated = EvidenceFusionEngine.fuse(res_repeated["evidence"])

    # Both should be bounded to a single semantic group's category cap (CONTENT_NLP cap is 25)
    assert fusion_repeated["category_scores"]["CONTENT_NLP"] <= 25.0
    assert fusion_repeated["deduplicated_evidence_count"] <= 3

def test_mitigating_evidence_on_legitimate_newsletter():
    """
    Verifies that cryptographic pass results and aligned domains lower threat scores.
    """
    ev_with_auth = [
        Evidence(engine="AUTHENTICATION", type="SPF_PASS", semantic_group="auth_spf", severity=0.0, direction="MITIGATING", description="SPF PASS"),
        Evidence(engine="AUTHENTICATION", type="DKIM_PASS", semantic_group="auth_dkim", severity=0.0, direction="MITIGATING", description="DKIM PASS"),
        Evidence(engine="AUTHENTICATION", type="DMARC_PASS", semantic_group="auth_dmarc", severity=0.0, direction="MITIGATING", description="DMARC PASS"),
        Evidence(engine="CONTENT_NLP", type="URGENCY_PRESSURE", semantic_group="urgency_pressure", severity=0.5, direction="SUPPORTING", description="Sale ends today")
    ]
    ev_no_auth = [
        Evidence(engine="CONTENT_NLP", type="URGENCY_PRESSURE", semantic_group="urgency_pressure", severity=0.5, direction="SUPPORTING", description="Sale ends today")
    ]

    fusion_auth = EvidenceFusionEngine.fuse(ev_with_auth)
    fusion_no_auth = EvidenceFusionEngine.fuse(ev_no_auth)

    assert fusion_auth["final_risk_score"] < fusion_no_auth["final_risk_score"]
    assert fusion_auth["risk_severity"] == "LOW"

def test_double_extension_attachment_detection():
    attachments = [{
        "filename": "invoice_2026_march.pdf.exe",
        "content_type": "application/pdf",
        "size_bytes": 102400,
        "payload_bytes": b"MZ\x90\x00\x03\x00\x00\x00"
    }]
    res = AttachmentSecurityAnalyzer.analyze_attachments(attachments)
    assert res["has_double_extension"] is True
    assert res["has_dangerous_extension"] is True
    
    fusion = EvidenceFusionEngine.fuse(res["evidence"])
    assert fusion["final_risk_score"] >= 80.0
    assert fusion["threat_classification"] == "MALICIOUS_ATTACHMENT"

@pytest.mark.asyncio
async def test_telegram_unconfigured_safe_fallback():
    # Telegram notifier must return False safely when disabled, without raising exceptions
    from unittest.mock import patch
    with patch.object(settings, "TELEGRAM_ENABLED", False):
        sent = await TelegramNotifier.send_threat_alert(
            case_number="TR-TEST-001",
            sender="attacker@example.com",
            subject="Phishing Lure",
            verdict={"final_risk_score": 90.0, "risk_severity": "CRITICAL", "threat_classification": "PHISHING"}
        )
        assert sent is False

@pytest.mark.asyncio
async def test_benchmark_suite_accuracy_and_metrics():
    """
    Executes benchmark test suite against standardized test fixtures.
    """
    test_cases = [
        {"name": "Legitimate Business", "raw": FIXTURE_LEGITIMATE_BUSINESS, "expected_cat": "LEGITIMATE", "expected_sev": "LOW"},
        {"name": "Authenticated BEC", "raw": FIXTURE_AUTHENTICATED_BEC, "expected_cat": "BUSINESS_EMAIL_COMPROMISE", "expected_sev": ["HIGH", "CRITICAL"]},
        {"name": "Credential Phishing", "raw": FIXTURE_CREDENTIAL_PHISHING, "expected_cat": "CREDENTIAL_PHISHING", "expected_sev": ["HIGH", "CRITICAL"]},
        {"name": "Executive Impersonation", "raw": FIXTURE_EXECUTIVE_IMPERSONATION, "expected_cat": ["IMPERSONATION", "BUSINESS_EMAIL_COMPROMISE", "PHISHING"], "expected_sev": ["MEDIUM", "HIGH", "CRITICAL"]}
    ]

    passed = 0
    results_summary = []

    for tc in test_cases:
        rec = await InboundPipelineProcessor.process_raw_email(
            raw_bytes=tc["raw"],
            mail_from="test@example.com",
            rcpt_tos=["target@example.org"],
            source="SMTP_GATEWAY",
            is_demo=False
        )

        cat_match = (rec.threat_classification in tc["expected_cat"]) if isinstance(tc["expected_cat"], list) else (rec.threat_classification == tc["expected_cat"])
        sev_match = (rec.risk_severity in tc["expected_sev"]) if isinstance(tc["expected_sev"], list) else (rec.risk_severity == tc["expected_sev"])

        if cat_match and sev_match:
            passed += 1

        results_summary.append({
            "name": tc["name"],
            "score": rec.final_risk_score,
            "severity": rec.risk_severity,
            "classification": rec.threat_classification,
            "passed": cat_match and sev_match
        })

    accuracy = (passed / len(test_cases)) * 100.0
    print(f"\n=== TraceMail Pipeline Benchmark: {passed}/{len(test_cases)} Passed ({accuracy:.1f}%) ===")
    for r in results_summary:
        print(f"[{'PASS' if r['passed'] else 'FAIL'}] {r['name']} -> Risk: {r['score']} | Sev: {r['severity']} | Class: {r['classification']}")

    assert accuracy == 100.0
