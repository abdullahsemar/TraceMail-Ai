import pytest
from unittest.mock import patch, AsyncMock, MagicMock
import httpx
from app.config import settings
from app.notifications.telegram import TelegramNotifier
from app.notifications.manager import NotificationManager
from app.core.policy import PolicyEngine
from app.gateway.handler import InboundPipelineProcessor
from app.database.session import SessionLocal, init_db
from app.database.models import EmailRecord, ForensicCase
from tests.fixtures.test_emails import FIXTURE_AUTHENTICATED_BEC, FIXTURE_LEGITIMATE_BUSINESS

@pytest.fixture(autouse=True)
def reset_notification_cache():
    init_db()
    NotificationManager.clear_cache()
    yield
    NotificationManager.clear_cache()

def test_telegram_disabled_fallback():
    with patch.object(settings, "TELEGRAM_ENABLED", False):
        assert TelegramNotifier.is_configured() is False

def test_telegram_configuration_detection():
    with patch.object(settings, "TELEGRAM_ENABLED", True), \
         patch.object(settings, "TELEGRAM_BOT_TOKEN", "mock_bot_token_123"), \
         patch.object(settings, "TELEGRAM_CHAT_ID", "mock_chat_id_456"):
        assert TelegramNotifier.is_configured() is True

def test_telegram_policy_thresholds():
    # 1. LOW severity -> No alert
    verdict_low = {"risk_severity": "LOW", "final_risk_score": 10.0, "threat_classification": "LEGITIMATE"}
    policy_low = PolicyEngine.evaluate_policy(verdict_low)
    assert policy_low["should_alert_telegram"] is False

    # 2. MEDIUM severity -> No alert with default TELEGRAM_MIN_SEVERITY=HIGH
    with patch.object(settings, "TELEGRAM_MIN_SEVERITY", "HIGH"):
        verdict_med = {"risk_severity": "MEDIUM", "final_risk_score": 45.0, "threat_classification": "SUSPICIOUS"}
        policy_med = PolicyEngine.evaluate_policy(verdict_med)
        assert policy_med["should_alert_telegram"] is False

    # 3. HIGH severity -> Alert triggered
    verdict_high = {"risk_severity": "HIGH", "final_risk_score": 75.0, "threat_classification": "PHISHING"}
    policy_high = PolicyEngine.evaluate_policy(verdict_high)
    assert policy_high["should_alert_telegram"] is True

    # 4. CRITICAL severity -> Alert triggered
    verdict_crit = {"risk_severity": "CRITICAL", "final_risk_score": 95.0, "threat_classification": "CREDENTIAL_THEFT"}
    policy_crit = PolicyEngine.evaluate_policy(verdict_crit)
    assert policy_crit["should_alert_telegram"] is True

@pytest.mark.asyncio
async def test_telegram_network_failure_does_not_crash_pipeline():
    with patch.object(settings, "TELEGRAM_ENABLED", True), \
         patch.object(settings, "TELEGRAM_BOT_TOKEN", "mock_bot_token_123"), \
         patch.object(settings, "TELEGRAM_CHAT_ID", "mock_chat_id_456"), \
         patch("httpx.AsyncClient.post", side_effect=httpx.ConnectError("Network unreachable")):

        # High-risk BEC message triggers Telegram branch, which fails gracefully
        record = await InboundPipelineProcessor.process_raw_email(
            raw_bytes=FIXTURE_AUTHENTICATED_BEC,
            mail_from="ceo@vendor.com",
            rcpt_tos=["finance@corporate.com"],
            source="SMTP_GATEWAY"
        )
        assert record is not None
        assert record.risk_severity in ["HIGH", "CRITICAL"]

@pytest.mark.asyncio
async def test_duplicate_case_does_not_notify_twice():
    verdict = {
        "risk_severity": "HIGH",
        "threat_classification": "BUSINESS_EMAIL_COMPROMISE",
        "final_risk_score": 88.0,
        "threat_confidence": 0.9,
        "top_reasons": ["Urgent financial wire demand"]
    }
    
    with patch.object(TelegramNotifier, "send_threat_alert", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True

        # First dispatch
        res1 = await NotificationManager.dispatch_alerts(
            case_number="CASE-DEDUP-001",
            sender="attacker@spoof.com",
            subject="Wire Transfer",
            verdict=verdict,
            dedup_key="sha256_mock_hash_12345"
        )
        assert res1 is True
        assert mock_send.call_count == 1

        # Second dispatch with same dedup_key (e.g. Gmail re-sync or duplicate ingestion)
        res2 = await NotificationManager.dispatch_alerts(
            case_number="CASE-DEDUP-001",
            sender="attacker@spoof.com",
            subject="Wire Transfer",
            verdict=verdict,
            dedup_key="sha256_mock_hash_12345"
        )
        assert res2 is False
        assert mock_send.call_count == 1  # Not called again!

@pytest.mark.asyncio
async def test_connection_test_endpoint_does_not_create_entities():
    db = SessionLocal()
    initial_email_count = db.query(EmailRecord).count()
    initial_case_count = db.query(ForensicCase).count()
    db.close()

    with patch.object(settings, "TELEGRAM_ENABLED", True), \
         patch.object(settings, "TELEGRAM_BOT_TOKEN", "mock_bot_token_123"), \
         patch.object(settings, "TELEGRAM_CHAT_ID", "mock_chat_id_456"):

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            res = await TelegramNotifier.send_test_message()
            assert res["success"] is True
            assert res["status"] == "CONNECTED"
            assert "successfully" in res["message"].lower()

    # Confirm no entities were created
    db = SessionLocal()
    final_email_count = db.query(EmailRecord).count()
    final_case_count = db.query(ForensicCase).count()
    db.close()

    assert final_email_count == initial_email_count
    assert final_case_count == initial_case_count
