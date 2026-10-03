import pytest
import os
import json
import base64
from unittest.mock import patch, MagicMock
from app.connectors.gmail import GmailConnector
from app.gateway.handler import InboundPipelineProcessor
from tests.fixtures.test_emails import FIXTURE_AUTHENTICATED_BEC

def test_gmail_connector_configuration_check():
    connector = GmailConnector()
    assert isinstance(connector.is_configured(), bool)
    assert isinstance(connector.is_connected(), bool)

def test_gmail_oauth_config_reads_from_settings():
    from app.config import get_google_oauth_config, settings
    with patch.object(settings, "GOOGLE_CLIENT_ID", "test-env-client-id"), \
         patch.object(settings, "GOOGLE_CLIENT_SECRET", "test-env-secret"), \
         patch.object(settings, "GOOGLE_REDIRECT_URI", "http://localhost:8000/api/connectors/gmail/callback"):
        cfg = get_google_oauth_config()
        assert cfg is not None
        assert cfg["client_id"] == "test-env-client-id"
        assert cfg["client_secret"] == "test-env-secret"
        assert cfg["redirect_uri"] == "http://localhost:8000/api/connectors/gmail/callback"

def test_gmail_oauth_url_generation():
    connector = GmailConnector()
    with patch("app.connectors.gmail.get_google_oauth_config", return_value={
        "client_id": "test-client-id.apps.googleusercontent.com",
        "client_secret": "test-secret",
        "redirect_uri": "http://localhost:8000/api/connectors/gmail/callback"
    }):
        assert connector.is_configured() is True
        auth_url = connector.get_authorization_url(state="test_state_123")
        assert "accounts.google.com/o/oauth2/v2/auth" in auth_url
        assert "client_id=test-client-id" in auth_url
        assert "state=test_state_123" in auth_url
        assert "gmail.readonly" in auth_url

@pytest.mark.asyncio
async def test_gmail_message_routed_through_unified_pipeline():
    # Simulate a raw message retrieved from Gmail API
    record = await InboundPipelineProcessor.process_raw_email(
        raw_bytes=FIXTURE_AUTHENTICATED_BEC,
        mail_from="ceo@example.com",
        rcpt_tos=["target-gmail-inbox@example.org"],
        source="GMAIL",
        connection_id="gmail-primary"
    )

    # Verify message is analyzed by the SAME forensic pipeline
    assert record.source == "GMAIL"
    assert record.threat_classification == "BUSINESS_EMAIL_COMPROMISE"
    assert record.risk_severity in ["HIGH", "CRITICAL"]
    assert record.action_taken == "FLAG_AND_ALERT"
    assert record.processing_state in ["REVIEW_REQUIRED", "FLAGGED"]
    assert len(record.evidence_sha256) == 64
