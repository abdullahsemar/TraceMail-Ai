import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database.session import SessionLocal, init_db
from app.gateway.handler import InboundPipelineProcessor
from tests.fixtures.test_emails import FIXTURE_LEGITIMATE_BUSINESS, FIXTURE_AUTHENTICATED_BEC

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    init_db()
    db = SessionLocal()
    # Clean test data if needed
    yield
    db.close()

def test_health_endpoint_truthful_structure():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "backend" in data
    assert "database" in data
    assert "gmail" in data
    assert "smtp_gateway" in data
    assert "downstream_smtp" in data
    assert "telegram" in data
    assert "distilbert" in data

def test_dashboard_stats_endpoint():
    response = client.get("/api/dashboard/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_emails" in data
    assert "today" in data
    assert "safe_emails" in data
    assert "suspicious_emails" in data
    assert "high_threats" in data
    assert "critical_threats" in data
    assert "gmail_count" in data
    assert "smtp_count" in data
    assert "flagged_for_review" in data

def test_smtp_status_and_downstream_test():
    # 1. Status check
    res_status = client.get("/api/smtp/status")
    assert res_status.status_code == 200
    s_data = res_status.json()
    assert "gateway_enabled" in s_data
    assert "gateway_port" in s_data
    assert "downstream_configured" in s_data
    assert "flagged_count" in s_data

    # 2. Downstream connection test without fake email
    res_test = client.post("/api/smtp/test-downstream")
    assert res_test.status_code == 200
    t_data = res_test.json()
    assert "status" in t_data
    assert "host" in t_data

@pytest.mark.asyncio
async def test_emails_inbox_pagination_and_source_filters():
    # Ingest 1 Gmail and 1 SMTP email
    gmail_record = await InboundPipelineProcessor.process_raw_email(
        raw_bytes=FIXTURE_LEGITIMATE_BUSINESS,
        mail_from="alice.harper@example.com",
        rcpt_tos=["bob@corporate.org"],
        source="GMAIL_API"
    )

    smtp_record = await InboundPipelineProcessor.process_raw_email(
        raw_bytes=FIXTURE_AUTHENTICATED_BEC,
        mail_from="ceo@example.com",
        rcpt_tos=["finance@target.org"],
        source="SMTP_GATEWAY"
    )

    # 1. Test pagination
    res = client.get("/api/emails?page=1&page_size=10")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert "total_pages" in data
    assert data["total"] >= 2
    assert len(data["items"]) <= 10

    # 2. Test Source Filter: GMAIL
    res_gmail = client.get("/api/emails?source=GMAIL")
    assert res_gmail.status_code == 200
    gmail_items = res_gmail.json()["items"]
    assert len(gmail_items) >= 1
    for item in gmail_items:
        assert "GMAIL" in item["source"].upper()

    # 3. Test Source Filter: SMTP
    res_smtp = client.get("/api/emails?source=SMTP")
    assert res_smtp.status_code == 200
    smtp_items = res_smtp.json()["items"]
    assert len(smtp_items) >= 1
    for item in smtp_items:
        assert "SMTP" in item["source"].upper()

    # 4. Test Search Filter
    res_search = client.get("/api/emails?search=alice.harper")
    assert res_search.status_code == 200
    search_items = res_search.json()["items"]
    assert len(search_items) >= 1
    assert "alice.harper" in search_items[0]["mail_from"]

    # 5. Gmail action semantics check
    assert gmail_record.processing_state in ["MONITORED", "ALLOWED", "FLAGGED", "DELIVERED"]
    assert "QUARANTINE" not in gmail_record.action_taken

    # 6. SMTP threat action semantics check
    assert smtp_record.risk_severity in ["HIGH", "CRITICAL"]
    assert smtp_record.action_taken == "FLAG_AND_ALERT"
