import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Integer, Float, Text, Boolean, DateTime, ForeignKey, Enum as SQLEnum, JSON
)
from sqlalchemy.orm import relationship
from app.database.session import Base

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(128), unique=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    role = Column(String(32), default="SOC_ANALYST")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class MailConnection(Base):
    __tablename__ = "mail_connections"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    provider_type = Column(String(32), nullable=False)
    account_email = Column(String(128), nullable=False)
    status = Column(String(32), default="CONNECTED")
    sync_mode = Column(String(32), default="NEAR_REALTIME")
    last_sync_at = Column(DateTime, nullable=True)
    credentials_json = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class EmailRecord(Base):
    __tablename__ = "emails"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    gateway_message_id = Column(String(128), index=True, nullable=False)
    source = Column(String(32), default="SMTP_GATEWAY")
    connection_id = Column(String(36), ForeignKey("mail_connections.id"), nullable=True)
    
    mail_from = Column(String(256), nullable=False, index=True)
    rcpt_to = Column(Text, nullable=False)
    subject = Column(Text, nullable=True)
    sender_display_name = Column(String(256), nullable=True)
    reply_to = Column(String(256), nullable=True)
    return_path = Column(String(256), nullable=True)
    date_header = Column(String(128), nullable=True)
    
    processing_state = Column(String(32), default="DELIVERED") # DELIVERED, FLAGGED, REVIEW_REQUIRED, DELIVERY_FAILED
    review_status = Column(String(32), default="UNREVIEWED")   # UNREVIEWED, IN_REVIEW, CONFIRMED_THREAT, FALSE_POSITIVE, RESOLVED
    evidence_sha256 = Column(String(64), nullable=False, index=True)
    evidence_file_path = Column(String(256), nullable=False)
    
    sentinel_score = Column(Float, default=0.0)
    sentinel_decision = Column(String(32), default="ALLOW_FAST")
    
    final_risk_score = Column(Float, default=0.0)
    risk_severity = Column(String(32), default="LOW")
    threat_classification = Column(String(64), default="LEGITIMATE")
    confidence_score = Column(Float, default=0.0)
    threat_probability = Column(Float, default=0.0)
    evidence_confidence = Column(Float, default=0.0)
    impact_score = Column(Float, default=0.0)
    origin_confidence = Column(Float, default=0.0)
    
    recommended_action = Column(String(32), default="ALLOW")
    action_taken = Column(String(32), default="ALLOW") # ALLOW, FLAG, FLAG_AND_ALERT
    action_reason = Column(Text, nullable=True)
    
    is_demo_fixture = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    analyzed_at = Column(DateTime, nullable=True)
    
    evidence = relationship("EmailEvidence", back_populates="email", uselist=False)
    analysis = relationship("AnalysisResult", back_populates="email", uselist=False)
    auth_results = relationship("AuthenticationResult", back_populates="email", uselist=False)
    relay_hops = relationship("RelayHop", back_populates="email")
    origin_assessment = relationship("OriginAssessment", back_populates="email", uselist=False)
    iocs = relationship("IOC", back_populates="email")
    case = relationship("ForensicCase", back_populates="email", uselist=False)
    feedback_entries = relationship("AnalystFeedback", back_populates="email")
    quarantine_entry = relationship("QuarantineRecord", back_populates="email", uselist=False) # Historical deprecated

class EmailEvidence(Base):
    __tablename__ = "email_evidence"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False, unique=True)
    sha256_hash = Column(String(64), nullable=False)
    raw_size_bytes = Column(Integer, nullable=False)
    storage_path = Column(String(256), nullable=False)
    headers_json = Column(JSON, nullable=True)
    extracted_body_text = Column(Text, nullable=True)
    extracted_body_html_sanitized = Column(Text, nullable=True)
    attachments_json = Column(JSON, nullable=True)
    urls_json = Column(JSON, nullable=True)
    preserved_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    email = relationship("EmailRecord", back_populates="evidence")

class AnalysisResult(Base):
    __tablename__ = "analysis_results"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False, unique=True)
    model_version = Column(String(32), default="TraceMail-Fusion-v2.0")
    detected_behaviors = Column(JSON, default=list)
    supporting_reasons = Column(JSON, default=list)
    mitigating_reasons = Column(JSON, default=list)
    uncertainties = Column(JSON, default=list)
    
    nlp_score = Column(Float, default=0.0)
    header_anomaly_score = Column(Float, default=0.0)
    baseline_anomaly_score = Column(Float, default=0.0)
    url_intel_score = Column(Float, default=0.0)
    ip_reputation_score = Column(Float, default=0.0)
    
    fusion_summary = Column(Text, nullable=True)
    analyzed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    email = relationship("EmailRecord", back_populates="analysis")

class AuthenticationResult(Base):
    __tablename__ = "authentication_results"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False, unique=True)
    spf_result = Column(String(32), default="UNKNOWN")
    spf_domain = Column(String(128), nullable=True)
    dkim_result = Column(String(32), default="UNKNOWN")
    dkim_domain = Column(String(128), nullable=True)
    dmarc_result = Column(String(32), default="UNKNOWN")
    dmarc_policy = Column(String(32), nullable=True)
    arc_result = Column(String(32), default="NONE")
    auth_summary = Column(Text, nullable=True)
    
    email = relationship("EmailRecord", back_populates="auth_results")

class RelayHop(Base):
    __tablename__ = "relay_hops"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False)
    hop_order = Column(Integer, nullable=False)
    by_host = Column(String(256), nullable=True)
    from_host = Column(String(256), nullable=True)
    ip_address = Column(String(64), nullable=True)
    is_public = Column(Boolean, default=True)
    is_trustworthy = Column(Boolean, default=True)
    protocol = Column(String(32), nullable=True)
    timestamp_str = Column(String(128), nullable=True)
    
    email = relationship("EmailRecord", back_populates="relay_hops")

class OriginAssessment(Base):
    __tablename__ = "origin_assessments"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False, unique=True)
    earliest_observable_ip = Column(String(64), nullable=True)
    country = Column(String(64), nullable=True)
    country_code = Column(String(8), nullable=True)
    region = Column(String(64), nullable=True)
    city = Column(String(64), nullable=True)
    asn = Column(String(64), nullable=True)
    asn_org = Column(String(128), nullable=True)
    isp = Column(String(128), nullable=True)
    is_cloud = Column(Boolean, default=False)
    is_vpn = Column(Boolean, default=False)
    is_tor = Column(Boolean, default=False)
    is_proxy = Column(Boolean, default=False)
    is_open_relay = Column(Boolean, default=False)
    origin_confidence_score = Column(Float, default=0.0)
    origin_confidence_level = Column(String(32), default="MEDIUM")
    confidence_explanation = Column(Text, nullable=True)
    infrastructure_label = Column(String(128), default="Probable Observable Infrastructure")
    
    email = relationship("EmailRecord", back_populates="origin_assessment")

class IOC(Base):
    __tablename__ = "iocs"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False)
    ioc_type = Column(String(32), nullable=False)
    ioc_value = Column(Text, nullable=False)
    reputation = Column(String(32), default="UNKNOWN")
    enrichment_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    email = relationship("EmailRecord", back_populates="iocs")

class ForensicCase(Base):
    """
    Forensic Incident Case in the Review Queue.
    Used for SOC analyst investigations, not for holding mail.
    """
    __tablename__ = "cases"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_number = Column(String(32), unique=True, nullable=False, index=True)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False, unique=True)
    status = Column(String(32), default="UNREVIEWED") # UNREVIEWED, IN_REVIEW, CONFIRMED_THREAT, FALSE_POSITIVE, RESOLVED
    assigned_analyst = Column(String(64), default="Unassigned")
    priority = Column(String(32), default="HIGH")
    summary = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    campaign_id = Column(String(36), ForeignKey("campaigns.id"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    email = relationship("EmailRecord", back_populates="case")
    campaign = relationship("Campaign", back_populates="cases")
    feedback_entries = relationship("AnalystFeedback", back_populates="case")

class AnalystFeedback(Base):
    """
    Structured Analyst Feedback Record:
    Records analyst verdicts (CONFIRMED_THREAT, FALSE_POSITIVE, BENIGN, NEEDS_REVIEW).
    Stored safely for offline calibration and dataset exports; does NOT immediately
    poison or retrain active production models.
    """
    __tablename__ = "analyst_feedback"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), ForeignKey("cases.id"), nullable=True)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False)
    verdict_label = Column(String(32), nullable=False) # CONFIRMED_THREAT, FALSE_POSITIVE, BENIGN, NEEDS_REVIEW
    analyst_name = Column(String(64), nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    email = relationship("EmailRecord", back_populates="feedback_entries")
    case = relationship("ForensicCase", back_populates="feedback_entries")

class QuarantineRecord(Base):
    """
    @deprecated Historical Quarantine Record Table.
    Maintained for non-destructive database compatibility.
    TraceMail no longer generates new quarantine actions.
    """
    __tablename__ = "quarantine"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False, unique=True)
    quarantine_state = Column(String(32), default="LEGACY_QUARANTINE")
    quarantined_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    action_by = Column(String(64), nullable=True)
    action_at = Column(DateTime, nullable=True)
    release_notes = Column(Text, nullable=True)
    
    email = relationship("EmailRecord", back_populates="quarantine_entry")

class Campaign(Base):
    __tablename__ = "campaigns"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(128), nullable=False)
    threat_type = Column(String(64), nullable=False)
    description = Column(Text, nullable=True)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    total_incidents = Column(Integer, default=1)
    status = Column(String(32), default="ACTIVE")
    shared_indicators = Column(JSON, default=dict)
    correlation_confidence = Column(Float, default=0.85)
    
    cases = relationship("ForensicCase", back_populates="campaign")
    links = relationship("CampaignLink", back_populates="campaign")

class CampaignLink(Base):
    __tablename__ = "campaign_links"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    campaign_id = Column(String(36), ForeignKey("campaigns.id"), nullable=False)
    source_node = Column(String(128), nullable=False)
    target_node = Column(String(128), nullable=False)
    link_type = Column(String(64), nullable=False)
    
    campaign = relationship("Campaign", back_populates="links")

class AuditEvent(Base):
    __tablename__ = "audit_events"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    event_type = Column(String(64), nullable=False)
    actor = Column(String(64), default="SYSTEM")
    target_resource = Column(String(128), nullable=False)
    details = Column(JSON, nullable=True)
    prev_event_hash = Column(String(64), nullable=True)
    event_hash = Column(String(64), nullable=False, unique=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

class WeeklyReport(Base):
    __tablename__ = "reports"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    report_title = Column(String(256), nullable=False)
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    file_path = Column(String(256), nullable=False)
    stats_json = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class SenderBaseline(Base):
    __tablename__ = "sender_baselines"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    sender_email = Column(String(256), unique=True, nullable=False, index=True)
    sender_domain = Column(String(128), nullable=False, index=True)
    observed_ips = Column(JSON, default=list)
    observed_asns = Column(JSON, default=list)
    observed_countries = Column(JSON, default=list)
    typical_reply_to_domains = Column(JSON, default=list)
    typical_recipients = Column(JSON, default=list)
    total_messages_seen = Column(Integer, default=1)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
