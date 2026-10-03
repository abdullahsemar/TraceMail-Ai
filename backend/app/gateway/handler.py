import os
import hashlib
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from sqlalchemy.orm import Session
from app.config import settings
from app.database.session import SessionLocal
from app.database.models import (
    EmailRecord, EmailEvidence, AnalysisResult, AuthenticationResult,
    RelayHop, OriginAssessment, IOC, ForensicCase, Campaign
)
from app.core.evidence import Evidence
from app.core.audit import AuditLogger
from app.core.events import broadcaster
from app.core.policy import PolicyEngine
from app.notifications.manager import NotificationManager
from app.parsers.rfc822_parser import RFC822Parser
from app.parsers.header_forensics import HeaderForensics
from app.parsers.relay_tracer import RelayTracer
from app.engines.sentinel import FastSentinelEngine
from app.engines.threat_ml import HybridThreatEngine
from app.engines.attachment_analyzer import AttachmentSecurityAnalyzer
from app.engines.behavioral_intelligence import BehavioralIntelligenceEngine
from app.engines.bec_detector import SequentialBECDetector
from app.engines.campaign_correlation import FuzzyCampaignCorrelationEngine
from app.engines.origin import OriginTraceabilityEngine
from app.engines.domain_intel import DomainIntelligenceProvider
from app.engines.url_intel import URLDomainIntelligenceEngine
from app.engines.threat_intel import ThreatIntelligenceProvider
from app.engines.fusion import EvidenceFusionEngine
from app.gateway.downstream import DownstreamRelayClient

logger = logging.getLogger("tracemail.pipeline")

class InboundPipelineProcessor:
    """
    Unified Non-Quarantining Inbound Threat Detection & Forensics Pipeline:
    RECEIVE -> PRESERVE (SHA-256) -> PARSE -> MULTI-ENGINE FORENSIC ANALYSIS ->
    SEQUENTIAL BEC REASONING -> FUZZY CAMPAIGN CORRELATION -> EVIDENCE FUSION ->
    EXPLAINABLE RISK VERDICT -> POLICY ENGINE -> INJECT HEADERS -> FORWARD DOWNSTREAM ->
    REVIEW QUEUE / SOC NOTIFICATION
    
    Operates symmetrically for SMTP Proxy (source="SMTP_GATEWAY") and Connected Mailbox (source="GMAIL").
    """

    @classmethod
    async def process_raw_email(
        cls,
        raw_bytes: bytes,
        mail_from: str,
        rcpt_tos: list,
        source: str = "SMTP_GATEWAY",
        connection_id: Optional[str] = None,
        is_demo: bool = False
    ) -> EmailRecord:
        db = SessionLocal()
        try:
            # 1. Forensic Evidence Preservation (SHA-256)
            now_utc = datetime.now(timezone.utc)
            year_str = now_utc.strftime("%Y")
            gateway_msg_id = f"TR-{year_str}-{uuid.uuid4().hex[:8].upper()}"
            sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
            
            # Save raw immutable .eml file for cryptographic integrity
            evidence_filename = f"{sha256_hash}.eml"
            os.makedirs(settings.EVIDENCE_DIR, exist_ok=True)
            evidence_path = os.path.join(settings.EVIDENCE_DIR, evidence_filename)
            if settings.STORE_RAW_EMAIL and not os.path.exists(evidence_path):
                try:
                    with open(evidence_path, "wb") as f:
                        f.write(raw_bytes)
                except Exception as fe:
                    logger.warning(f"Could not save evidence file {evidence_path}: {fe}")
            elif not settings.STORE_RAW_EMAIL:
                evidence_path = "STORAGE_DISABLED"

            # Log Audit Event: Evidence Ingested
            AuditLogger.log_event(
                db=db,
                event_type="SMTP_MESSAGE_RECEIVED" if source == "SMTP_GATEWAY" else "EMAIL_INGESTED",
                target_resource=gateway_msg_id,
                details={"sha256": sha256_hash, "size_bytes": len(raw_bytes), "source": source}
            )

            # 2. Parse RFC822 Structure
            parsed = RFC822Parser.parse_raw_bytes(raw_bytes)
            sender_email = parsed.get("sender_email") or mail_from
            sender_display_name = parsed.get("sender_display_name") or ""
            sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
            reply_to = parsed.get("reply_to") or ""

            # Master Evidence Collection
            collected_evidence: List[Evidence] = []

            # 3. Engine 1: Header Forensics & Authentication (SPF / DKIM / DMARC)
            header_res = HeaderForensics.analyze_headers(parsed)
            collected_evidence.extend(header_res.get("evidence", []))

            # Engine 2: Fast Sentinel Screening
            sentinel_res = FastSentinelEngine.screen(parsed, header_res)

            # Engine 3: Relay Traceability (IPv4 + IPv6 Hop Reconstruction)
            relay_res = RelayTracer.trace_relays(parsed.get("headers", {}))
            collected_evidence.extend(relay_res.get("evidence", []))
            earliest_ip = relay_res.get("earliest_observable_ip")

            # Engine 4: Observable Infrastructure & Origin Assessment
            origin_res = OriginTraceabilityEngine.assess_origin(
                earliest_public_ip=earliest_ip,
                total_hops=relay_res.get("total_hops", 0)
            )
            collected_evidence.extend(origin_res.get("evidence", []))

            # Engine 5: Research-Grounded Behavioral Intelligence (Cidon et al. 2019 Table 3)
            behavioral_res = BehavioralIntelligenceEngine.evaluate_behavioral_intelligence(
                db=db,
                sender_email=sender_email,
                sender_display_name=sender_display_name,
                reply_to=reply_to,
                recipients=rcpt_tos,
                observed_ip=earliest_ip or "",
                observed_asn=origin_res.get("asn") or "",
                observed_country=origin_res.get("country") or ""
            )
            collected_evidence.extend(behavioral_res.get("evidence", []))

            # Engine 6: Domain Intelligence (DNS Lookups & Brand Squatting)
            domain_res = DomainIntelligenceProvider.analyze_domain(sender_domain)
            collected_evidence.extend(domain_res.get("evidence", []))

            # Engine 7: URL & Link Intelligence (SSRF-Safe, Length, Popularity)
            url_res = URLDomainIntelligenceEngine.analyze_urls_and_domains(
                urls=parsed.get("urls", []),
                sender_domain=sender_domain
            )
            collected_evidence.extend(url_res.get("evidence", []))

            # Engine 8: Attachment Security Inspection
            attachment_res = AttachmentSecurityAnalyzer.analyze_attachments(parsed.get("attachments", []))
            collected_evidence.extend(attachment_res.get("evidence", []))

            # Engine 9: External Threat Intelligence Feeds (Real or UNKNOWN)
            ip_intel = ThreatIntelligenceProvider.check_ip_reputation(earliest_ip or "")
            dom_intel = ThreatIntelligenceProvider.check_domain_reputation(sender_domain)
            if ip_intel.get("status") == "KNOWN_BAD":
                collected_evidence.append(Evidence(
                    engine="RELAY_INFRASTRUCTURE",
                    type="KNOWN_BAD_IP_FEED",
                    semantic_group="origin_infrastructure",
                    independence_group="external_threat_feed",
                    value=earliest_ip,
                    severity=0.95,
                    confidence=0.98,
                    reliability=0.95,
                    freshness=1.0,
                    direction="SUPPORTING",
                    description=f"Origin IP '{earliest_ip}' is confirmed malicious on external threat feed",
                    source=ip_intel.get("source", "THREAT_INTEL"),
                    research_provenance="TRACEMAIL_ORIGIN_FORENSICS"
                ))
            if dom_intel.get("status") == "KNOWN_BAD":
                collected_evidence.append(Evidence(
                    engine="DOMAIN",
                    type="KNOWN_BAD_DOMAIN_FEED",
                    semantic_group="domain_reputation",
                    independence_group="external_threat_feed",
                    value=sender_domain,
                    severity=0.95,
                    confidence=0.98,
                    reliability=0.95,
                    freshness=1.0,
                    direction="SUPPORTING",
                    description=f"Sender domain '{sender_domain}' is confirmed malicious on external threat feed",
                    source=dom_intel.get("source", "THREAT_INTEL"),
                    research_provenance="TRACEMAIL_ORIGIN_FORENSICS"
                ))

            # Engine 10: Deep Pretrained Transformer (DistilBERT) & Content NLP
            ml_engine = HybridThreatEngine()
            ml_context = {
                **parsed,
                "auth_results": header_res,
                "header_analysis": header_res,
                "baseline": behavioral_res,
                "attachment_analysis": attachment_res
            }
            content_nlp_res = ml_engine.evaluate(ml_context)
            collected_evidence.extend(content_nlp_res.get("evidence", []))

            # Engine 11: Sequential BEC Detection Synthesis (Cidon et al. 2019 Stage A -> Stage B)
            bec_res = SequentialBECDetector.evaluate_sequential_bec(
                behavioral_results=behavioral_res,
                content_results=content_nlp_res,
                header_results=header_res,
                url_results=url_res
            )
            collected_evidence.extend(bec_res.get("evidence", []))

            # Engine 12: Fuzzy Campaign Correlation (SimHash Near-Duplicate Clustering)
            campaign_context = {
                "subject": parsed.get("subject", ""),
                "body_text": parsed.get("body_text", ""),
                "sender_email": sender_email,
                "reply_to": reply_to,
                "urls": parsed.get("urls", []),
                "attachments": attachment_res.get("attachments_analysis", []),
                "threat_classification": "SUSPICIOUS"
            }
            campaign_res = FuzzyCampaignCorrelationEngine.correlate_with_existing_campaigns(
                db=db,
                email_data=campaign_context,
                min_risk_threshold=40.0
            )
            collected_evidence.extend(campaign_res.get("evidence", []))

            # 4. Multi-Engine Evidence Fusion & Risk Calculation
            fusion_res = EvidenceFusionEngine.fuse(
                evidence_items=collected_evidence,
                origin_assessment=origin_res,
                auth_results=header_res,
                behavioral_results=behavioral_res
            )

            final_risk = fusion_res["final_risk_score"]
            severity = fusion_res["risk_severity"]
            classification = fusion_res["threat_classification"]
            threat_prob = fusion_res["threat_probability"]
            evidence_conf = fusion_res["evidence_confidence"]
            impact = fusion_res["impact_score"]
            infra_confidence = fusion_res["infrastructure_confidence"]
            geo_confidence = fusion_res["geolocation_confidence"]

            # 5. Non-Quarantining Policy Decision (ALLOW / FLAG / FLAG_AND_ALERT)
            policy_decision = PolicyEngine.evaluate_policy(verdict=fusion_res, source=source)
            action_taken = policy_decision["action_taken"]
            action_reason = policy_decision["action_reason"]
            processing_state = policy_decision["processing_state"]

            # 6. Downstream Relay with Injected Warning Metadata (Pre-Delivery Proxy Mode)
            if policy_decision["should_forward_downstream"] and source == "SMTP_GATEWAY":
                try:
                    relayed = await DownstreamRelayClient.relay_raw_message(
                        raw_bytes=raw_bytes,
                        sender=mail_from,
                        recipients=rcpt_tos,
                        case_id=gateway_msg_id,
                        risk_score=final_risk,
                        severity=severity,
                        classification=classification
                    )
                    if not relayed and DownstreamRelayClient.is_configured():
                        processing_state = "DELIVERY_FAILED"
                        logger.warning(f"[{gateway_msg_id}] Downstream relay failed, evidence preserved.")
                    else:
                        logger.info(f"[{gateway_msg_id}] Forwarded downstream with X-TraceMail headers.")
                except Exception as relay_err:
                    processing_state = "DELIVERY_FAILED"
                    logger.error(f"[{gateway_msg_id}] Downstream relay exception: {relay_err}")

            # 7. Persist Entities to Database
            email_record = EmailRecord(
                gateway_message_id=gateway_msg_id,
                source=source,
                connection_id=connection_id,
                mail_from=mail_from or sender_email,
                rcpt_to=",".join(rcpt_tos),
                subject=parsed.get("subject", "(No Subject)"),
                sender_display_name=parsed.get("sender_display_name"),
                reply_to=parsed.get("reply_to"),
                return_path=parsed.get("return_path"),
                date_header=parsed.get("date"),
                processing_state=processing_state,
                review_status="UNREVIEWED" if severity in ["HIGH", "CRITICAL", "MEDIUM"] else "RESOLVED",
                evidence_sha256=sha256_hash,
                evidence_file_path=evidence_path,
                sentinel_score=sentinel_res.get("sentinel_score", 0.0),
                sentinel_decision=sentinel_res.get("decision", "ALLOW_FAST"),
                final_risk_score=final_risk,
                risk_severity=severity,
                threat_classification=classification,
                confidence_score=evidence_conf,
                threat_probability=threat_prob,
                evidence_confidence=evidence_conf,
                impact_score=impact,
                origin_confidence=infra_confidence * 100.0,
                recommended_action=action_taken,
                action_taken=action_taken,
                action_reason=action_reason,
                is_demo_fixture=is_demo,
                created_at=now_utc,
                analyzed_at=now_utc
            )
            db.add(email_record)
            db.flush()

            # Persist Email Evidence Artifacts
            evidence_record = EmailEvidence(
                email_id=email_record.id,
                sha256_hash=sha256_hash,
                raw_size_bytes=len(raw_bytes),
                storage_path=evidence_path,
                headers_json=parsed.get("headers"),
                extracted_body_text=parsed.get("body_text"),
                extracted_body_html_sanitized=parsed.get("body_html_sanitized"),
                attachments_json=parsed.get("attachments"),
                urls_json=parsed.get("urls")
            )
            db.add(evidence_record)

            # Persist Analysis Breakdown & Explainability
            analysis_record = AnalysisResult(
                email_id=email_record.id,
                model_version="TraceMail-Fusion-v2.0",
                detected_behaviors=content_nlp_res.get("detected_behaviors", []),
                supporting_reasons=fusion_res.get("top_supporting_evidence", []),
                mitigating_reasons=fusion_res.get("top_mitigating_evidence", []),
                uncertainties=fusion_res.get("uncertainties", []),
                nlp_score=fusion_res["category_scores"].get("CONTENT_NLP", 0.0),
                header_anomaly_score=fusion_res["category_scores"].get("IDENTITY", 0.0) + fusion_res["category_scores"].get("AUTHENTICATION", 0.0),
                baseline_anomaly_score=fusion_res["category_scores"].get("BEHAVIOR", 0.0) + fusion_res["category_scores"].get("DOMAIN", 0.0),
                url_intel_score=fusion_res["category_scores"].get("URL", 0.0),
                ip_reputation_score=fusion_res["category_scores"].get("RELAY_INFRASTRUCTURE", 0.0),
                fusion_summary=f"Risk: {final_risk}/100 ({severity}) | Action: {action_taken} | Classification: {classification}"
            )
            db.add(analysis_record)

            # Persist Authentication Results
            auth_record = AuthenticationResult(
                email_id=email_record.id,
                spf_result=header_res.get("spf", {}).get("result", "UNKNOWN"),
                spf_domain=header_res.get("spf", {}).get("domain"),
                dkim_result=header_res.get("dkim", {}).get("result", "UNKNOWN"),
                dkim_domain=header_res.get("dkim", {}).get("domain"),
                dmarc_result=header_res.get("dmarc", {}).get("result", "UNKNOWN"),
                dmarc_policy=header_res.get("dmarc", {}).get("policy"),
                arc_result="PASS" if header_res.get("has_arc") else "NONE",
                auth_summary=header_res.get("summary")
            )
            db.add(auth_record)

            # Persist Relay Hops
            for hop in relay_res.get("hops", []):
                hop_rec = RelayHop(
                    email_id=email_record.id,
                    hop_order=hop.get("hop_order", 0),
                    by_host=hop.get("by_host"),
                    from_host=hop.get("from_host"),
                    ip_address=hop.get("ip_address"),
                    is_public=hop.get("is_public", True),
                    timestamp_str=hop.get("timestamp_str") or now_utc.isoformat()
                )
                db.add(hop_rec)

            # Persist Origin Assessment
            origin_rec = OriginAssessment(
                email_id=email_record.id,
                earliest_observable_ip=origin_res.get("earliest_observable_ip"),
                country=origin_res.get("country"),
                country_code=origin_res.get("country_code"),
                region=origin_res.get("region"),
                city=origin_res.get("city"),
                asn=origin_res.get("asn"),
                asn_org=origin_res.get("asn_org"),
                isp=origin_res.get("isp"),
                is_cloud=origin_res.get("is_cloud", False),
                is_vpn=origin_res.get("is_vpn", False),
                is_tor=origin_res.get("is_tor", False),
                is_proxy=origin_res.get("is_proxy", False),
                is_open_relay=origin_res.get("is_open_relay", False),
                origin_confidence_score=origin_res.get("origin_confidence_score", 40.0),
                origin_confidence_level=origin_res.get("origin_confidence_level", "MEDIUM"),
                confidence_explanation=origin_res.get("confidence_explanation"),
                infrastructure_label="Probable Observable Infrastructure"
            )
            db.add(origin_rec)

            # Record Normalized IOCs
            if earliest_ip:
                db.add(IOC(email_id=email_record.id, ioc_type="IP", ioc_value=earliest_ip, reputation=ip_intel.get("status", "UNKNOWN")))
            if sender_domain:
                db.add(IOC(email_id=email_record.id, ioc_type="DOMAIN", ioc_value=sender_domain, reputation=dom_intel.get("status", "UNKNOWN")))
            if reply_to and "@" in reply_to:
                db.add(IOC(email_id=email_record.id, ioc_type="REPLY_TO", ioc_value=reply_to, reputation="OBSERVED"))
            for u in parsed.get("urls", []):
                db.add(IOC(email_id=email_record.id, ioc_type="URL", ioc_value=u.get("url", ""), reputation="UNKNOWN"))
            for att in attachment_res.get("attachments_analysis", []):
                if att.get("sha256") and att.get("sha256") != "NOT_COMPUTED":
                    db.add(IOC(email_id=email_record.id, ioc_type="ATTACHMENT_SHA256", ioc_value=att["sha256"], reputation="UNKNOWN"))

            # Handle Case Creation in Review Queue (for SOC Analyst investigation)
            case_number = gateway_msg_id
            if policy_decision["should_create_case"]:
                forensic_case = ForensicCase(
                    case_number=case_number,
                    email_id=email_record.id,
                    status="UNREVIEWED",
                    priority=severity,
                    assigned_analyst="Unassigned",
                    summary=f"[{source}] {classification} threat flagged against {','.join(rcpt_tos)} from {sender_email}",
                    campaign_id=campaign_res.get("matched_campaign_id")
                )
                db.add(forensic_case)

            # Audit Log: Verdict Generated & Message Flagged/Forwarded
            AuditLogger.log_event(
                db=db,
                event_type="VERDICT_GENERATED",
                target_resource=gateway_msg_id,
                details={
                    "risk_score": final_risk,
                    "classification": classification,
                    "action_taken": action_taken,
                    "source": source
                }
            )

            db.commit()
            db.refresh(email_record)

            # 8. Asynchronous Notification Dispatch (Telegram for HIGH/CRITICAL)
            if policy_decision["should_alert_telegram"]:
                await NotificationManager.dispatch_alerts(
                    case_number=case_number,
                    sender=sender_email,
                    subject=email_record.subject,
                    verdict=fusion_res,
                    origin=origin_res,
                    source=source,
                    dedup_key=sha256_hash
                )

            # 9. Real-Time Broadcast via SSE
            await broadcaster.broadcast("EMAIL_PROCESSED", {
                "id": email_record.id,
                "gateway_message_id": email_record.gateway_message_id,
                "source": email_record.source,
                "sender": email_record.mail_from,
                "subject": email_record.subject,
                "risk_score": email_record.final_risk_score,
                "severity": email_record.risk_severity,
                "classification": email_record.threat_classification,
                "threat_confidence": threat_prob,
                "infrastructure_confidence": infra_confidence,
                "geolocation_confidence": geo_confidence,
                "action_taken": email_record.action_taken,
                "review_status": email_record.review_status,
                "probable_country": origin_res.get("country"),
                "probable_asn": origin_res.get("asn"),
                "top_reasons": fusion_res.get("top_supporting_evidence", []),
                "mitigating_reasons": fusion_res.get("top_mitigating_evidence", []),
                "uncertainties": fusion_res.get("uncertainties", []),
                "timestamp": email_record.created_at.isoformat()
            })

            return email_record

        finally:
            db.close()
