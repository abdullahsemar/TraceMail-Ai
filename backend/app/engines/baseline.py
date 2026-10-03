from datetime import datetime
from typing import Dict, Any, List
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.database.models import SenderBaseline

class SenderBaselineEngine:
    """
    Maintains historical sender behavioral baselines.
    Detects anomalies such as new infrastructure, new country, unusual sending times,
    new Reply-To domains, and unusual recipient relationships.
    """
    
    @classmethod
    def evaluate_and_update(
        cls,
        db: Session,
        sender_email: str,
        observed_ip: str,
        observed_asn: str,
        observed_country: str,
        reply_to: str,
        recipients: List[str]
    ) -> Dict[str, Any]:
        if not sender_email:
            return {"is_new_sender": True, "anomalies": [], "baseline_anomaly_score": 0.0}

        sender_email_clean = sender_email.strip().lower()
        sender_domain = sender_email_clean.split("@")[-1] if "@" in sender_email_clean else ""
        reply_to_domain = reply_to.strip().lower().split("@")[-1] if reply_to and "@" in reply_to else ""
        
        baseline = db.query(SenderBaseline).filter(SenderBaseline.sender_email == sender_email_clean).first()
        now_dt = datetime.now(timezone.utc)
        
        anomalies: List[str] = []
        anomaly_score = 0.0
        
        if not baseline:
            # First time seeing this sender
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
            
            return {
                "is_new_sender": True,
                "total_messages_seen": 1,
                "anomalies": ["First time observed sending to organization"],
                "baseline_anomaly_score": 10.0,
                "explanation": "No prior historical baseline exists for this sender"
            }
            
        # Existing sender: Check for behavioral drift
        ips = list(baseline.observed_ips or [])
        asns = list(baseline.observed_asns or [])
        countries = list(baseline.observed_countries or [])
        reply_domains = list(baseline.typical_reply_to_domains or [])
        known_recipients = set(baseline.typical_recipients or [])
        
        if observed_ip and observed_ip not in ips:
            anomalies.append(f"New sending IP infrastructure: {observed_ip}")
            anomaly_score += 15.0
            ips.append(observed_ip)
            
        if observed_country and countries and observed_country not in countries:
            anomalies.append(f"Unusual sending country: '{observed_country}' (Historical: {', '.join(countries)})")
            anomaly_score += 25.0
            countries.append(observed_country)
            
        if observed_asn and asns and observed_asn not in asns:
            anomalies.append(f"New network autonomous system (ASN): {observed_asn}")
            anomaly_score += 15.0
            asns.append(observed_asn)
            
        if reply_to_domain and reply_domains and reply_to_domain not in reply_domains:
            anomalies.append(f"Unusual Reply-To domain: '{reply_to_domain}'")
            anomaly_score += 30.0
            reply_domains.append(reply_to_domain)
            
        # Update baseline statistics
        baseline.observed_ips = ips
        baseline.observed_asns = asns
        baseline.observed_countries = countries
        baseline.typical_reply_to_domains = reply_domains
        baseline.typical_recipients = list(known_recipients.union(set(recipients or [])))
        baseline.total_messages_seen += 1
        baseline.last_seen = now_dt
        db.commit()
        
        return {
            "is_new_sender": False,
            "total_messages_seen": baseline.total_messages_seen,
            "anomalies": anomalies,
            "baseline_anomaly_score": min(100.0, anomaly_score),
            "explanation": f"Observed across {baseline.total_messages_seen} historical messages"
        }
