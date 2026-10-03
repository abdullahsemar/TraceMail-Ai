import hashlib
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.database.models import AuditEvent

class AuditLogger:
    @staticmethod
    def get_latest_hash(db: Session) -> Optional[str]:
        last_event = db.query(AuditEvent).order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).first()
        return last_event.event_hash if last_event else "GENESIS_HASH_00000000000000000000000000000000000000000000000000000000"

    @classmethod
    def log_event(
        cls,
        db: Session,
        event_type: str,
        target_resource: str,
        actor: str = "SYSTEM",
        details: Optional[Dict[str, Any]] = None
    ) -> AuditEvent:
        prev_hash = cls.get_latest_hash(db)
        timestamp = datetime.now(timezone.utc)
        ts_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        
        # Build canonical payload for hashing
        payload = {
            "prev_hash": prev_hash,
            "event_type": event_type,
            "actor": actor,
            "target_resource": target_resource,
            "details": details or {},
            "timestamp": ts_str
        }
        
        serialized = json.dumps(payload, sort_keys=True)
        event_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        
        event = AuditEvent(
            event_type=event_type,
            actor=actor,
            target_resource=target_resource,
            details=details or {},
            prev_event_hash=prev_hash,
            event_hash=event_hash,
            created_at=timestamp
        )
        
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    @classmethod
    def verify_chain_integrity(cls, db: Session) -> Dict[str, Any]:
        events = db.query(AuditEvent).order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc()).all()
        if not events:
            return {"status": "VALID", "total_records": 0, "broken_at": None}
            
        prev_hash = "GENESIS_HASH_00000000000000000000000000000000000000000000000000000000"
        for idx, event in enumerate(events):
            if event.prev_event_hash != prev_hash:
                return {
                    "status": "COMPROMISED",
                    "total_records": len(events),
                    "broken_at_index": idx,
                    "event_id": event.id,
                    "reason": "Previous hash pointer mismatch"
                }
            
            # Recalculate event hash using deterministic timestamp formatting
            ts_str = event.created_at.strftime("%Y-%m-%d %H:%M:%S") if isinstance(event.created_at, datetime) else str(event.created_at)[:19]
            payload = {
                "prev_hash": event.prev_event_hash,
                "event_type": event.event_type,
                "actor": event.actor,
                "target_resource": event.target_resource,
                "details": event.details or {},
                "timestamp": ts_str
            }
            computed_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
            if computed_hash != event.event_hash:
                return {
                    "status": "COMPROMISED",
                    "total_records": len(events),
                    "broken_at_index": idx,
                    "event_id": event.id,
                    "reason": "Event content tamper detected"
                }
            prev_hash = event.event_hash
            
        return {"status": "VALID", "total_records": len(events), "last_hash": prev_hash}
