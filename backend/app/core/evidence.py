import uuid
from datetime import datetime, timezone
from typing import Any, Optional, Dict
from pydantic import BaseModel, Field

class Evidence(BaseModel):
    """
    Standardized Evidence Object V2 produced by all TraceMail detection engines.
    
    Adheres to the unified multi-engine evidence schema with research provenance
    tracking, directional polarity (SUPPORTING / MITIGATING / NEUTRAL), and
    calibrated reliability and freshness weights.
    """
    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    engine: str = Field(description="Engine category: AUTHENTICATION, IDENTITY, BEHAVIOR, CONTENT_NLP, URL, DOMAIN, ATTACHMENT, RELAY_INFRASTRUCTURE, THREAT_INTELLIGENCE, CAMPAIGN")
    type: str = Field(description="Specific finding type identifier (e.g., UNSEEN_NAME_ADDRESS_PAIR, PAYMENT_DIVERSION, DMARC_PASS)")
    semantic_group: Optional[str] = Field(default=None, description="Semantic group for deduplication (e.g., sender_identity_history, urgency_pressure, payment_diversion)")
    independence_group: Optional[str] = Field(default=None, description="Group for preventing double counting across related detectors")
    value: Optional[Any] = Field(default=None, description="Observed value or extracted artifact")
    description: str = Field(description="Human-readable explainable description of the evidence")
    severity: float = Field(ge=0.0, le=1.0, description="Risk severity rating (0.0=benign/safe to 1.0=maximum threat)")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Detector confidence in this specific finding")
    reliability: float = Field(default=1.0, ge=0.0, le=1.0, description="Inherent reliability of the evidence source")
    freshness: float = Field(default=1.0, ge=0.0, le=1.0, description="Freshness / temporal relevance factor (0.0 to 1.0)")
    direction: str = Field(default="SUPPORTING", description="SUPPORTING (increases threat), MITIGATING (decreases threat), or NEUTRAL")
    source: str = Field(default="UNKNOWN", description="Source component that produced this evidence")
    research_provenance: Optional[str] = Field(
        default=None,
        description="Research paper basis or extension label (e.g., CIDON_2019_TABLE3, TRACEMAIL_TRANSFORMER_EXTENSION)"
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def effective_risk_contribution(self) -> float:
        """
        Calculates raw weighted contribution: severity * confidence * reliability * freshness.
        Mitigating evidence returns a negative contribution.
        """
        strength = self.severity * self.confidence * self.reliability * self.freshness
        if self.direction == "MITIGATING":
            return -strength
        elif self.direction == "SUPPORTING":
            return strength
        return 0.0
