import os
import logging
from typing import Dict, Any, Optional, List
from app.config import settings
from app.core.evidence import Evidence

logger = logging.getLogger("tracemail.engines.origin")

class BaseGeoIPProvider:
    def lookup(self, ip_str: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

class MaxMindGeoLite2Provider(BaseGeoIPProvider):
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or getattr(settings, "MAXMIND_DB_PATH", "./data/GeoLite2-City.mmdb")
        self.reader = None
        if self.db_path and os.path.exists(self.db_path):
            try:
                import geoip2.database
                self.reader = geoip2.database.Reader(self.db_path)
                logger.info(f"Loaded MaxMind GeoIP database from {self.db_path}")
            except Exception as e:
                logger.warning(f"Failed to initialize MaxMind database: {e}")

    def lookup(self, ip_str: str) -> Optional[Dict[str, Any]]:
        if not self.reader:
            return None
        try:
            resp = self.reader.city(ip_str)
            return {
                "country": resp.country.name or "UNKNOWN",
                "country_code": resp.country.iso_code or "UN",
                "region": resp.subdivisions.most_specific.name or "UNKNOWN",
                "city": resp.city.name or "UNKNOWN",
                "provider": "MaxMind-GeoLite2"
            }
        except Exception:
            return None

class ExternalGeoIPProvider(BaseGeoIPProvider):
    def lookup(self, ip_str: str) -> Optional[Dict[str, Any]]:
        return None

class OriginTraceabilityEngine:
    """
    Evaluates Observable Network Infrastructure.
    Uses real GeoIP / ASN provider abstraction.
    Strict Forensic Standard:
    - Never labels IP location as 'Attacker Physical Location' or 'Hacker Location'
    - Labels exclusively as 'Probable Observable Infrastructure'
    - Returns UNKNOWN cleanly when intelligence databases are not configured
    """
    providers: List[BaseGeoIPProvider] = [
        MaxMindGeoLite2Provider(),
        ExternalGeoIPProvider()
    ]

    @classmethod
    def assess_origin(cls, earliest_public_ip: Optional[str], total_hops: int) -> Dict[str, Any]:
        evidence_list: List[Evidence] = []

        if not earliest_public_ip:
            return {
                "earliest_observable_ip": None,
                "country": "UNKNOWN",
                "country_code": "UN",
                "region": "UNKNOWN",
                "city": "UNKNOWN",
                "asn": "UNKNOWN",
                "asn_org": "UNKNOWN",
                "isp": "UNKNOWN",
                "is_cloud": False,
                "is_vpn": False,
                "is_tor": False,
                "is_proxy": False,
                "is_open_relay": False,
                "origin_confidence_score": 10.0,
                "origin_confidence_level": "LOW",
                "confidence_explanation": "No observable public IP extracted from trustworthy relay hops",
                "infrastructure_label": "Probable Observable Infrastructure",
                "evidence": evidence_list
            }

        # Query provider abstraction
        geo_data = None
        for prov in cls.providers:
            try:
                geo_data = prov.lookup(earliest_public_ip)
                if geo_data:
                    break
            except Exception as e:
                logger.warning(f"GeoIP provider lookup error: {e}")

        if not geo_data:
            # Intelligence unconfigured -> return UNKNOWN
            return {
                "earliest_observable_ip": earliest_public_ip,
                "country": "UNKNOWN",
                "country_code": "UN",
                "region": "UNKNOWN",
                "city": "UNKNOWN",
                "asn": "UNKNOWN",
                "asn_org": "UNKNOWN",
                "isp": "UNKNOWN",
                "is_cloud": False,
                "is_vpn": False,
                "is_tor": False,
                "is_proxy": False,
                "is_open_relay": False,
                "origin_confidence_score": 40.0,
                "origin_confidence_level": "MEDIUM" if total_hops > 1 else "LOW",
                "confidence_explanation": "Public IP identified but local GeoIP/ASN database is currently unconfigured (UNKNOWN)",
                "infrastructure_label": "Probable Observable Infrastructure",
                "evidence": evidence_list
            }

        # If GeoIP is available
        country = geo_data.get("country", "UNKNOWN")
        country_code = geo_data.get("country_code", "UN")
        region = geo_data.get("region", "UNKNOWN")
        city = geo_data.get("city", "UNKNOWN")
        
        confidence = 80.0
        reasons = []
        if total_hops <= 1:
            confidence -= 20.0
            reasons.append("Single hop observed in Received chain")

        final_conf = max(20.0, min(100.0, confidence))
        level = "HIGH" if final_conf >= 75 else ("MEDIUM" if final_conf >= 45 else "LOW")
        explanation = "; ".join(reasons) if reasons else "Observable relay hop verified with local GeoIP database"

        evidence_list.append(Evidence(
            engine="RELAY_INFRASTRUCTURE",
            type="OBSERVED_INFRASTRUCTURE_LOCATION",
            semantic_group="origin_infrastructure",
            value=f"{city}, {country}",
            severity=0.15,
            confidence=round(final_conf / 100.0, 2),
            reliability=0.80,
            direction="NEUTRAL",
            description=f"Probable observable infrastructure located in {city}, {country} ({country_code})",
            source="GEOIP_DATABASE"
        ))

        return {
            "earliest_observable_ip": earliest_public_ip,
            "country": country,
            "country_code": country_code,
            "region": region,
            "city": city,
            "asn": geo_data.get("asn", "UNKNOWN"),
            "asn_org": geo_data.get("asn_org", "UNKNOWN"),
            "isp": geo_data.get("isp", "UNKNOWN"),
            "is_cloud": geo_data.get("is_cloud", False),
            "is_vpn": geo_data.get("is_vpn", False),
            "is_tor": geo_data.get("is_tor", False),
            "is_proxy": geo_data.get("is_proxy", False),
            "is_open_relay": geo_data.get("is_open_relay", False),
            "origin_confidence_score": round(final_conf, 1),
            "origin_confidence_level": level,
            "confidence_explanation": explanation,
            "infrastructure_label": "Probable Observable Infrastructure",
            "evidence": evidence_list
        }
