import ipaddress
import re
from urllib.parse import urlparse
from typing import Dict, Any, List, Set, Optional
from app.core.evidence import Evidence

class DomainPopularityProvider:
    """
    Modern Domain Popularity & Prevalence Provider (Cidon et al. 2019 Table 5 modern equivalent).
    Avoids deprecated Alexa rankings. Uses curated global popularity + enterprise prevalence.
    If popularity is unknown, returns UNKNOWN (never assumes SAFE).
    """
    TOP_POPULAR_DOMAINS: Set[str] = {
        "google.com", "microsoft.com", "apple.com", "amazon.com", "github.com",
        "linkedin.com", "facebook.com", "twitter.com", "x.com", "youtube.com",
        "cloudflare.com", "salesforce.com", "zoom.us", "dropbox.com", "adobe.com",
        "office.com", "live.com", "netflix.com", "wikipedia.org", "yahoo.com"
    }

    @classmethod
    def get_popularity_status(cls, domain: str) -> str:
        if not domain:
            return "UNKNOWN"
        clean = domain.strip().lower()
        if clean in cls.TOP_POPULAR_DOMAINS or any(clean.endswith(f".{d}") for d in cls.TOP_POPULAR_DOMAINS):
            return "HIGH_POPULARITY"
        return "UNKNOWN"


class URLDomainIntelligenceEngine:
    """
    Research-Informed URL & Link Analysis Engine (Cidon et al. 2019 Table 5 & §4.4):
    - URL length & hostname length analysis (long obfuscated URLs are suspicious)
    - Domain popularity ranking check via modern DomainPopularityProvider
    - Anchor text vs destination link mismatch (deceptive hyperlink)
    - Direct IP in URL destination
    - Brand lookalike and typosquatting paths
    - Punycode internationalized domains
    - Non-standard ports (e.g. :8080, :8443, :8888)
    - SSRF prevention against internal networks and cloud metadata endpoints
    """
    PROTECTED_NETWORKS = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
    ]
    
    POPULAR_BRANDS = [
        "paypal", "microsoft", "google", "apple", "netflix", "amazon",
        "chase", "wellsfargo", "bankofamerica", "dhl", "fedex", "dropbox",
        "docusign", "onedrive", "sharepoint", "office365"
    ]

    UNUSUAL_PORTS = {8080, 8443, 8888, 8000, 8008, 9000, 3000, 5000, 2082, 2083}

    @classmethod
    def is_ssrf_safe(cls, hostname_or_ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(hostname_or_ip)
            for net in cls.PROTECTED_NETWORKS:
                if ip_obj in net:
                    return False
            return True
        except ValueError:
            lower_host = hostname_or_ip.lower().strip()
            if lower_host in ["localhost", "metadata.google.internal", "instance-data", "169.254.169.254"]:
                return False
            if lower_host.endswith(".local") or lower_host.endswith(".internal") or lower_host.endswith(".localhost"):
                return False
            return True

    @classmethod
    def analyze_urls_and_domains(cls, urls: List[Dict[str, str]], sender_domain: str) -> Dict[str, Any]:
        analyzed_items = []
        evidence_list: List[Evidence] = []
        findings = []
        
        for item in urls:
            raw_url = item.get("url", "")
            visible_text = item.get("visible_text", "")
            try:
                parsed = urlparse(raw_url)
                hostname = (parsed.hostname or "").lower()
                port = parsed.port
            except Exception:
                continue
                
            is_safe_ssrf = cls.is_ssrf_safe(hostname)
            has_punycode = hostname.startswith("xn--") or ".xn--" in hostname
            
            # Check brand lookalike in URL hostname
            lookalike_brand = None
            for brand in cls.POPULAR_BRANDS:
                if brand in hostname and not (hostname.endswith(f"{brand}.com") or hostname.endswith(f"{brand}.org") or hostname == f"{brand}.com"):
                    lookalike_brand = brand
                    break
                    
            # Check direct IP
            is_direct_ip = False
            try:
                ipaddress.ip_address(hostname)
                is_direct_ip = True
            except ValueError:
                pass
                
            # Check non-standard ports
            has_unusual_port = port in cls.UNUSUAL_PORTS if port else False

            # Check deceptive anchor text
            deceptive_anchor = False
            if visible_text and ("http://" in visible_text.lower() or "https://" in visible_text.lower() or "@" in visible_text or ".com" in visible_text.lower()):
                clean_text = visible_text.lower().strip()
                if not (clean_text in raw_url.lower() or hostname in clean_text):
                    deceptive_anchor = True

            # Check URL length feature (Cidon et al. 2019 Table 5)
            is_excessively_long_url = len(raw_url) > 150

            # Check Domain Popularity feature (Cidon et al. 2019 Table 5)
            popularity = DomainPopularityProvider.get_popularity_status(hostname)

            is_suspicious_url = bool(
                has_punycode or lookalike_brand or is_direct_ip or has_unusual_port or deceptive_anchor or is_excessively_long_url
            )

            # Generate Standardized Evidence V2
            if has_punycode:
                evidence_list.append(Evidence(
                    engine="URL",
                    type="PUNYCODE_URL_HOST",
                    semantic_group="link_obfuscation",
                    independence_group="url_punycode",
                    value=hostname,
                    severity=0.82,
                    confidence=0.95,
                    reliability=0.92,
                    freshness=1.0,
                    direction="SUPPORTING",
                    description=f"Destination link uses Punycode encoding '{hostname}' (potential homoglyph lure)",
                    source="URL_INTELLIGENCE",
                    research_provenance="CIDON_2019_TABLE5"
                ))

            if lookalike_brand:
                evidence_list.append(Evidence(
                    engine="URL",
                    type="BRAND_LOOKALIKE_URL",
                    semantic_group="domain_impersonation",
                    independence_group="brand_spoofing",
                    value=lookalike_brand,
                    severity=0.88,
                    confidence=0.94,
                    reliability=0.92,
                    freshness=1.0,
                    direction="SUPPORTING",
                    description=f"Destination URL mimics recognized brand '{lookalike_brand}' on unauthorized host '{hostname}'",
                    source="URL_INTELLIGENCE",
                    research_provenance="CIDON_2019_TABLE5"
                ))

            if is_direct_ip:
                evidence_list.append(Evidence(
                    engine="URL",
                    type="DIRECT_IP_URL_DESTINATION",
                    semantic_group="link_obfuscation",
                    independence_group="raw_ip_url",
                    value=hostname,
                    severity=0.75,
                    confidence=0.95,
                    reliability=0.90,
                    freshness=1.0,
                    direction="SUPPORTING",
                    description=f"Destination link uses bare numeric IP address '{hostname}' bypassing standard domain DNS",
                    source="URL_INTELLIGENCE",
                    research_provenance="CIDON_2019_TABLE5"
                ))

            if deceptive_anchor:
                evidence_list.append(Evidence(
                    engine="URL",
                    type="DECEPTIVE_HYPERLINK_TEXT",
                    semantic_group="link_mismatch",
                    independence_group="anchor_mismatch",
                    value=visible_text,
                    severity=0.85,
                    confidence=0.98,
                    reliability=0.95,
                    freshness=1.0,
                    direction="SUPPORTING",
                    description=f"Deceptive hyperlink: Display text '{visible_text}' conceals actual target '{raw_url}'",
                    source="URL_INTELLIGENCE",
                    research_provenance="CIDON_2019_TABLE5"
                ))

            if is_excessively_long_url and not popularity == "HIGH_POPULARITY":
                evidence_list.append(Evidence(
                    engine="URL",
                    type="ABNORMAL_URL_LENGTH",
                    semantic_group="link_obfuscation",
                    independence_group="url_length",
                    value=len(raw_url),
                    severity=0.50,
                    confidence=0.80,
                    reliability=0.75,
                    freshness=1.0,
                    direction="SUPPORTING",
                    description=f"Excessively long URL ({len(raw_url)} characters) indicating tokenized tracking or obfuscation",
                    source="URL_INTELLIGENCE",
                    research_provenance="CIDON_2019_TABLE5"
                ))

            if popularity == "HIGH_POPULARITY" and not is_suspicious_url:
                evidence_list.append(Evidence(
                    engine="URL",
                    type="HIGH_POPULARITY_LINK_DOMAIN",
                    semantic_group="domain_reputation",
                    independence_group="domain_popularity",
                    value=hostname,
                    severity=0.0,
                    confidence=0.90,
                    reliability=0.88,
                    freshness=1.0,
                    direction="MITIGATING",
                    description=f"Destination link domain '{hostname}' is a verified high-popularity service",
                    source="URL_INTELLIGENCE",
                    research_provenance="CIDON_2019_TABLE5"
                ))

            analyzed_items.append({
                "raw_url": raw_url,
                "hostname": hostname,
                "visible_text": visible_text,
                "is_ssrf_safe": is_safe_ssrf,
                "has_punycode": has_punycode,
                "lookalike_brand": lookalike_brand,
                "is_direct_ip": is_direct_ip,
                "has_unusual_port": has_unusual_port,
                "deceptive_anchor": deceptive_anchor,
                "is_suspicious": is_suspicious_url,
                "domain_popularity": popularity
            })

        return {
            "urls_analyzed": analyzed_items,
            "total_urls": len(urls),
            "suspicious_url_count": sum(1 for u in analyzed_items if u["is_suspicious"]),
            "evidence": evidence_list
        }
