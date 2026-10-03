import re
import dns.resolver
from typing import Dict, Any, List, Optional
from app.core.evidence import Evidence

class DomainIntelligenceProvider:
    """
    Real DNS and Domain Intelligence Provider:
    - DNS A, AAAA, MX, NS, TXT resolution
    - Brand lookalike and typosquatting detection
    - Punycode / Internationalized domain name (IDN) homoglyph detection
    - Suspicious / High-Abuse TLD classification
    - Emits Standardized Evidence V2 with research provenance
    """

    MAJOR_BRANDS = [
        "microsoft", "google", "paypal", "apple", "amazon", "netflix",
        "chase", "wellsfargo", "bankofamerica", "dhl", "fedex", "adobe",
        "dropbox", "docusign", "slack", "zoom", "facebook", "instagram"
    ]

    SUSPICIOUS_TLDS = {
        ".xyz", ".top", ".buzz", ".online", ".click", ".live", ".guru",
        ".fit", ".rest", ".work", ".cfd", ".monster", ".sbs", ".quest"
    }

    @classmethod
    def analyze_domain(cls, domain: str) -> Dict[str, Any]:
        if not domain or domain.lower() in ["localhost", "unknown", ""]:
            return {
                "domain": domain,
                "has_dns": False,
                "mx_records": [],
                "ns_records": [],
                "a_records": [],
                "txt_records": [],
                "status": "UNKNOWN",
                "evidence": []
            }

        clean_domain = domain.strip().lower()
        evidence_list: List[Evidence] = []
        
        # 1. Lookalike & Brand Squatting Detection
        lookalike_brand = None
        for brand in cls.MAJOR_BRANDS:
            if brand in clean_domain:
                # If domain contains brand name but is not the legitimate brand domain
                legit_suffixes = (f"{brand}.com", f"{brand}.org", f"{brand}.net", f"{brand}.io")
                if not (clean_domain.endswith(legit_suffixes) or clean_domain == f"{brand}.com"):
                    lookalike_brand = brand
                    evidence_list.append(Evidence(
                        engine="DOMAIN",
                        type="BRAND_LOOKALIKE_DOMAIN",
                        semantic_group="domain_impersonation",
                        independence_group="domain_squatting",
                        value=clean_domain,
                        severity=0.88,
                        confidence=0.95,
                        reliability=0.92,
                        freshness=1.0,
                        direction="SUPPORTING",
                        description=f"Domain '{clean_domain}' contains brand name '{brand}' in an unauthorized lookalike configuration",
                        source="DOMAIN_INTELLIGENCE",
                        research_provenance="CIDON_2019_TABLE5"
                    ))
                    break

        # 2. Punycode / Homoglyph Detection
        is_punycode = clean_domain.startswith("xn--") or ".xn--" in clean_domain
        if is_punycode:
            evidence_list.append(Evidence(
                engine="DOMAIN",
                type="PUNYCODE_HOMOGLYPH_DOMAIN",
                semantic_group="domain_impersonation",
                independence_group="domain_punycode",
                value=clean_domain,
                severity=0.82,
                confidence=0.96,
                reliability=0.95,
                freshness=1.0,
                direction="SUPPORTING",
                description=f"Domain '{clean_domain}' uses Punycode/IDN encoding (potential homoglyph spoofing)",
                source="DOMAIN_INTELLIGENCE",
                research_provenance="CIDON_2019_TABLE5"
            ))

        # 3. High-Abuse TLD Flag
        has_suspicious_tld = any(clean_domain.endswith(tld) for tld in cls.SUSPICIOUS_TLDS)
        if has_suspicious_tld:
            tld_matched = next(tld for tld in cls.SUSPICIOUS_TLDS if clean_domain.endswith(tld))
            evidence_list.append(Evidence(
                engine="DOMAIN",
                type="HIGH_ABUSE_TLD",
                semantic_group="domain_reputation",
                independence_group="tld_reputation",
                value=tld_matched,
                severity=0.45,
                confidence=0.85,
                reliability=0.80,
                freshness=1.0,
                direction="SUPPORTING",
                description=f"Domain registered under high-abuse TLD '{tld_matched}'",
                source="DOMAIN_INTELLIGENCE",
                research_provenance="CIDON_2019_TABLE5"
            ))

        # 4. Live DNS Lookups
        mx_list = []
        ns_list = []
        a_list = []
        txt_list = []
        has_dns = False

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 2.0
            
            try:
                mx_answers = resolver.resolve(clean_domain, "MX")
                mx_list = [str(r.exchange).rstrip('.') for r in mx_answers]
                has_dns = True
            except Exception:
                pass
                
            try:
                ns_answers = resolver.resolve(clean_domain, "NS")
                ns_list = [str(r.target).rstrip('.') for r in ns_answers]
                has_dns = True
            except Exception:
                pass
                
            try:
                a_answers = resolver.resolve(clean_domain, "A")
                a_list = [str(r.address) for r in a_answers]
                has_dns = True
            except Exception:
                pass

            try:
                txt_answers = resolver.resolve(clean_domain, "TXT")
                txt_list = [b"".join(r.strings).decode("utf-8", errors="ignore") for r in txt_answers]
            except Exception:
                pass

        except Exception:
            pass

        if not has_dns and "." in clean_domain:
            evidence_list.append(Evidence(
                engine="DOMAIN",
                type="NO_DNS_RECORDS_FOUND",
                semantic_group="domain_legitimacy",
                independence_group="dns_validity",
                value=clean_domain,
                severity=0.75,
                confidence=0.90,
                reliability=0.88,
                freshness=1.0,
                direction="SUPPORTING",
                description=f"Domain '{clean_domain}' has no resolvable MX or A DNS records",
                source="DNS_RESOLVER",
                research_provenance="STANDARD_EMAIL_AUTH"
            ))
        elif has_dns and not lookalike_brand and not is_punycode and not has_suspicious_tld:
            evidence_list.append(Evidence(
                engine="DOMAIN",
                type="VALID_DNS_INFRASTRUCTURE",
                semantic_group="domain_legitimacy",
                independence_group="dns_validity",
                value=clean_domain,
                severity=0.0,
                confidence=0.85,
                reliability=0.85,
                freshness=1.0,
                direction="MITIGATING",
                description=f"Domain '{clean_domain}' has standard verified DNS MX/A infrastructure",
                source="DNS_RESOLVER",
                research_provenance="STANDARD_EMAIL_AUTH"
            ))

        return {
            "domain": clean_domain,
            "has_dns": has_dns,
            "mx_records": mx_list,
            "ns_records": ns_list,
            "a_records": a_list,
            "txt_records": txt_list,
            "lookalike_brand": lookalike_brand,
            "is_punycode": is_punycode,
            "has_suspicious_tld": has_suspicious_tld,
            "evidence": evidence_list
        }
