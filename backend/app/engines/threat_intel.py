import time
import logging
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod

logger = logging.getLogger("tracemail.engines.threat_intel")

class BaseIPReputationProvider(ABC):
    @abstractmethod
    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        pass

class BaseDomainReputationProvider(ABC):
    @abstractmethod
    def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        pass

class BaseURLReputationProvider(ABC):
    @abstractmethod
    def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        pass

class BaseFileHashReputationProvider(ABC):
    @abstractmethod
    def check_file_hash(self, sha256_hash: str) -> Optional[Dict[str, Any]]:
        pass

class ThreatIntelligenceProvider:
    """
    Extensible Threat Intelligence Provider Abstraction.
    Queries configured external threat feeds with caching and timeouts.
    If no feed provider is configured, returns UNKNOWN.
    UNKNOWN is never treated as confirmed CLEAN.
    """
    _cache: Dict[str, Dict[str, Any]] = {}
    _cache_ttl_seconds: int = 3600
    
    ip_providers: list[BaseIPReputationProvider] = []
    domain_providers: list[BaseDomainReputationProvider] = []
    url_providers: list[BaseURLReputationProvider] = []
    file_providers: list[BaseFileHashReputationProvider] = []

    @classmethod
    def _get_cached(cls, key: str) -> Optional[Dict[str, Any]]:
        if key in cls._cache:
            entry = cls._cache[key]
            if time.time() - entry.get("timestamp", 0) < cls._cache_ttl_seconds:
                return entry.get("data")
        return None

    @classmethod
    def _set_cached(cls, key: str, data: Dict[str, Any]):
        cls._cache[key] = {"data": data, "timestamp": time.time()}

    @classmethod
    def check_ip_reputation(cls, ip: str) -> Dict[str, Any]:
        if not ip:
            return {"status": "UNAVAILABLE", "reputation_score": 0.0, "source": "None"}
        
        cached = cls._get_cached(f"ip:{ip}")
        if cached:
            return cached

        for prov in cls.ip_providers:
            try:
                res = prov.check_ip(ip)
                if res:
                    cls._set_cached(f"ip:{ip}", res)
                    return res
            except Exception as e:
                logger.warning(f"Error querying IP threat intel provider: {e}")

        result = {"status": "UNKNOWN", "reputation_score": 0.0, "source": "Unconfigured"}
        cls._set_cached(f"ip:{ip}", result)
        return result

    @classmethod
    def check_domain_reputation(cls, domain: str) -> Dict[str, Any]:
        if not domain or domain.lower() in ["unknown", "localhost"]:
            return {"status": "UNAVAILABLE", "reputation_score": 0.0, "source": "None"}

        clean_domain = domain.strip().lower()
        cached = cls._get_cached(f"dom:{clean_domain}")
        if cached:
            return cached

        for prov in cls.domain_providers:
            try:
                res = prov.check_domain(clean_domain)
                if res:
                    cls._set_cached(f"dom:{clean_domain}", res)
                    return res
            except Exception as e:
                logger.warning(f"Error querying Domain threat intel provider: {e}")

        result = {"status": "UNKNOWN", "reputation_score": 0.0, "source": "Unconfigured"}
        cls._set_cached(f"dom:{clean_domain}", result)
        return result

    @classmethod
    def check_url_reputation(cls, url: str) -> Dict[str, Any]:
        if not url:
            return {"status": "UNAVAILABLE", "reputation_score": 0.0, "source": "None"}

        cached = cls._get_cached(f"url:{url}")
        if cached:
            return cached

        for prov in cls.url_providers:
            try:
                res = prov.check_url(url)
                if res:
                    cls._set_cached(f"url:{url}", res)
                    return res
            except Exception as e:
                logger.warning(f"Error querying URL threat intel provider: {e}")

        result = {"status": "UNKNOWN", "reputation_score": 0.0, "source": "Unconfigured"}
        cls._set_cached(f"url:{url}", result)
        return result

    @classmethod
    def check_file_hash_reputation(cls, sha256_hash: str) -> Dict[str, Any]:
        if not sha256_hash or sha256_hash == "NOT_COMPUTED":
            return {"status": "UNAVAILABLE", "reputation_score": 0.0, "source": "None"}

        cached = cls._get_cached(f"hash:{sha256_hash}")
        if cached:
            return cached

        for prov in cls.file_providers:
            try:
                res = prov.check_file_hash(sha256_hash)
                if res:
                    cls._set_cached(f"hash:{sha256_hash}", res)
                    return res
            except Exception as e:
                logger.warning(f"Error querying File Hash threat intel provider: {e}")

        result = {"status": "UNKNOWN", "reputation_score": 0.0, "source": "Unconfigured"}
        cls._set_cached(f"hash:{sha256_hash}", result)
        return result
