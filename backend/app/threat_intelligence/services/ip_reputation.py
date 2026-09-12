import os
import datetime
from typing import Dict, Any
from sqlalchemy.orm import Session
from app.models.threat_intel import IPReputationCache
from app.threat_intelligence.providers.abuseipdb import AbuseIPDBProvider
from app.threat_intelligence.providers.otx import AlienVaultOTXProvider
from app.threat_intelligence.providers.misp import MISPProvider

CACHE_TTL_MINUTES = int(os.getenv("NETWATCH_TI_CACHE_MINUTES", "60"))

class IPReputationService:
    def __init__(self):
        self.providers = [
            AbuseIPDBProvider(),
            AlienVaultOTXProvider(),
            MISPProvider()
        ]

    def get_ip_reputation(self, db: Session, ip_address: str) -> Dict[str, Any]:
        """
        Retrieves IP reputation score from database cache or external providers.
        Cached entries within NETWATCH_TI_CACHE_MINUTES TTL are returned immediately.
        """
        if not ip_address or ip_address in ("127.0.0.1", "0.0.0.0", "localhost", "::1"):
            return {
                "ip_address": ip_address,
                "reputation_score": 0.0,
                "abuse_confidence": 0,
                "country": "LOCAL",
                "asn": "INTERNAL",
                "organization": "Local Loopback / Private Network",
                "isp": "Local System",
                "categories": "LOCAL_MACHINE",
                "provider": "LOCAL",
                "status": "SUCCESS",
                "last_error": None,
                "lookup_timestamp": datetime.datetime.utcnow().isoformat()
            }

        # Check DB cache
        now = datetime.datetime.utcnow()
        cache_entry = db.query(IPReputationCache).filter(IPReputationCache.ip_address == ip_address).first()

        if cache_entry:
            age_minutes = (now - cache_entry.lookup_timestamp).total_seconds() / 60.0
            if age_minutes < CACHE_TTL_MINUTES:
                return {
                    "ip_address": cache_entry.ip_address,
                    "reputation_score": cache_entry.reputation_score,
                    "abuse_confidence": cache_entry.abuse_confidence,
                    "country": cache_entry.country,
                    "asn": cache_entry.asn,
                    "organization": cache_entry.organization,
                    "isp": cache_entry.isp,
                    "categories": cache_entry.categories,
                    "provider": cache_entry.provider,
                    "status": cache_entry.status,
                    "last_error": cache_entry.last_error,
                    "lookup_timestamp": cache_entry.lookup_timestamp.isoformat()
                }

        # Query configured active provider
        active_provider = None
        for p in self.providers:
            if p.get_status().get("enabled"):
                active_provider = p
                break

        if not active_provider:
            # Fallback if no TI provider keys configured
            res = {
                "ip_address": ip_address,
                "reputation_score": 0.0,
                "abuse_confidence": 0,
                "country": None,
                "asn": None,
                "organization": None,
                "isp": None,
                "categories": None,
                "provider": "NONE",
                "status": "NOT_CONFIGURED",
                "last_error": "No active threat intelligence provider credentials configured",
                "lookup_timestamp": now.isoformat()
            }
            return res

        lookup_res = active_provider.lookup_ip(ip_address)

        # Update or create DB cache record
        if not cache_entry:
            cache_entry = IPReputationCache(ip_address=ip_address)
            db.add(cache_entry)

        cache_entry.reputation_score = lookup_res.get("reputation_score", 0.0)
        cache_entry.abuse_confidence = lookup_res.get("abuse_confidence", 0)
        cache_entry.country = lookup_res.get("country")
        cache_entry.asn = lookup_res.get("asn")
        cache_entry.organization = lookup_res.get("organization")
        cache_entry.isp = lookup_res.get("isp")
        cache_entry.categories = lookup_res.get("categories")
        cache_entry.provider = lookup_res.get("provider", "UNKNOWN")
        cache_entry.status = lookup_res.get("status", "SUCCESS")
        cache_entry.last_error = lookup_res.get("last_error")
        cache_entry.lookup_timestamp = now

        db.commit()

        return {
            "ip_address": cache_entry.ip_address,
            "reputation_score": cache_entry.reputation_score,
            "abuse_confidence": cache_entry.abuse_confidence,
            "country": cache_entry.country,
            "asn": cache_entry.asn,
            "organization": cache_entry.organization,
            "isp": cache_entry.isp,
            "categories": cache_entry.categories,
            "provider": cache_entry.provider,
            "status": cache_entry.status,
            "last_error": cache_entry.last_error,
            "lookup_timestamp": cache_entry.lookup_timestamp.isoformat()
        }

ip_reputation_service = IPReputationService()
