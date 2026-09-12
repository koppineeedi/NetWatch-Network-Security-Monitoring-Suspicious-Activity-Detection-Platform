import os
import datetime
from typing import Dict, Any
from sqlalchemy.orm import Session
from app.models.threat_intel import IPGeolocationCache

class IPGeolocationService:
    def get_ip_geolocation(self, db: Session, ip_address: str) -> Dict[str, Any]:
        """
        Retrieves IP Geolocation & ASN information from DB cache or provider adapter.
        """
        if not ip_address or ip_address in ("127.0.0.1", "0.0.0.0", "localhost", "::1"):
            return {
                "ip_address": ip_address,
                "country": "LOCAL",
                "country_code": "LO",
                "region": "Local Machine",
                "city": "Internal",
                "latitude": 0.0,
                "longitude": 0.0,
                "asn": "PRIVATE",
                "organization": "Local Loopback",
                "provider": "LOCAL",
                "status": "SUCCESS"
            }

        now = datetime.datetime.utcnow()
        cache_entry = db.query(IPGeolocationCache).filter(IPGeolocationCache.ip_address == ip_address).first()

        if cache_entry:
            return {
                "ip_address": cache_entry.ip_address,
                "country": cache_entry.country,
                "country_code": cache_entry.country_code,
                "region": cache_entry.region,
                "city": cache_entry.city,
                "latitude": cache_entry.latitude,
                "longitude": cache_entry.longitude,
                "asn": cache_entry.asn,
                "organization": cache_entry.organization,
                "provider": cache_entry.provider,
                "status": cache_entry.status
            }

        # Check if MaxMind / GeoIP API key present in env
        geoip_key = os.getenv("MAXMIND_LICENSE_KEY") or os.getenv("GEOIP_API_KEY")
        if not geoip_key:
            return {
                "ip_address": ip_address,
                "country": None,
                "country_code": None,
                "region": None,
                "city": None,
                "latitude": None,
                "longitude": None,
                "asn": None,
                "organization": None,
                "provider": "NONE",
                "status": "NOT_CONFIGURED"
            }

        # Save placeholder for missing external key setup
        cache_entry = IPGeolocationCache(
            ip_address=ip_address,
            provider="GEOIP_API",
            status="NOT_CONFIGURED"
        )
        db.add(cache_entry)
        db.commit()

        return {
            "ip_address": ip_address,
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "asn": None,
            "organization": None,
            "provider": "NONE",
            "status": "NOT_CONFIGURED"
        }

ip_geolocation_service = IPGeolocationService()
