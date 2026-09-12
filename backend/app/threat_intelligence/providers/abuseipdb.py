import os
import urllib.request
import urllib.parse
import json
import logging
from typing import Dict, Any
from app.threat_intelligence.base import BaseTIProvider

logger = logging.getLogger("netwatch.ti.abuseipdb")

class AbuseIPDBProvider(BaseTIProvider):
    def __init__(self):
        super().__init__(provider_name="abuseipdb", display_name="AbuseIPDB Threat Intelligence")

    def get_api_key(self) -> str:
        return os.getenv("ABUSEIPDB_API_KEY", "").strip()

    def get_status(self) -> Dict[str, Any]:
        key = self.get_api_key()
        return {
            "provider_name": self.provider_name,
            "display_name": self.display_name,
            "status": "CONFIGURED" if key else "NOT_CONFIGURED",
            "enabled": bool(key)
        }

    def test_connection(self) -> Dict[str, Any]:
        key = self.get_api_key()
        if not key:
            return {
                "status": "NOT_CONFIGURED",
                "message": "AbuseIPDB API key is not configured (ABUSEIPDB_API_KEY)"
            }

        try:
            req = urllib.request.Request(
                "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8",
                headers={"Key": key, "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                return {
                    "status": "CONNECTED",
                    "message": "Successfully authenticated with AbuseIPDB API v2",
                    "details": {"abuseConfidenceScore": data.get("data", {}).get("abuseConfidenceScore")}
                }
        except Exception as e:
            logger.warning(f"AbuseIPDB API test failed: {e}")
            return {
                "status": "ERROR",
                "message": f"AbuseIPDB API request error: {str(e)}"
            }

    def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        key = self.get_api_key()
        if not key:
            return {
                "status": "NOT_CONFIGURED",
                "reputation_score": 0.0,
                "abuse_confidence": 0,
                "provider": self.provider_name,
                "message": "ABUSEIPDB_API_KEY is not configured"
            }

        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip_address)}&maxAgeInDays=90"
            req = urllib.request.Request(url, headers={"Key": key, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                raw = json.loads(resp.read().decode())
                data = raw.get("data", {})
                score = float(data.get("abuseConfidenceScore", 0))
                return {
                    "status": "SUCCESS",
                    "reputation_score": score,
                    "abuse_confidence": int(score),
                    "country": data.get("countryCode"),
                    "asn": str(data.get("asn") or ""),
                    "organization": data.get("domain"),
                    "isp": data.get("isp"),
                    "categories": ",".join(map(str, data.get("reports", []))),
                    "provider": self.provider_name
                }
        except Exception as e:
            return {
                "status": "ERROR",
                "reputation_score": 0.0,
                "abuse_confidence": 0,
                "provider": self.provider_name,
                "last_error": str(e)
            }
