import os
import urllib.request
import urllib.parse
import json
import logging
from typing import Dict, Any
from app.threat_intelligence.base import BaseTIProvider

logger = logging.getLogger("netwatch.ti.otx")

class AlienVaultOTXProvider(BaseTIProvider):
    def __init__(self):
        super().__init__(provider_name="alienvault_otx", display_name="AlienVault OTX Threat Intelligence")

    def get_api_key(self) -> str:
        return os.getenv("OTX_API_KEY", "").strip()

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
                "message": "AlienVault OTX API key is not configured (OTX_API_KEY)"
            }

        try:
            req = urllib.request.Request(
                "https://otx.alienvault.com/api/v1/user/me",
                headers={"X-OTX-API-KEY": key, "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                return {
                    "status": "CONNECTED",
                    "message": f"Successfully authenticated with AlienVault OTX (User: {data.get('username')})",
                    "details": {"username": data.get("username")}
                }
        except Exception as e:
            return {
                "status": "ERROR",
                "message": f"AlienVault OTX API request error: {str(e)}"
            }

    def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        key = self.get_api_key()
        if not key:
            return {
                "status": "NOT_CONFIGURED",
                "reputation_score": 0.0,
                "abuse_confidence": 0,
                "provider": self.provider_name,
                "message": "OTX_API_KEY is not configured"
            }

        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{urllib.parse.quote(ip_address)}/general"
            req = urllib.request.Request(url, headers={"X-OTX-API-KEY": key, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                score = min(100.0, float(pulse_count * 20.0))
                return {
                    "status": "SUCCESS",
                    "reputation_score": score,
                    "abuse_confidence": int(score),
                    "country": data.get("country_name"),
                    "asn": str(data.get("asn") or ""),
                    "organization": data.get("asn"),
                    "isp": None,
                    "categories": f"OTX Pulses: {pulse_count}",
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
