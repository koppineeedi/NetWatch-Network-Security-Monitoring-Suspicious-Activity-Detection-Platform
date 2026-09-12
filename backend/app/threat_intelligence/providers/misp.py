import os
import urllib.request
import urllib.parse
import json
import logging
from typing import Dict, Any
from app.threat_intelligence.base import BaseTIProvider

logger = logging.getLogger("netwatch.ti.misp")

class MISPProvider(BaseTIProvider):
    def __init__(self):
        super().__init__(provider_name="misp", display_name="MISP Threat Sharing Platform")

    def get_config(self) -> Dict[str, str]:
        return {
            "url": os.getenv("MISP_URL", "").strip(),
            "key": os.getenv("MISP_API_KEY", "").strip()
        }

    def get_status(self) -> Dict[str, Any]:
        cfg = self.get_config()
        configured = bool(cfg["url"] and cfg["key"])
        return {
            "provider_name": self.provider_name,
            "display_name": self.display_name,
            "status": "CONFIGURED" if configured else "NOT_CONFIGURED",
            "enabled": configured
        }

    def test_connection(self) -> Dict[str, Any]:
        cfg = self.get_config()
        if not cfg["url"] or not cfg["key"]:
            return {
                "status": "NOT_CONFIGURED",
                "message": "MISP URL or API key is not configured (MISP_URL, MISP_API_KEY)"
            }

        try:
            endpoint = f"{cfg['url'].rstrip('/')}/servers/getPyMISPVersion.json"
            req = urllib.request.Request(
                endpoint,
                headers={"Authorization": cfg["key"], "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                return {
                    "status": "CONNECTED",
                    "message": "Successfully authenticated with MISP API",
                    "details": {"version": data.get("version")}
                }
        except Exception as e:
            return {
                "status": "ERROR",
                "message": f"MISP API request error: {str(e)}"
            }

    def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        cfg = self.get_config()
        if not cfg["url"] or not cfg["key"]:
            return {
                "status": "NOT_CONFIGURED",
                "reputation_score": 0.0,
                "abuse_confidence": 0,
                "provider": self.provider_name,
                "message": "MISP server URL or API key is not configured"
            }

        try:
            endpoint = f"{cfg['url'].rstrip('/')}/attributes/restSearch"
            payload = json.dumps({"value": ip_address, "type": "ip-src"}).encode("utf-8")
            req = urllib.request.Request(
                endpoint,
                data=payload,
                headers={"Authorization": cfg["key"], "Accept": "application/json", "Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                attributes = data.get("response", {}).get("Attribute", [])
                match_count = len(attributes)
                score = min(100.0, float(match_count * 25.0))
                return {
                    "status": "SUCCESS",
                    "reputation_score": score,
                    "abuse_confidence": int(score),
                    "country": None,
                    "asn": None,
                    "organization": "MISP Attribute Match",
                    "isp": None,
                    "categories": f"MISP Matches: {match_count}",
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
