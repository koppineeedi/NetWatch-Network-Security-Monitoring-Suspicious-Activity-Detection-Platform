import json
import datetime
import re
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.threat_intel import IOC, ThreatIntelProvider, IOCMatch
from app.threat_intelligence.providers.abuseipdb import AbuseIPDBProvider
from app.threat_intelligence.providers.otx import AlienVaultOTXProvider
from app.threat_intelligence.providers.misp import MISPProvider
from app.threat_intelligence.services.ioc_matcher import normalize_ioc_value

class ThreatIntelManager:
    def __init__(self):
        self.providers = {
            "abuseipdb": AbuseIPDBProvider(),
            "alienvault_otx": AlienVaultOTXProvider(),
            "misp": MISPProvider()
        }

    def seed_providers(self, db: Session):
        existing = {p.provider_name for p in db.query(ThreatIntelProvider).all()}
        defaults = [
            ("abuseipdb", "AbuseIPDB Threat Intelligence"),
            ("alienvault_otx", "AlienVault OTX Threat Intelligence"),
            ("misp", "MISP Threat Sharing Platform")
        ]

        for pname, dname in defaults:
            if pname not in existing:
                provider_obj = self.providers.get(pname)
                status_info = provider_obj.get_status() if provider_obj else {}
                p = ThreatIntelProvider(
                    provider_name=pname,
                    display_name=dname,
                    status=status_info.get("status", "NOT_CONFIGURED"),
                    enabled=status_info.get("enabled", False)
                )
                db.add(p)
        db.commit()

    def get_providers_status(self, db: Session) -> List[Dict[str, Any]]:
        self.seed_providers(db)
        db_providers = db.query(ThreatIntelProvider).all()
        result = []
        for p in db_providers:
            provider_obj = self.providers.get(p.provider_name)
            current_status = provider_obj.get_status() if provider_obj else {}
            ioc_cnt = db.query(IOC).filter(IOC.source == p.provider_name).count()
            
            result.append({
                "provider_name": p.provider_name,
                "display_name": p.display_name,
                "status": current_status.get("status", p.status),
                "enabled": current_status.get("enabled", p.enabled),
                "ioc_count": ioc_cnt,
                "last_sync": p.last_sync.isoformat() if p.last_sync else None,
                "last_error": p.last_error
            })
        return result

    def test_provider(self, provider_name: str) -> Dict[str, Any]:
        provider_obj = self.providers.get(provider_name.lower())
        if not provider_obj:
            return {"status": "ERROR", "message": f"Unknown provider '{provider_name}'"}
        return provider_obj.test_connection()

    def get_ti_statistics(self, db: Session) -> Dict[str, Any]:
        now = datetime.datetime.utcnow()
        total_iocs = db.query(IOC).count()
        active_iocs = db.query(IOC).filter((IOC.expiration == None) | (IOC.expiration >= now)).count()
        expired_iocs = total_iocs - active_iocs
        recent_matches = db.query(IOCMatch).order_by(IOCMatch.timestamp.desc()).limit(10).all()
        high_conf_matches = db.query(IOCMatch).filter(IOCMatch.confidence >= 80).count()

        return {
            "total_iocs": total_iocs,
            "active_iocs": active_iocs,
            "expired_iocs": expired_iocs,
            "providers": self.get_providers_status(db),
            "recent_matches_count": len(recent_matches),
            "high_confidence_matches_count": high_conf_matches,
            "recent_matches": [
                {
                    "id": m.id,
                    "ioc_value": m.ioc_value,
                    "ioc_type": m.ioc_type,
                    "matched_field": m.matched_field,
                    "provider": m.provider,
                    "confidence": m.confidence,
                    "severity": m.severity,
                    "timestamp": m.timestamp.isoformat()
                }
                for m in recent_matches
            ]
        }

    def import_ioc_feed_file(self, db: Session, filename: str, content: str, source_label: str = "MANUAL_UPLOAD") -> Dict[str, Any]:
        """
        Parses uploaded JSON, CSV, or TXT feed content, normalizes IOC records, avoids duplicates, and persists to DB.
        """
        lines = content.strip().splitlines()
        records_received = len(lines)
        records_accepted = 0
        records_rejected = 0

        now = datetime.datetime.utcnow()
        ip_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        domain_regex = r'\b[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
        hash32_regex = r'\b[a-fA-F0-9]{32}\b'
        hash64_regex = r'\b[a-fA-F0-9]{64}\b'

        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith('#') or line_str.startswith('//'):
                continue
            if line_str.lower().startswith("ioc_value") or line_str.lower().startswith("indicator") or line_str.lower().startswith("ioc,") or line_str.lower().startswith("value,"):
                continue

            detected_val = None
            detected_type = None

            # Detect format
            if re.match(ip_regex, line_str):
                detected_val = line_str
                detected_type = "IP"
            elif re.match(hash64_regex, line_str):
                detected_val = line_str
                detected_type = "HASH_SHA256"
            elif re.match(hash32_regex, line_str):
                detected_val = line_str
                detected_type = "HASH_MD5"
            elif re.match(domain_regex, line_str):
                detected_val = line_str
                detected_type = "DOMAIN"
            elif "," in line_str:
                parts = [p.strip() for p in line_str.split(",")]
                if len(parts) >= 2:
                    detected_val = parts[0]
                    detected_type = parts[1].upper()

            if not detected_val or not detected_type:
                records_rejected += 1
                continue

            norm_val = normalize_ioc_value(detected_val, detected_type)
            
            # Deduplication
            existing = db.query(IOC).filter(
                IOC.normalized_value == norm_val,
                IOC.ioc_type == detected_type
            ).first()

            if existing:
                existing.last_seen = now
                records_accepted += 1
            else:
                ioc = IOC(
                    ioc_value=detected_val,
                    normalized_value=norm_val,
                    ioc_type=detected_type,
                    source=source_label,
                    confidence=85,
                    severity="HIGH",
                    first_seen=now,
                    last_seen=now,
                    tags="feed_import"
                )
                db.add(ioc)
                records_accepted += 1

        db.commit()

        return {
            "filename": filename,
            "source": source_label,
            "records_received": records_received,
            "records_accepted": records_accepted,
            "records_rejected": records_rejected,
            "status": "SUCCESS"
        }

threat_intel_manager = ThreatIntelManager()
