import re
import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.threat_intel import IOC, IOCMatch
from app.models.event import NetworkEvent
from app.realtime.manager import ws_manager

def validate_ioc(value: str) -> tuple[bool, str]:
    """
    Validates an IOC string format and returns (is_valid, ioc_type).
    """
    if not value or not isinstance(value, str):
        return False, "UNKNOWN"

    val = value.strip()
    
    # IPv4 regex
    if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', val):
        parts = val.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            return True, "IP"

    # Hashes
    if re.match(r'^[a-fA-F0-9]{32}$', val):
        return True, "HASH_MD5"
    if re.match(r'^[a-fA-F0-9]{40}$', val):
        return True, "HASH_SHA1"
    if re.match(r'^[a-fA-F0-9]{64}$', val):
        return True, "HASH_SHA256"

    # Email
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', val):
        return True, "EMAIL"

    # Domain
    cleaned = val.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    if re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', cleaned):
        return True, "DOMAIN"

    return False, "UNKNOWN"

def normalize_ioc_value(val: str, ioc_type: str = "UNKNOWN") -> str:
    """
    Normalizes IOC string values to standard canonical lowercase formats.
    """
    if not val:
        return ""

    cleaned_val = val.strip()
    if not ioc_type or ioc_type == "UNKNOWN":
        _, detected_type = validate_ioc(cleaned_val)
        ioc_type = detected_type
    else:
        ioc_type = ioc_type.upper()

    if ioc_type in ("DOMAIN", "EMAIL", "HASH_MD5", "HASH_SHA1", "HASH_SHA256"):
        norm = cleaned_val.lower()
        if norm.startswith("http://") or norm.startswith("https://"):
            norm = norm.split("://", 1)[1].split("/")[0]
        return norm
    elif ioc_type == "URL":
        return cleaned_val.lower().rstrip('/')
    elif ioc_type == "IP":
        return cleaned_val.lower()
    
    return cleaned_val

class IOCMatcherService:
    def match_value(self, db: Session, value: str, field_name: str = "ip_address") -> List[IOC]:
        """
        Matches a single string value against active IOC records in the database.
        """
        if not value:
            return []

        norm_val = value.strip().lower()
        now = datetime.datetime.utcnow()
        
        matches = db.query(IOC).filter(
            IOC.normalized_value == norm_val,
            (IOC.expiration == None) | (IOC.expiration >= now)
        ).all()
        return matches

    def match_event(self, db: Session, event: NetworkEvent) -> List[IOCMatch]:
        """
        Scans an ingested NetworkEvent's fields (source_ip, dest_ip, payload) against IOC database records.
        Saves IOCMatch records, enriches the event, and broadcasts WebSocket IOC_MATCH alerts.
        """
        if not event:
            return []

        fields_to_check = []
        if event.source_ip:
            fields_to_check.append(("source_ip", event.source_ip, "IP"))
        if event.dest_ip:
            fields_to_check.append(("dest_ip", event.dest_ip, "IP"))

        if event.payload_summary:
            # Extract domains/hashes from payload text
            domain_matches = re.findall(r'\b[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b', event.payload_summary)
            for d in set(domain_matches):
                fields_to_check.append(("payload_domain", d, "DOMAIN"))

            hash_matches = re.findall(r'\b[a-fA-F0-9]{32,64}\b', event.payload_summary)
            for h in set(hash_matches):
                htype = "HASH_MD5" if len(h) == 32 else "HASH_SHA256"
                fields_to_check.append(("payload_hash", h, htype))

        created_matches = []
        now = datetime.datetime.utcnow()

        for field_name, raw_val, ioc_type in fields_to_check:
            norm_val = normalize_ioc_value(raw_val, ioc_type)
            matching_iocs = db.query(IOC).filter(
                IOC.normalized_value == norm_val,
                (IOC.expiration == None) | (IOC.expiration >= now)
            ).all()

            for ioc in matching_iocs:
                # Deduplication: Check if identical match already recorded for this event
                existing = db.query(IOCMatch).filter(
                    IOCMatch.event_id == event.id,
                    IOCMatch.ioc_id == ioc.id
                ).first()

                if existing:
                    continue

                match_rec = IOCMatch(
                    event_id=event.id,
                    ioc_id=ioc.id,
                    ioc_value=ioc.ioc_value,
                    ioc_type=ioc.ioc_type,
                    matched_field=field_name,
                    provider=ioc.source,
                    confidence=ioc.confidence,
                    severity=ioc.severity,
                    tags=ioc.tags,
                    timestamp=now
                )
                db.add(match_rec)

                # Flag network event
                event.status = "FLAGGED"
                event.risk_score = max(event.risk_score or 0.0, float(ioc.confidence))

                db.commit()
                db.refresh(match_rec)
                created_matches.append(match_rec)

                # Broadcast real-time WebSocket IOC_MATCH notification
                if ws_manager.active_connections:
                    payload = {
                        "type": "IOC_MATCH",
                        "timestamp": now.isoformat(),
                        "data": {
                            "id": match_rec.id,
                            "event_id": event.id,
                            "ioc_type": ioc.ioc_type,
                            "value": ioc.ioc_value,
                            "matched_field": field_name,
                            "provider": ioc.source,
                            "confidence": ioc.confidence,
                            "severity": ioc.severity,
                            "tags": ioc.tags
                        }
                    }
                    try:
                        import asyncio
                        loop = asyncio.get_event_loop()
                        if loop.is_running():
                            loop.create_task(ws_manager.broadcast(payload))
                    except Exception:
                        pass

        return created_matches

ioc_matcher_service = IOCMatcherService()
