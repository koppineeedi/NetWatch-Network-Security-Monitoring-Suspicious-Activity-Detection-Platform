from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.threat_intelligence import threat_intel_manager, ip_reputation_service, ip_geolocation_service
from app.threat_intelligence.schemas import ProviderStatusResponse, IPReputationResponse, IPGeolocationResponse
from app.api.deps import get_current_user, require_role
from app.models.user import User

router = APIRouter(prefix="/api/threat-intelligence", tags=["threat-intelligence"])
ip_router = APIRouter(prefix="/api/ip", tags=["ip"])

@router.get("/status")
def get_threat_intel_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns threat intelligence dashboard summary and provider status.
    Requires authentication.
    """
    return threat_intel_manager.get_ti_statistics(db)

@router.get("/providers", response_model=List[ProviderStatusResponse])
def get_providers(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns list of configured Threat Intelligence providers and active status.
    """
    return threat_intel_manager.get_providers_status(db)

@router.post("/providers/{name}/test")
def test_provider(
    name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN", "ANALYST"))
):
    """
    Tests API connectivity and credential validation for a specified TI provider.
    ADMIN and ANALYST allowed. Never returns secrets.
    """
    res = threat_intel_manager.test_provider(name)
    return res

@ip_router.get("/{ip_address}/reputation", response_model=IPReputationResponse)
def get_ip_reputation(
    ip_address: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns IP reputation analysis with DB caching. Requires authentication.
    """
    res = ip_reputation_service.get_ip_reputation(db, ip_address)
    return IPReputationResponse(
        ip_address=res["ip_address"],
        reputation_score=res["reputation_score"],
        abuse_confidence=res["abuse_confidence"],
        country=res.get("country"),
        asn=res.get("asn"),
        organization=res.get("organization"),
        isp=res.get("isp"),
        categories=res.get("categories"),
        provider=res["provider"],
        status=res["status"],
        last_error=res.get("last_error"),
        lookup_timestamp=res["lookup_timestamp"]
    )

@ip_router.get("/{ip_address}/geolocation", response_model=IPGeolocationResponse)
def get_ip_geolocation(
    ip_address: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns IP Geolocation and ASN information. Requires authentication.
    """
    res = ip_geolocation_service.get_ip_geolocation(db, ip_address)
    return IPGeolocationResponse(
        ip_address=res["ip_address"],
        country=res.get("country"),
        country_code=res.get("country_code"),
        region=res.get("region"),
        city=res.get("city"),
        latitude=res.get("latitude"),
        longitude=res.get("longitude"),
        asn=res.get("asn"),
        organization=res.get("organization"),
        provider=res["provider"],
        status=res["status"]
    )
