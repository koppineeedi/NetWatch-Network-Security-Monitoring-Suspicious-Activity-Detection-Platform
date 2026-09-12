import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.connectors.manager import connector_manager
from app.connectors.schemas import ConnectorCreate, ConnectorUpdate, ConnectorResponse, ConnectorTestResult
from app.api.deps import get_current_user, require_role
from app.models.user import User
from app.models.connector import Connector

router = APIRouter(prefix="/api/connectors", tags=["connectors"])

@router.get("", response_model=List[ConnectorResponse])
def get_connectors(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns list of configured remote network and cloud connectors.
    ADMIN, ANALYST, and VIEWER roles allowed. Secrets are redacted.
    """
    return connector_manager.get_all_connectors(db)

@router.post("", response_model=ConnectorResponse)
def create_connector(
    payload: ConnectorCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN"))
):
    """
    Registers a new network or cloud log connector. ADMIN only.
    """
    existing = db.query(Connector).filter(Connector.connector_id == payload.connector_id).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Connector '{payload.connector_id}' already exists")

    c = Connector(
        connector_id=payload.connector_id,
        name=payload.name,
        connector_type=payload.connector_type,
        status="CONFIGURED",
        config_json=json.dumps(payload.config or {})
    )
    db.add(c)
    db.commit()
    db.refresh(c)
    return connector_manager.get_connector(db, c.connector_id)

@router.get("/{id}", response_model=ConnectorResponse)
def get_connector_by_id(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    c = connector_manager.get_connector(db, id)
    if not c:
        raise HTTPException(status_code=404, detail="Connector not found")
    return c

@router.put("/{id}", response_model=ConnectorResponse)
def update_connector(
    id: str,
    payload: ConnectorUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN"))
):
    c = db.query(Connector).filter((Connector.connector_id == id) | (Connector.id == (int(id) if id.isdigit() else -1))).first()
    if not c:
        raise HTTPException(status_code=404, detail="Connector not found")

    if payload.name:
        c.name = payload.name
    if payload.config is not None:
        c.config_json = json.dumps(payload.config)

    db.commit()
    return connector_manager.get_connector(db, c.connector_id)

@router.delete("/{id}")
def delete_connector(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN"))
):
    c = db.query(Connector).filter((Connector.connector_id == id) | (Connector.id == (int(id) if id.isdigit() else -1))).first()
    if not c:
        raise HTTPException(status_code=404, detail="Connector not found")

    db.delete(c)
    db.commit()
    return {"status": "SUCCESS", "message": f"Connector '{id}' deleted successfully"}

@router.post("/{id}/test", response_model=ConnectorTestResult)
def test_connector(
    id: str,
    config: Optional[dict] = Body(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN", "ANALYST"))
):
    """
    Tests credential and connection status for a connector. ADMIN and ANALYST allowed.
    """
    res = connector_manager.test_connector(db, id, config)
    return ConnectorTestResult(
        connector_id=res.get("connector_id", id),
        status=res.get("status", "ERROR"),
        message=res.get("message", "Connection test failed"),
        details=res.get("details")
    )

@router.post("/{id}/enable", response_model=ConnectorResponse)
def enable_connector(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN"))
):
    res = connector_manager.enable_connector(db, id)
    if not res:
        raise HTTPException(status_code=404, detail="Connector not found")
    return res

@router.post("/{id}/disable", response_model=ConnectorResponse)
def disable_connector(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN"))
):
    res = connector_manager.disable_connector(db, id)
    if not res:
        raise HTTPException(status_code=404, detail="Connector not found")
    return res
