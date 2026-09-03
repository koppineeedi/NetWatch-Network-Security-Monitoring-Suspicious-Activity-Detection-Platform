import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, status
from typing import Optional

from app.database.connection import SessionLocal
from app.models.user import User
from app.core.security import decode_access_token
from app.realtime.manager import ws_manager

logger = logging.getLogger("netwatch.ws")
router = APIRouter(prefix="/ws", tags=["websocket"])

@router.websocket("/events")
async def websocket_events_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(None)
):
    """
    Authenticated WebSocket streaming endpoint for real-time telemetry, detections, and alerts.
    Rejects unauthenticated connections immediately.
    """
    # Fallback to Authorization header if query param token is not present
    if not token:
        auth_header = websocket.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

    if not token:
        logger.warning("[WEBSOCKET] Rejected unauthenticated connection: missing token")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Authentication token required")
        return

    payload = decode_access_token(token)
    if not payload or not payload.get("sub"):
        logger.warning("[WEBSOCKET] Rejected unauthenticated connection: invalid token")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid or expired token")
        return

    db = SessionLocal()
    try:
        user_id = int(payload["sub"])
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_active:
            logger.warning(f"[WEBSOCKET] Rejected connection: user_id={user_id} inactive or not found")
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Account disabled or not found")
            return

        # Connect WebSocket client with verified user identity
        await ws_manager.connect(websocket, user_id=str(user.id), role=user.role, username=user.username)

        # Send welcome ack message
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to NetWatch Real-Time SOC Stream",
            "user": user.username,
            "role": user.role
        })

        # Main message loop for heartbeat ping/pong
        while True:
            data = await websocket.receive_json()
            if isinstance(data, dict) and data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.warning(f"[WEBSOCKET] Connection error: {e}")
        ws_manager.disconnect(websocket)
    finally:
        db.close()
