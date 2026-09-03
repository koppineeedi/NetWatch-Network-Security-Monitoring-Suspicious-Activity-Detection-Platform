import logging
import asyncio
from typing import Dict, Any, List
from fastapi import WebSocket

logger = logging.getLogger("netwatch.realtime")

class ConnectionManager:
    def __init__(self):
        # Maps active WebSocket connection to client metadata
        self.active_connections: Dict[WebSocket, Dict[str, Any]] = {}

    async def connect(self, websocket: WebSocket, user_id: str, role: str, username: str):
        """
        Accepts WebSocket connection and registers client metadata.
        """
        await websocket.accept()
        self.active_connections[websocket] = {
            "user_id": user_id,
            "role": role,
            "username": username
        }
        logger.info(f"[WEBSOCKET] Client connected: user={username} role={role} (Total: {len(self.active_connections)})")

    def disconnect(self, websocket: WebSocket):
        """
        Removes WebSocket connection upon client disconnect or error.
        """
        if websocket in self.active_connections:
            meta = self.active_connections.pop(websocket)
            logger.info(f"[WEBSOCKET] Client disconnected: user={meta['username']} (Total: {len(self.active_connections)})")

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """
        Sends JSON payload to a specific connected client.
        """
        if websocket in self.active_connections:
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.warning(f"[WEBSOCKET] Error sending message to client: {e}")
                self.disconnect(websocket)

    async def broadcast(self, message: dict):
        """
        Safely broadcasts JSON payload to all active connected clients.
        Failing client sockets are caught and disconnected without interrupting broadcast to others.
        """
        if not self.active_connections:
            return

        disconnected_clients: List[WebSocket] = []
        for ws in list(self.active_connections.keys()):
            try:
                await ws.send_json(message)
            except Exception as e:
                logger.warning(f"[WEBSOCKET] Broadcast send failed for client: {e}")
                disconnected_clients.append(ws)

        for ws in disconnected_clients:
            self.disconnect(ws)

# Singleton manager instance
ws_manager = ConnectionManager()
