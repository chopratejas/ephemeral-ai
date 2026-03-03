"""WebSocket manager for real-time task event streaming."""

import json
import logging
from collections import defaultdict

from fastapi import WebSocket

logger = logging.getLogger("ephemeral.ws")


class WebSocketManager:
    """Manages WebSocket connections per task for real-time event streaming."""

    def __init__(self):
        self.connections: dict[str, list[WebSocket]] = defaultdict(list)

    async def connect(self, task_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self.connections[task_id].append(websocket)
        logger.info(
            "WebSocket connected for task %s (total: %d)",
            task_id,
            len(self.connections[task_id]),
        )

    def disconnect(self, task_id: str, websocket: WebSocket) -> None:
        if task_id in self.connections:
            self.connections[task_id] = [
                ws for ws in self.connections[task_id] if ws != websocket
            ]
            if not self.connections[task_id]:
                del self.connections[task_id]

    async def broadcast(self, task_id: str, event: str, data: dict) -> None:
        """Send an event to all WebSocket clients subscribed to a task."""
        message = json.dumps({"event": event, "data": data})
        dead = []

        for ws in self.connections.get(task_id, []):
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.disconnect(task_id, ws)


ws_manager = WebSocketManager()
