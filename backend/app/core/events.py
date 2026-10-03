import asyncio
import json
from typing import Dict, Any, Set
from fastapi import WebSocket

class EventBroadcaster:
    def __init__(self):
        self._queues: Set[asyncio.Queue] = set()
        self._websockets: Set[WebSocket] = set()

    def subscribe_sse(self) -> asyncio.Queue:
        q = asyncio.Queue()
        self._queues.add(q)
        return q

    def unsubscribe_sse(self, q: asyncio.Queue):
        if q in self._queues:
            self._queues.remove(q)

    async def register_ws(self, ws: WebSocket):
        await ws.accept()
        self._websockets.add(ws)

    def unregister_ws(self, ws: WebSocket):
        if ws in self._websockets:
            self._websockets.remove(ws)

    async def broadcast(self, event_type: str, data: Dict[str, Any]):
        message = {
            "event": event_type,
            "data": data
        }
        raw_msg = json.dumps(message)
        
        # Send to SSE queues
        for q in list(self._queues):
            try:
                await q.put(f"event: {event_type}\ndata: {json.dumps(data)}\n\n")
            except Exception:
                pass
                
        # Send to WebSockets
        for ws in list(self._websockets):
            try:
                await ws.send_text(raw_msg)
            except Exception:
                self.unregister_ws(ws)

broadcaster = EventBroadcaster()
