import logging
from typing import List, Dict, Any, Optional
from app.connectors.base import BaseMailConnector

logger = logging.getLogger("tracemail.connectors.outlook")

class OutlookConnector(BaseMailConnector):
    async def connect(self) -> bool:
        return bool(self.credentials.get("access_token"))

    async def disconnect(self) -> bool:
        return True

    async def get_account(self) -> Dict[str, Any]:
        return {
            "provider": "OUTLOOK",
            "account_email": self.account_email or "Not Connected",
            "status": "NOT_CONFIGURED" if not self.credentials.get("access_token") else "CONNECTED",
            "sync_mode": "GRAPH_WEBHOOK_NOTIFICATIONS"
        }

    async def list_recent_messages(self, limit: int = 20) -> List[Dict[str, Any]]:
        return []

    async def get_raw_message(self, message_id: str) -> bytes:
        return b""

    async def get_changes(self) -> List[Dict[str, Any]]:
        return []
