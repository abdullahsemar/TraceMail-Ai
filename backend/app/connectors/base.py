from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

class BaseMailConnector(ABC):
    """
    Abstract Base Class for Connected-Mailbox Monitoring.
    Secondary Ingestion Source (Post-Arrival Monitoring).
    """

    def __init__(self, connection_id: str, account_email: str, credentials: Optional[Dict[str, Any]] = None):
        self.connection_id = connection_id
        self.account_email = account_email
        self.credentials = credentials or {}

    @abstractmethod
    async def connect(self) -> bool:
        """Establish authorized connection with provider."""
        pass

    @abstractmethod
    async def disconnect(self) -> bool:
        """Terminate connection / revoke session."""
        pass

    @abstractmethod
    async def get_account(self) -> Dict[str, Any]:
        """Return account profile metadata."""
        pass

    @abstractmethod
    async def list_recent_messages(self, limit: int = 20) -> List[Dict[str, Any]]:
        """List summary of recent messages."""
        pass

    @abstractmethod
    async def get_raw_message(self, message_id: str) -> bytes:
        """Retrieve full RFC822 raw bytes required by forensic pipeline."""
        pass

    @abstractmethod
    async def get_changes(self) -> List[Dict[str, Any]]:
        """Near-realtime delta synchronization (Webhooks / PubSub / Polling fallback)."""
        pass
