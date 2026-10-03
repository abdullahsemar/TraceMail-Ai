import logging
from typing import Dict, Any, Optional, Set
from app.notifications.telegram import TelegramNotifier

logger = logging.getLogger("tracemail.notifications.manager")

class NotificationManager:
    """
    Central Notification Dispatcher:
    Orchestrates alert channels (Telegram, Webhook, etc.) following Policy Engine decisions.
    Enforces deduplication to prevent duplicate alerts on re-sync, duplicate ingestion, or reprocessing.
    """
    _NOTIFIED_IDENTIFIERS: Set[str] = set()

    @classmethod
    def is_already_notified(cls, identifier: str) -> bool:
        if not identifier:
            return False
        return identifier in cls._NOTIFIED_IDENTIFIERS

    @classmethod
    def mark_notified(cls, identifier: str):
        if identifier:
            cls._NOTIFIED_IDENTIFIERS.add(identifier)

    @classmethod
    def clear_cache(cls):
        """Used in test suites to reset notification tracking."""
        cls._NOTIFIED_IDENTIFIERS.clear()

    @classmethod
    async def dispatch_alerts(
        cls,
        case_number: str,
        sender: str,
        subject: str,
        verdict: Dict[str, Any],
        origin: Optional[Dict[str, Any]] = None,
        source: str = "SMTP_GATEWAY",
        dedup_key: Optional[str] = None
    ) -> bool:
        key = dedup_key or case_number
        if cls.is_already_notified(key):
            logger.info(f"Duplicate alert suppressed for {key}; notification was already sent.")
            return False

        try:
            success = await TelegramNotifier.send_threat_alert(
                case_number=case_number,
                sender=sender,
                subject=subject,
                verdict=verdict,
                origin=origin,
                source=source
            )
            if success:
                cls.mark_notified(key)
            return success
        except Exception as e:
            logger.error(f"Error in NotificationManager dispatch: {e}")
            return False
