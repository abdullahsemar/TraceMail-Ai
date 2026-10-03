import os
import json
import base64
import logging
import urllib.parse
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
import httpx

from app.config import settings, get_google_oauth_config
from app.connectors.base import BaseMailConnector
from app.gateway.handler import InboundPipelineProcessor

logger = logging.getLogger("tracemail.connectors.gmail")

class GmailConnector(BaseMailConnector):
    GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
    GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"
    
    SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

    def __init__(self, connection_id: str = "gmail-primary", account_email: str = ""):
        super().__init__(connection_id=connection_id, account_email=account_email)
        self.tokens: Dict[str, Any] = self._load_stored_tokens()
        if self.tokens.get("email"):
            self.account_email = self.tokens["email"]

    def _load_stored_tokens(self) -> Dict[str, Any]:
        if os.path.exists(settings.GOOGLE_TOKENS_STORAGE):
            try:
                with open(settings.GOOGLE_TOKENS_STORAGE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading stored Google tokens: {e}")
        return {}

    def _save_stored_tokens(self, token_data: Dict[str, Any]):
        self.tokens = token_data
        try:
            with open(settings.GOOGLE_TOKENS_STORAGE, "w", encoding="utf-8") as f:
                json.dump(token_data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving Google tokens to disk: {e}")

    def is_configured(self) -> bool:
        cfg = get_google_oauth_config()
        return cfg is not None and bool(cfg.get("client_id") and cfg.get("client_secret"))

    def is_connected(self) -> bool:
        return bool(self.tokens.get("access_token") or self.tokens.get("refresh_token"))

    def get_authorization_url(self, state: str) -> str:
        cfg = get_google_oauth_config()
        if not cfg:
            raise ValueError("Google OAuth credentials are not configured in backend/.env")

        params = {
            "client_id": cfg["client_id"],
            "redirect_uri": cfg.get("redirect_uri", "http://localhost:8000/api/connectors/gmail/callback"),
            "response_type": "code",
            "scope": " ".join(self.SCOPES),
            "access_type": "offline",
            "prompt": "consent",
            "state": state
        }
        return f"{self.GOOGLE_AUTH_URL}?{urllib.parse.urlencode(params)}"

    async def exchange_code(self, code: str) -> Dict[str, Any]:
        cfg = get_google_oauth_config()
        if not cfg:
            raise ValueError("Google OAuth configuration is missing")

        data = {
            "client_id": cfg["client_id"],
            "client_secret": cfg["client_secret"],
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": cfg.get("redirect_uri", "http://localhost:8000/api/connectors/gmail/callback")
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(self.GOOGLE_TOKEN_URL, data=data)
            if resp.status_code != 200:
                logger.error(f"OAuth code exchange failed with status {resp.status_code}")
                raise ValueError("Google token exchange failed. Please verify client configuration.")
            token_response = resp.json()

        access_token = token_response.get("access_token")
        profile = await self._fetch_profile_with_token(access_token)

        token_data = {
            "access_token": access_token,
            "refresh_token": token_response.get("refresh_token"),
            "expires_in": token_response.get("expires_in"),
            "token_type": token_response.get("token_type", "Bearer"),
            "email": profile.get("emailAddress", "unknown@gmail.com"),
            "history_id": profile.get("historyId"),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "monitoring_mode": "DEVELOPMENT_POLLING"
        }
        self._save_stored_tokens(token_data)
        self.account_email = token_data["email"]

        # Run initial safe inbox sync upon connection
        try:
            await self.sync_inbox(limit=settings.GMAIL_INITIAL_SYNC_LIMIT)
        except Exception as sync_err:
            logger.warning(f"Initial Gmail inbox sync encountered: {sync_err}")

        return {"email": token_data["email"], "monitoring_mode": token_data["monitoring_mode"]}

    async def refresh_credentials(self) -> Optional[str]:
        cfg = get_google_oauth_config()
        refresh_token = self.tokens.get("refresh_token")
        if not cfg or not refresh_token:
            return None

        data = {
            "client_id": cfg["client_id"],
            "client_secret": cfg["client_secret"],
            "refresh_token": refresh_token,
            "grant_type": "refresh_token"
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(self.GOOGLE_TOKEN_URL, data=data)
            if resp.status_code == 200:
                new_tokens = resp.json()
                self.tokens["access_token"] = new_tokens["access_token"]
                self.tokens["updated_at"] = datetime.now(timezone.utc).isoformat()
                self._save_stored_tokens(self.tokens)
                return self.tokens["access_token"]
            else:
                logger.error(f"Failed to refresh Google token (status {resp.status_code})")
                return None

    async def _get_valid_access_token(self) -> Optional[str]:
        if not self.tokens.get("access_token"):
            return None
        return self.tokens.get("access_token")

    async def _fetch_profile_with_token(self, token: str) -> Dict[str, Any]:
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.GMAIL_API_BASE}/profile", headers=headers)
            if resp.status_code == 200:
                return resp.json()
        return {}

    async def connect(self) -> bool:
        return self.is_connected()

    async def disconnect(self) -> bool:
        try:
            await self.stop_watch()
        except Exception:
            pass
        self.tokens = {}
        if os.path.exists(settings.GOOGLE_TOKENS_STORAGE):
            try:
                os.remove(settings.GOOGLE_TOKENS_STORAGE)
            except Exception:
                pass
        return True

    async def get_account(self) -> Dict[str, Any]:
        # Never expose access_token or refresh_token in response
        return {
            "provider": "GMAIL",
            "account_email": self.tokens.get("email") or self.account_email or "Not Connected",
            "status": "CONNECTED" if self.is_connected() else ("NOT_CONFIGURED" if not self.is_configured() else "DISCONNECTED"),
            "monitoring_enabled": bool(self.tokens.get("watch_active") or self.tokens.get("monitoring_mode")),
            "monitoring_mode": self.tokens.get("monitoring_mode", "DEVELOPMENT_POLLING"),
            "last_sync": self.tokens.get("last_sync", self.tokens.get("updated_at")),
            "watch_expiration": self.tokens.get("watch_expiration"),
            "history_id": self.tokens.get("history_id")
        }

    async def get_raw_message(self, message_id: str) -> bytes:
        token = await self._get_valid_access_token()
        if not token:
            raise ValueError("Gmail connector is not authenticated")

        headers = {"Authorization": f"Bearer {token}"}
        url = f"{self.GMAIL_API_BASE}/messages/{message_id}?format=raw"

        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 401:
                token = await self.refresh_credentials()
                if token:
                    headers = {"Authorization": f"Bearer {token}"}
                    resp = await client.get(url, headers=headers)

            if resp.status_code != 200:
                raise ValueError(f"Failed to fetch Gmail message {message_id}: status {resp.status_code}")

            msg_json = resp.json()
            raw_b64 = msg_json.get("raw", "")
            raw_bytes = base64.urlsafe_b64decode(raw_b64.encode("ASCII"))
            return raw_bytes

    async def list_recent_messages(self, limit: int = 10) -> List[Dict[str, Any]]:
        token = await self._get_valid_access_token()
        if not token:
            return []

        headers = {"Authorization": f"Bearer {token}"}
        url = f"{self.GMAIL_API_BASE}/messages?maxResults={limit}"

        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.json().get("messages", [])
        return []

    async def sync_inbox(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Synchronizes recent real emails from the connected Gmail INBOX.
        Uses message ID / SHA-256 deduplication to avoid re-processing existing emails.
        """
        token = await self._get_valid_access_token()
        if not token:
            raise ValueError("Gmail connector is not authenticated. Please authorize with Google OAuth first.")

        sync_limit = limit or getattr(settings, "GMAIL_INITIAL_SYNC_LIMIT", 25)
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{self.GMAIL_API_BASE}/messages?labelIds=INBOX&maxResults={sync_limit}"

        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 401:
                token = await self.refresh_credentials()
                if token:
                    headers = {"Authorization": f"Bearer {token}"}
                    resp = await client.get(url, headers=headers)

            if resp.status_code != 200:
                logger.error(f"Failed to list Gmail inbox messages: status {resp.status_code}")
                raise ValueError(f"Gmail API error: status {resp.status_code}")

            msg_list = resp.json().get("messages", [])

        from app.database.session import SessionLocal
        from app.database.models import EmailRecord

        db = SessionLocal()
        existing_gateway_ids = {
            r[0] for r in db.query(EmailRecord.gateway_message_id).all()
        }
        db.close()

        processed_records = []
        for item in msg_list:
            msg_id = item.get("id")
            if not msg_id:
                continue

            expected_id = f"GMAIL-{msg_id}"
            if expected_id in existing_gateway_ids:
                logger.debug(f"Gmail message {msg_id} already indexed; skipping.")
                continue

            try:
                raw_bytes = await self.get_raw_message(msg_id)
                account_email = self.tokens.get("email", self.account_email or "unknown@gmail.com")
                record = await InboundPipelineProcessor.process_raw_email(
                    raw_bytes=raw_bytes,
                    mail_from=account_email,
                    rcpt_tos=[account_email],
                    source="GMAIL_API",
                    connection_id="gmail-primary"
                )
                existing_gateway_ids.add(record.gateway_message_id)
                processed_records.append({
                    "message_id": msg_id,
                    "gateway_id": record.gateway_message_id,
                    "subject": record.subject,
                    "risk_score": record.final_risk_score,
                    "classification": record.threat_classification,
                    "action_taken": record.action_taken
                })
            except Exception as e:
                logger.error(f"Error processing synced Gmail message {msg_id}: {e}", exc_info=True)

        self.tokens["last_sync"] = datetime.now(timezone.utc).isoformat()
        self._save_stored_tokens(self.tokens)
        return processed_records

    async def check_and_renew_watch(self) -> Optional[Dict[str, Any]]:
        """
        Renews Gmail users.watch if watch is active and nearing expiration (within 24 hours).
        """
        if not self.is_connected() or not self.tokens.get("watch_active") or self.tokens.get("monitoring_mode") != "PUB/SUB_PUSH":
            return None

        exp_ms = self.tokens.get("watch_expiration")
        if exp_ms:
            try:
                exp_dt = datetime.fromtimestamp(int(exp_ms) / 1000.0, tz=timezone.utc)
                if datetime.now(timezone.utc) + timedelta(hours=24) >= exp_dt:
                    logger.info("Gmail watch subscription is expiring soon. Renewing now...")
                    return await self.start_watch()
            except Exception as e:
                logger.warning(f"Error checking watch expiration: {e}")
        return None

    async def start_watch(self, pubsub_topic: Optional[str] = None) -> Dict[str, Any]:
        token = await self._get_valid_access_token()
        if not token:
            raise ValueError("Gmail connector not authenticated")

        cfg = get_google_oauth_config() or {}
        topic = pubsub_topic or cfg.get("pubsub_topic")
        if not topic or "YOUR_GCP_PROJECT" in topic:
            self.tokens["monitoring_mode"] = "DEVELOPMENT_POLLING"
            self.tokens["watch_active"] = True
            self._save_stored_tokens(self.tokens)
            return {
                "status": "ACTIVE_POLLING_FALLBACK",
                "monitoring_mode": "DEVELOPMENT_POLLING",
                "message": "Pub/Sub topic not configured. Incremental history polling activated."
            }

        payload = {
            "topicName": topic,
            "labelIds": ["INBOX"]
        }
        headers = {"Authorization": f"Bearer {token}"}

        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{self.GMAIL_API_BASE}/watch", headers=headers, json=payload)
            if resp.status_code != 200:
                raise ValueError(f"Failed to start Gmail watch: status {resp.status_code}")
            
            data = resp.json()
            self.tokens["history_id"] = data.get("historyId", self.tokens.get("history_id"))
            self.tokens["watch_expiration"] = data.get("expiration")
            self.tokens["monitoring_mode"] = "PUB/SUB_PUSH"
            self.tokens["watch_active"] = True
            self._save_stored_tokens(self.tokens)
            return data

    async def stop_watch(self) -> Dict[str, Any]:
        token = await self._get_valid_access_token()
        if token:
            headers = {"Authorization": f"Bearer {token}"}
            async with httpx.AsyncClient() as client:
                await client.post(f"{self.GMAIL_API_BASE}/stop", headers=headers)

        self.tokens["watch_active"] = False
        self._save_stored_tokens(self.tokens)
        return {"status": "STOPPED"}

    async def process_history(self, trigger_history_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Uses users.history.list to identify newly arrived messages.
        CRITICAL: Starts from PREVIOUSLY STORED historyId so we do not skip any intervening changes.
        Only updates the stored historyId AFTER delta processing succeeds.
        """
        token = await self._get_valid_access_token()
        if not token:
            return []

        start_id = self.tokens.get("history_id")
        if not start_id:
            profile = await self._fetch_profile_with_token(token)
            if profile.get("historyId"):
                self.tokens["history_id"] = profile["historyId"]
                self._save_stored_tokens(self.tokens)
            return []

        headers = {"Authorization": f"Bearer {token}"}
        url = f"{self.GMAIL_API_BASE}/history?startHistoryId={start_id}&historyTypes=messageAdded"

        processed_records = []
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                logger.warning(f"history.list returned {resp.status_code}")
                return []

            data = resp.json()
            history_items = data.get("history", [])
            for item in history_items:
                for added in item.get("messagesAdded", []):
                    msg_meta = added.get("message", {})
                    msg_id = msg_meta.get("id")
                    if msg_id:
                        try:
                            raw_bytes = await self.get_raw_message(msg_id)
                            record = await InboundPipelineProcessor.process_raw_email(
                                raw_bytes=raw_bytes,
                                mail_from=self.tokens.get("email", "gmail-user@example.com"),
                                rcpt_tos=[self.tokens.get("email", "gmail-user@example.com")],
                                source="GMAIL_API",
                                connection_id="gmail-primary"
                            )
                            processed_records.append({
                                "message_id": msg_id,
                                "gateway_id": record.gateway_message_id,
                                "subject": record.subject,
                                "risk_score": record.final_risk_score,
                                "classification": record.threat_classification
                            })
                        except Exception as e:
                            logger.error(f"Error processing Gmail message {msg_id}: {e}", exc_info=True)

            latest_history_id = data.get("historyId") or trigger_history_id
            if latest_history_id:
                self.tokens["history_id"] = latest_history_id

        self.tokens["last_sync"] = datetime.now(timezone.utc).isoformat()
        self._save_stored_tokens(self.tokens)
        return processed_records

    async def get_changes(self) -> List[Dict[str, Any]]:
        return await self.process_history()

gmail_connector = GmailConnector()
