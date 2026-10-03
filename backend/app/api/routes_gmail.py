import secrets
import json
import base64
import logging
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from app.config import settings
from app.connectors.gmail import gmail_connector

logger = logging.getLogger("tracemail.api.gmail")
router = APIRouter()

# Temporary in-memory CSRF state cache
_OAUTH_STATES = set()

@router.get("/auth")
def start_gmail_oauth():
    if not gmail_connector.is_configured():
        raise HTTPException(
            status_code=400,
            detail="Google OAuth credentials not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in backend/.env"
        )
    state = secrets.token_urlsafe(24)
    _OAUTH_STATES.add(state)
    auth_url = gmail_connector.get_authorization_url(state=state)
    return {"auth_url": auth_url, "state": state}

@router.get("/callback")
async def gmail_oauth_callback(
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None
):
    if error:
        logger.warning(f"OAuth callback returned error from Google: {error}")
        return RedirectResponse(f"{settings.FRONTEND_URL}/connections?error={error}")

    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    # Strict OAuth state verification: must match and not be empty
    if not state or state not in _OAUTH_STATES:
        logger.error("OAuth state verification failed. Possible CSRF attempt.")
        raise HTTPException(status_code=403, detail="Invalid or expired OAuth state parameter.")

    _OAUTH_STATES.remove(state)

    try:
        tokens = await gmail_connector.exchange_code(code)
        logger.info(f"Successfully connected Gmail account: {tokens.get('email')}")
        return RedirectResponse(f"{settings.FRONTEND_URL}/connections?success=gmail_connected")
    except Exception as e:
        logger.error(f"Failed to exchange Google OAuth code: {e}")
        return RedirectResponse(f"{settings.FRONTEND_URL}/connections?error=token_exchange_failed")

@router.get("/status")
async def get_gmail_status():
    return await gmail_connector.get_account()

@router.post("/watch")
async def start_gmail_watch(payload: Optional[Dict[str, Any]] = None):
    if not gmail_connector.is_connected():
        raise HTTPException(status_code=400, detail="Gmail account is not connected. Authorize first.")
    
    topic = payload.get("topic") if payload else None
    try:
        res = await gmail_connector.start_watch(pubsub_topic=topic)
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/webhook")
async def gmail_pubsub_webhook(request: Request):
    try:
        body = await request.json()
        message = body.get("message", {})
        data_b64 = message.get("data", "")
        if data_b64:
            decoded_json_str = base64.b64decode(data_b64).decode("utf-8")
            payload = json.loads(decoded_json_str)
            history_id = payload.get("historyId")
            logger.info(f"[PubSub Webhook] Received notification for historyId: {history_id}")
            
            # Start from last stored historyId and process up to trigger history_id
            new_records = await gmail_connector.process_history(trigger_history_id=history_id)
            return {"status": "SUCCESS", "processed_emails": len(new_records)}
    except Exception as e:
        logger.error(f"Error handling PubSub webhook: {e}", exc_info=True)
        return {"status": "ERROR", "detail": str(e)}

    return {"status": "NOOP"}

@router.post("/poll")
async def poll_gmail_now():
    if not gmail_connector.is_connected():
        raise HTTPException(status_code=400, detail="Gmail account is not connected")

    try:
        processed = await gmail_connector.process_history()
        return {
            "status": "SUCCESS",
            "monitoring_mode": "DEVELOPMENT_POLLING",
            "new_emails_processed": len(processed),
            "details": processed
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/sync")
async def sync_gmail_inbox(payload: Optional[Dict[str, Any]] = None):
    if not gmail_connector.is_connected():
        raise HTTPException(status_code=400, detail="Gmail account is not connected. Authorize with Google OAuth first.")

    limit = payload.get("limit") if payload else settings.GMAIL_INITIAL_SYNC_LIMIT
    try:
        processed = await gmail_connector.sync_inbox(limit=limit)
        return {
            "status": "SUCCESS",
            "synced_count": len(processed),
            "details": processed
        }
    except Exception as e:
        logger.error(f"Error syncing Gmail inbox: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/disconnect")
async def disconnect_gmail():
    await gmail_connector.disconnect()
    return {"status": "DISCONNECTED"}
