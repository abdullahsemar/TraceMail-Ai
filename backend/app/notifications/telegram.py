import html
import logging
import httpx
from typing import Dict, Any, Optional
from app.config import settings

logger = logging.getLogger("tracemail.notifications.telegram")

class TelegramNotifier:
    """
    Telegram Threat Alerting Notifier:
    Dispatches formatted critical incident alerts to designated SOC channel/chat.
    Fails safely and gracefully without interrupting the email pipeline.
    """

    @classmethod
    def is_configured(cls) -> bool:
        bot_token = getattr(settings, "TELEGRAM_BOT_TOKEN", None)
        chat_id = getattr(settings, "TELEGRAM_CHAT_ID", None)
        enabled = getattr(settings, "TELEGRAM_ENABLED", False)
        return bool(enabled and bot_token and str(bot_token).strip() and chat_id and str(chat_id).strip())

    @classmethod
    async def send_test_message(cls) -> Dict[str, Any]:
        """
        Sends a safe connection test message to verify the Telegram bot can reach the configured chat.
        Does NOT process emails, create cases, or modify system risk metrics.
        """
        bot_token = getattr(settings, "TELEGRAM_BOT_TOKEN", None)
        chat_id = getattr(settings, "TELEGRAM_CHAT_ID", None)
        enabled = getattr(settings, "TELEGRAM_ENABLED", False)

        if not enabled:
            return {
                "success": False,
                "status": "DISABLED",
                "error": "Telegram notifications are disabled in backend/.env (TELEGRAM_ENABLED=false)."
            }

        if not bot_token or not str(bot_token).strip() or not chat_id or not str(chat_id).strip():
            return {
                "success": False,
                "status": "NOT_CONFIGURED",
                "error": "Telegram bot token or chat ID is not configured in backend/.env."
            }

        api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": "✅ TraceMail AI — Telegram notification channel connected successfully."
        }

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post(api_url, json=payload)
                if resp.status_code == 200:
                    logger.info("Telegram connection test succeeded.")
                    return {
                        "success": True,
                        "status": "CONNECTED",
                        "message": "Notification sent successfully."
                    }
                elif resp.status_code == 401:
                    logger.warning("Telegram test failed: Invalid bot token (401).")
                    return {
                        "success": False,
                        "status": "ERROR",
                        "error": "Telegram authentication failed. Please verify TELEGRAM_BOT_TOKEN in backend/.env."
                    }
                elif resp.status_code == 400:
                    logger.warning("Telegram test failed: Bad request / Invalid chat ID (400).")
                    return {
                        "success": False,
                        "status": "ERROR",
                        "error": "Telegram request rejected. Please verify TELEGRAM_CHAT_ID in backend/.env."
                    }
                elif resp.status_code == 429:
                    logger.warning("Telegram test failed: Rate limit exceeded (429).")
                    return {
                        "success": False,
                        "status": "ERROR",
                        "error": "Telegram rate limit exceeded. Please retry in a few moments."
                    }
                else:
                    logger.warning(f"Telegram test failed with status {resp.status_code}")
                    return {
                        "success": False,
                        "status": "ERROR",
                        "error": f"Telegram API returned unexpected status {resp.status_code}."
                    }
        except httpx.TimeoutException:
            logger.warning("Telegram test failed: Connection timeout.")
            return {
                "success": False,
                "status": "ERROR",
                "error": "Telegram connection timed out after 8 seconds."
            }
        except Exception as e:
            logger.warning(f"Telegram test connection error: {e}")
            return {
                "success": False,
                "status": "ERROR",
                "error": "Failed to connect to Telegram API. Please check network connectivity."
            }

    @classmethod
    async def send_threat_alert(
        cls,
        case_number: str,
        sender: str,
        subject: str,
        verdict: Dict[str, Any],
        origin: Optional[Dict[str, Any]] = None,
        source: str = "SMTP_GATEWAY"
    ) -> bool:
        bot_token = getattr(settings, "TELEGRAM_BOT_TOKEN", None)
        chat_id = getattr(settings, "TELEGRAM_CHAT_ID", None)
        enabled = getattr(settings, "TELEGRAM_ENABLED", False)

        if not enabled or not bot_token or not chat_id:
            logger.debug("Telegram alert skipped: Telegram not configured or disabled.")
            return False

        severity = verdict.get("risk_severity", "HIGH").upper()
        classification = verdict.get("threat_classification", "UNKNOWN")
        risk_score = round(float(verdict.get("final_risk_score", 0.0)))
        threat_conf = round(float(verdict.get("threat_confidence", 0.85)) * 100)
        
        # Evidence items: top 3-5 findings
        top_reasons = verdict.get("top_reasons", [])[:5]
        if not top_reasons:
            top_reasons = ["Automated behavioral threat indicators detected"]

        # Origin details
        origin = origin or {}
        country = origin.get("country") or origin.get("country_code") or "Unknown"
        infra_conf = round(float(origin.get("origin_confidence_score", 40.0)))

        dashboard_url = getattr(settings, "PUBLIC_DASHBOARD_URL", "http://localhost:5173")
        investigation_url = f"{dashboard_url}/investigations?emailId={case_number}"

        # Format HTML message safely
        severity_icon = "🚨" if severity == "CRITICAL" else "⚠️"
        evidence_bullets = "\n".join([f"• {html.escape(str(r))}" for r in top_reasons])
        
        html_message = (
            f"{severity_icon} <b>TraceMail Security Alert</b>\n\n"
            f"<b>Severity:</b> <code>{html.escape(severity)}</code>\n"
            f"<b>Classification:</b> <code>{html.escape(classification)}</code>\n"
            f"<b>Risk:</b> {risk_score}/100\n"
            f"<b>Threat Confidence:</b> {threat_conf}%\n\n"
            f"<b>Sender:</b>\n<code>{html.escape(sender)}</code>\n\n"
            f"<b>Subject:</b>\n{html.escape(subject)}\n\n"
            f"<b>Top Evidence:</b>\n{evidence_bullets}\n\n"
            f"<b>Observed Infrastructure:</b>\n{html.escape(str(country))}\n\n"
            f"<b>Infrastructure Confidence:</b>\n{infra_conf}%\n\n"
            f"<b>Case:</b>\n<code>{html.escape(case_number)}</code>\n\n"
            f"<b>Open Investigation:</b>\n{investigation_url}"
        )

        api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": html_message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post(api_url, json=payload)
                if resp.status_code == 200:
                    logger.info(f"Telegram threat alert dispatched successfully for Case {case_number}")
                    return True
                elif resp.status_code == 400:
                    # Fallback to plain text if HTML parsing was rejected
                    logger.warning("Telegram HTML parse rejected. Retrying as plaintext...")
                    plain_payload = {
                        "chat_id": chat_id,
                        "text": (
                            f"{severity_icon} TraceMail Security Alert\n\n"
                            f"Severity: {severity}\n"
                            f"Classification: {classification}\n"
                            f"Risk: {risk_score}/100\n"
                            f"Threat Confidence: {threat_conf}%\n\n"
                            f"Sender: {sender}\n"
                            f"Subject: {subject}\n\n"
                            f"Top Evidence:\n" + "\n".join([f"• {r}" for r in top_reasons]) + "\n\n"
                            f"Observed Infrastructure: {country}\n"
                            f"Infrastructure Confidence: {infra_conf}%\n\n"
                            f"Case: {case_number}\n\n"
                            f"Open Investigation:\n{investigation_url}"
                        )
                    }
                    fallback_resp = await client.post(api_url, json=plain_payload)
                    return fallback_resp.status_code == 200
                else:
                    logger.warning(f"Telegram API returned status {resp.status_code}")
                    return False
        except httpx.TimeoutException:
            logger.warning(f"Telegram alert dispatch timed out for Case {case_number} (non-fatal).")
            return False
        except Exception as e:
            logger.warning(f"Could not dispatch Telegram alert for Case {case_number} (non-fatal): {e}")
            return False
