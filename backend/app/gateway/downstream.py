import email
import socket
import logging
import asyncio
from email import policy
from email.message import EmailMessage
from typing import List, Optional, Dict, Any
import aiosmtplib
from app.config import settings

logger = logging.getLogger("tracemail.downstream")

class DownstreamRelayClient:
    """
    Downstream SMTP Relay Client:
    - Injects safe operational TraceMail warning and analysis headers into the RFC822 stream.
    - Optionally prefixes subject with warning tag if configured (TRACEMAIL_SUBJECT_WARNING_ENABLED=True).
    - Forwards all evaluated messages downstream to the organization's destination MTA.
    - Does NOT inject confidential forensic details or secrets into public headers.
    """

    @classmethod
    def is_configured(cls) -> bool:
        host = getattr(settings, "DOWNSTREAM_SMTP_HOST", "")
        return bool(host and str(host).strip())

    @classmethod
    def inject_tracemail_headers(
        cls,
        raw_bytes: bytes,
        case_id: str,
        risk_score: float,
        severity: str,
        classification: str
    ) -> bytes:
        """
        Injects standard safe X-TraceMail headers into the RFC822 message bytes.
        """
        try:
            msg = email.message_from_bytes(raw_bytes, policy=policy.default)
            is_flagged = severity in ["MEDIUM", "HIGH", "CRITICAL"]

            # Safe standard internal metadata headers
            msg["X-TraceMail-Analyzed"] = "true"
            msg["X-TraceMail-Case-ID"] = case_id
            msg["X-TraceMail-Risk-Score"] = str(round(risk_score, 1))
            msg["X-TraceMail-Severity"] = severity
            msg["X-TraceMail-Classification"] = classification
            msg["X-TraceMail-Flagged"] = "true" if is_flagged else "false"

            # Optional Subject Warning Prefix
            subject_warning_enabled = getattr(settings, "TRACEMAIL_SUBJECT_WARNING_ENABLED", False)
            if subject_warning_enabled and is_flagged:
                curr_subj = msg.get("Subject", "")
                if severity == "CRITICAL" and not curr_subj.startswith("[TraceMail Critical]"):
                    del msg["Subject"]
                    msg["Subject"] = f"[TraceMail Critical] {curr_subj}"
                elif severity == "HIGH" and not curr_subj.startswith("[TraceMail Warning]"):
                    del msg["Subject"]
                    msg["Subject"] = f"[TraceMail Warning] {curr_subj}"

            return msg.as_bytes()
        except Exception as e:
            logger.warning(f"Header injection fallback to raw bytes: {e}")
            return raw_bytes

    @classmethod
    def inject_security_headers(
        cls,
        raw_bytes: bytes,
        verdict: Dict[str, Any],
        case_id: str = "TR-UNKNOWN"
    ) -> bytes:
        """Helper to inject headers directly from a verdict dict."""
        return cls.inject_tracemail_headers(
            raw_bytes=raw_bytes,
            case_id=case_id,
            risk_score=float(verdict.get("final_risk_score", verdict.get("operational_risk_score", 0.0))),
            severity=str(verdict.get("risk_severity", "LOW")),
            classification=str(verdict.get("threat_classification", "LEGITIMATE"))
        )

    @classmethod
    async def test_connection(cls) -> Dict[str, Any]:
        """
        Tests downstream SMTP connection (DNS resolution, TCP connectivity, and SMTP handshake/TLS).
        Does NOT send any fake or test email messages.
        """
        host = getattr(settings, "DOWNSTREAM_SMTP_HOST", "127.0.0.1")
        port = getattr(settings, "DOWNSTREAM_SMTP_PORT", 1026)
        use_tls = getattr(settings, "DOWNSTREAM_SMTP_USE_TLS", False)
        start_tls = getattr(settings, "DOWNSTREAM_SMTP_STARTTLS", False)
        username = getattr(settings, "DOWNSTREAM_SMTP_USERNAME", None)
        password = getattr(settings, "DOWNSTREAM_SMTP_PASSWORD", None)

        if not cls.is_configured():
            return {
                "success": False,
                "status": "NOT_CONFIGURED",
                "host": host,
                "port": port,
                "error": "Downstream SMTP host is not configured in backend/.env."
            }

        # 1. Test DNS resolution and TCP handshake
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, lambda: socket.gethostbyname(host))
        except Exception as dns_err:
            return {
                "success": False,
                "status": "DNS_ERROR",
                "host": host,
                "port": port,
                "error": f"Failed to resolve downstream SMTP hostname '{host}': {dns_err}"
            }

        # 2. Test SMTP handshake via aiosmtplib
        try:
            smtp = aiosmtplib.SMTP(
                hostname=host,
                port=port,
                use_tls=use_tls,
                start_tls=start_tls,
                timeout=6.0
            )
            await smtp.connect()
            
            if username and password:
                await smtp.login(username, password)

            await smtp.quit()

            return {
                "success": True,
                "status": "CONNECTED",
                "host": host,
                "port": port,
                "message": f"Successfully connected to downstream SMTP server on {host}:{port}."
            }
        except aiosmtplib.SMTPConnectError as conn_err:
            logger.warning(f"Downstream SMTP connect error ({host}:{port}): {conn_err}")
            return {
                "success": False,
                "status": "CONNECTION_REFUSED",
                "host": host,
                "port": port,
                "error": f"Connection refused by downstream SMTP server on {host}:{port}. Ensure your target mail server is running."
            }
        except Exception as e:
            logger.warning(f"Downstream SMTP connection test failed: {e}")
            return {
                "success": False,
                "status": "ERROR",
                "host": host,
                "port": port,
                "error": f"Downstream SMTP check failed: {e}"
            }

    @classmethod
    async def relay_raw_message(
        cls,
        raw_bytes: bytes,
        sender: str,
        recipients: List[str],
        case_id: Optional[str] = None,
        risk_score: float = 0.0,
        severity: str = "LOW",
        classification: str = "LEGITIMATE"
    ) -> bool:
        if not cls.is_configured():
            logger.warning("Downstream SMTP is not configured. Message preserved in repository but cannot be relayed.")
            return False

        # Inject safe headers before sending downstream
        message_to_send = cls.inject_tracemail_headers(
            raw_bytes=raw_bytes,
            case_id=case_id or "TR-UNKNOWN",
            risk_score=risk_score,
            severity=severity,
            classification=classification
        )

        try:
            await aiosmtplib.send(
                message_to_send,
                sender=sender,
                recipients=recipients,
                hostname=settings.DOWNSTREAM_SMTP_HOST,
                port=settings.DOWNSTREAM_SMTP_PORT,
                use_tls=settings.DOWNSTREAM_SMTP_USE_TLS,
                start_tls=getattr(settings, "DOWNSTREAM_SMTP_STARTTLS", False),
                username=settings.DOWNSTREAM_SMTP_USERNAME,
                password=settings.DOWNSTREAM_SMTP_PASSWORD,
                timeout=8.0
            )
            logger.info(f"Successfully relayed message to downstream SMTP {settings.DOWNSTREAM_SMTP_HOST}:{settings.DOWNSTREAM_SMTP_PORT}")
            return True
        except Exception as e:
            logger.warning(f"Downstream SMTP relay attempt to {settings.DOWNSTREAM_SMTP_HOST}:{settings.DOWNSTREAM_SMTP_PORT} resulted in: {str(e)}")
            return False


# Backwards compatibility alias
DownstreamSMTPRelay = DownstreamRelayClient

