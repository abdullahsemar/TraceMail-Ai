import logging
from aiosmtpd.controller import Controller
from app.config import settings
from app.gateway.handler import InboundPipelineProcessor

logger = logging.getLogger("tracemail.smtp_gateway")

class TraceMailSMTPHandler:
    async def handle_DATA(self, server, session, envelope):
        mail_from = envelope.mail_from
        rcpt_tos = envelope.rcpt_tos
        content_bytes = envelope.content
        
        logger.info(f"[TraceMail SMTP Gateway] Received inbound email from {mail_from} to {rcpt_tos} ({len(content_bytes)} bytes)")
        
        try:
            record = await InboundPipelineProcessor.process_raw_email(
                raw_bytes=content_bytes,
                mail_from=mail_from,
                rcpt_tos=rcpt_tos,
                source="SMTP_GATEWAY"
            )
            
            if record.action_taken == "QUARANTINE":
                logger.warning(f"[Gateway] Quarantined threat {record.threat_classification} (Risk: {record.final_risk_score})")
                return "250 OK: TraceMail Security Gateway accepted and quarantined suspicious message for forensic inspection"
            else:
                logger.info(f"[Gateway] Safe message passed and relayed downstream")
                return "250 OK: TraceMail Security Gateway accepted and queued for delivery"
                
        except Exception as e:
            logger.error(f"Error processing SMTP message: {str(e)}", exc_info=True)
            return "451 Temporary local error during security screening"

class TraceMailSMTPServer:
    def __init__(self, host: str = None, port: int = None):
        self.host = host or settings.SMTP_GATEWAY_HOST
        self.port = port or settings.SMTP_GATEWAY_PORT
        self.controller = None

    def start(self):
        handler = TraceMailSMTPHandler()
        self.controller = Controller(handler, hostname=self.host, port=self.port)
        self.controller.start()
        logger.info(f"TraceMail Pre-Delivery SMTP Security Gateway listening on {self.host}:{self.port}")

    def stop(self):
        if self.controller:
            self.controller.stop()
            logger.info("TraceMail SMTP Security Gateway stopped")
