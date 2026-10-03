import logging
from aiosmtpd.controller import Controller

logger = logging.getLogger("tracemail.mock_downstream")

class MockDownstreamHandler:
    async def handle_DATA(self, server, session, envelope):
        logger.info(f"[Downstream Final Mailbox] RECEIVED RELAYED EMAIL from {envelope.mail_from} to {envelope.rcpt_tos} ({len(envelope.content)} bytes)")
        return "250 Message accepted for final delivery"

class MockDownstreamServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 1026):
        self.host = host
        self.port = port
        self.controller = None

    def start(self):
        handler = MockDownstreamHandler()
        self.controller = Controller(handler, hostname=self.host, port=self.port)
        self.controller.start()
        logger.info(f"Mock Downstream SMTP Server started on {self.host}:{self.port}")

    def stop(self):
        if self.controller:
            self.controller.stop()
