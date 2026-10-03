import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database.session import engine, Base
from app.api.routes import api_router
from app.gateway.server import TraceMailSMTPServer
from app.gateway.mock_downstream import MockDownstreamServer
from app.background.scheduler import scheduler
from app.engines.threat_ml import DistilBERTThreatClassifier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("tracemail.main")

smtp_gateway_server = None
mock_downstream_server = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global smtp_gateway_server, mock_downstream_server
    
    logger.info("Initializing database tables...")
    Base.metadata.create_all(bind=engine)

    # Pre-load DistilBERT singleton model once on startup
    logger.info("Pre-loading DistilBERT threat model into memory...")
    try:
        DistilBERTThreatClassifier.get_instance()
    except Exception as me:
        logger.warning(f"DistilBERT preloading encountered error: {me}")
    
    # Conditionally start downstream mock SMTP receiver in development/gateway modes
    if settings.ENV == "development" and settings.SMTP_GATEWAY_ENABLED:
        logger.info(f"Starting Downstream Mock SMTP receiver on port {settings.DOWNSTREAM_SMTP_PORT}...")
        mock_downstream_server = MockDownstreamServer(host=settings.DOWNSTREAM_SMTP_HOST, port=settings.DOWNSTREAM_SMTP_PORT)
        try:
            mock_downstream_server.start()
        except Exception as e:
            logger.warning(f"Could not bind downstream mock server: {e}")

    # Conditionally start Pre-Delivery SMTP Gateway
    if settings.SMTP_GATEWAY_ENABLED and settings.TRACEMAIL_DEPLOYMENT_MODE in ["smtp_gateway", "hybrid"]:
        logger.info(f"Starting TraceMail Pre-Delivery SMTP Gateway on {settings.SMTP_GATEWAY_HOST}:{settings.SMTP_GATEWAY_PORT}...")
        smtp_gateway_server = TraceMailSMTPServer(host=settings.SMTP_GATEWAY_HOST, port=settings.SMTP_GATEWAY_PORT)
        try:
            smtp_gateway_server.start()
        except Exception as e:
            logger.warning(f"Could not bind SMTP gateway: {e}")
    else:
        logger.info(f"SMTP Gateway disabled for current deployment mode: {settings.TRACEMAIL_DEPLOYMENT_MODE}")

    scheduler.start()
    logger.info(f"TraceMail AI Security Platform v{settings.VERSION} [{settings.TRACEMAIL_DEPLOYMENT_MODE.upper()} MODE] successfully started.")
    
    yield
    
    logger.info("Shutting down TraceMail AI services...")
    scheduler.stop()
    if smtp_gateway_server:
        smtp_gateway_server.stop()
    if mock_downstream_server:
        mock_downstream_server.stop()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="AI-Powered Email Threat Detection, SMTP Security Gateway, Gmail Monitoring & Forensic Intelligence Platform",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_PREFIX)

@app.get("/")
def root():
    return {
        "platform": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "ONLINE",
        "deployment_mode": settings.TRACEMAIL_DEPLOYMENT_MODE,
        "smtp_gateway": f"{settings.SMTP_GATEWAY_HOST}:{settings.SMTP_GATEWAY_PORT}" if settings.SMTP_GATEWAY_ENABLED else "DISABLED",
        "downstream_relay": f"{settings.DOWNSTREAM_SMTP_HOST}:{settings.DOWNSTREAM_SMTP_PORT}",
        "docs": "/docs"
    }
