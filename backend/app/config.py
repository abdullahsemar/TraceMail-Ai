import os
import json
from typing import List, Optional, Dict, Any
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "TraceMail AI"
    VERSION: str = "2.0.0"
    API_PREFIX: str = "/api"
    
    # Environment & Deployment Mode
    # Modes: "gmail" (Mailbox Post-Delivery Monitoring) | "smtp_gateway" (Pre-Delivery Enterprise Proxy) | "hybrid"
    TRACEMAIL_DEPLOYMENT_MODE: str = "hybrid"
    ENV: str = "development"
    DEBUG: bool = True
    
    # Database
    DATABASE_URL: str = "sqlite:///./tracemail.db"
    
    # Storage & Privacy
    EVIDENCE_DIR: str = "./evidence_storage"
    REPORTS_DIR: str = "./reports"
    CONFIG_DIR: str = "./config"
    STORE_RAW_EMAIL: bool = True
    RAW_EMAIL_RETENTION_DAYS: int = 90
    MASK_SENSITIVE_DATA: bool = False
    
    # Pre-Delivery SMTP Security Gateway / Proxy
    SMTP_GATEWAY_ENABLED: bool = True
    SMTP_GATEWAY_HOST: str = "127.0.0.1"
    SMTP_GATEWAY_PORT: int = 1025
    
    # Downstream SMTP Relay (for Pre-Delivery Proxy forwarding to destination MTA)
    DOWNSTREAM_SMTP_HOST: str = "127.0.0.1"
    DOWNSTREAM_SMTP_PORT: int = 1026
    DOWNSTREAM_SMTP_USE_TLS: bool = False
    DOWNSTREAM_SMTP_STARTTLS: bool = False
    DOWNSTREAM_SMTP_USERNAME: Optional[str] = None
    DOWNSTREAM_SMTP_PASSWORD: Optional[str] = None
    
    # Subject Warning Prefix Configuration
    TRACEMAIL_SUBJECT_WARNING_ENABLED: bool = False
    
    # Policy Thresholds & Actions (Non-Quarantining Model)
    SENTINEL_FAST_ALLOW_THRESHOLD: int = 20
    SENTINEL_DEEP_SCAN_THRESHOLD: int = 40
    FUSION_FLAG_ALERT_THRESHOLD: int = 60
    FUSION_FLAG_THRESHOLD: int = 30
    
    # Fuzzy Campaign Correlation Thresholds
    CAMPAIGN_SIMILARITY_REVIEW: float = 0.70
    CAMPAIGN_SIMILARITY_STRONG: float = 0.85
    
    # Telegram Alerting
    TELEGRAM_ENABLED: bool = False
    TELEGRAM_BOT_TOKEN: Optional[str] = None
    TELEGRAM_CHAT_ID: Optional[str] = None
    TELEGRAM_MIN_SEVERITY: str = "HIGH"  # Options: HIGH, CRITICAL, ALL
    PUBLIC_DASHBOARD_URL: Optional[str] = "http://localhost:5173"
    
    # Threat Intelligence & GeoIP
    MAXMIND_DB_PATH: Optional[str] = "./data/GeoLite2-City.mmdb"
    
    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"]
    FRONTEND_URL: str = "http://localhost:5173"
    
    # Secret Key for Auth
    SECRET_KEY: str = "tracemail-insecure-dev-secret-key-change-in-prod-2026"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24
    
    # Retrospective Scan Interval (seconds) - Default 3600s (1 hour)
    RETROSPECTIVE_SCAN_INTERVAL_SECONDS: int = 3600

    # Google OAuth / Connector Config (Environment credentials primary, local JSON optional fallback)
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/api/connectors/gmail/callback"
    GOOGLE_OAUTH_LOCAL_CONFIG: str = "./config/google_oauth.local.json"
    GOOGLE_TOKENS_STORAGE: str = "./config/google_tokens.json"
    GMAIL_INITIAL_SYNC_LIMIT: int = 25

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()

def get_google_oauth_config() -> Optional[Dict[str, Any]]:
    """
    Load Google OAuth configuration prioritizing environment settings (.env),
    falling back to local JSON if environment variables are not set.
    Returns None if credentials are not configured.
    """
    if settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET:
        return {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI or "http://localhost:8000/api/connectors/gmail/callback"
        }

    if os.path.exists(settings.GOOGLE_OAUTH_LOCAL_CONFIG):
        try:
            with open(settings.GOOGLE_OAUTH_LOCAL_CONFIG, "r") as f:
                data = json.load(f)
                web_config = data.get("web") or data.get("installed") or data
                client_id = web_config.get("client_id")
                client_secret = web_config.get("client_secret")
                redirect_uris = web_config.get("redirect_uris", [settings.GOOGLE_REDIRECT_URI])
                if client_id and client_secret:
                    return {
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "redirect_uri": redirect_uris[0] if redirect_uris else settings.GOOGLE_REDIRECT_URI
                    }
        except Exception:
            pass

    return None
