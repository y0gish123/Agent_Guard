"""Application configuration for AgentGuard AI SOC backend."""

import os
import sys
from typing import Literal
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    DEMO_MODE: Literal["guarded", "naive"] = "guarded"
    HMAC_SECRET: str = ""
    TOKEN_TTL_SECONDS: int = 60
    SIMULATION: bool = True
    TOOL_URL: str = "http://localhost:8001"
    DB_URL: str = "sqlite:///./agentguard.db"
    LLM_PROVIDER: str = "gemini"
    LLM_MODEL: str = "gemini-2.5-flash"
    LLM_API_KEY: str = ""
    GEMINI_API_KEY: str = ""
    ALLOW_UNREVIEWED_LANGS: bool = False
    TELEGRAM_BOT_TOKEN: str = ""
    MAX_BODY_BYTES: int = 1_048_576  # 1 MB

    # Live integration & Site settings
    LIVE_MODE: bool = False
    TOOL_BACKEND: str = "mock"  # mock | portal
    SITE_URL: str = "http://localhost:8002"
    SITE_ADMIN_KEY: str = ""
    SITE_LOG_PATH: str = "./site_logs/auth.log"
    SITE_ACCESS_LOG_PATH: str = "./site_logs/access.log"
    SITE_DATA_LOG_PATH: str = "./site_logs/data.log"
    DASHBOARD_URL: str = "http://localhost:5173"

    # Mail / DNS
    IMAP_HOST: str = ""
    IMAP_USER: str = ""
    IMAP_PASSWORD: str = ""
    MAIL_DROP_DIR: str = "./mail_drop"
    DNS_LOG_PATH: str = "./dns_logs/dns.log"
    BACKUP_STATUS_PATH: str = "data/backup_status.json"
    RAW_RETENTION_DAYS: int = 30
    EVENT_RETENTION_DAYS: int = 90
    AUDIT_RETENTION_DAYS: int = 365


def get_settings() -> Settings:
    settings = Settings()
    if "TOOL_URL" in os.environ:
        settings.TOOL_URL = os.environ["TOOL_URL"]
    if "DEMO_MODE" in os.environ:
        settings.DEMO_MODE = os.environ["DEMO_MODE"]
    if "LIVE_MODE" in os.environ:
        settings.LIVE_MODE = os.environ["LIVE_MODE"].lower() == "true"
    if "TOOL_BACKEND" in os.environ:
        settings.TOOL_BACKEND = os.environ["TOOL_BACKEND"]

    # Secret resolution: HMAC_SECRET or SECRET
    if not settings.HMAC_SECRET:
        env_secret = os.getenv("HMAC_SECRET", "") or os.getenv("SECRET", "")
        if env_secret:
            settings.HMAC_SECRET = env_secret
        else:
            raise RuntimeError("HMAC_SECRET is required. Refusing to start backend.")

    # LLM API key resolution: LLM_API_KEY or GEMINI_API_KEY
    if not settings.LLM_API_KEY and (os.getenv("GEMINI_API_KEY") or settings.GEMINI_API_KEY):
        settings.LLM_API_KEY = os.getenv("GEMINI_API_KEY", settings.GEMINI_API_KEY)

    return settings
