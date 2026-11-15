"""Settings from environment variables (spec Section 4). Owner: Lead."""
from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """One field per variable. Field names match the variable names, case-insensitive."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    hc_env: str = "dev"
    hc_log_level: str = "INFO"
    hc_redis_url: str = "redis://redis:6379/0"
    hc_opensearch_url: str = "http://opensearch:9200"
    hc_events_index_prefix: str = "hc-events"
    hc_alerts_index: str = "hc-alerts"
    hc_findings_index: str = "hc-findings"
    hc_api_key: str = ""
    hc_api_url: str = "http://api:8000"
    hc_ml_url: str = "http://ml:8100"
    hc_generator_url: str = "http://generator:8300"
    hc_db_url: str = "sqlite:////data/hc.db"
    hc_audit_path: str = "/data/audit.jsonl"
    hc_model_dir: str = "/data/models"
    hc_mlflow_uri: str = "file:///data/mlruns"
    llm_provider: str = "none"
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_model: str = ""
    llm_timeout_s: int = 20


@lru_cache
def get_settings() -> Settings:
    return Settings()


def require_api_key(settings: Optional[Settings] = None) -> str:
    """Return HC_API_KEY or raise RuntimeError (services that expose an API call this at startup)."""
    s = settings or get_settings()
    if not s.hc_api_key:
        raise RuntimeError("HC_API_KEY is not set")
    return s.hc_api_key
