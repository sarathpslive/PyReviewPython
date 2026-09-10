from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "latency-fastapi-adk"
    app_env: str = "development"
    log_level: str = "info"
    api_key: str | None = None
    github_token: str | None = None
    gemini_api_key: str | None = None
    llm_provider: str = "gemini"
    llm_model: str = "gemini-3.6-flash"
    prompt_guard_enabled: bool = False
    prompt_guard_min_match_hits: int = 1
    prompt_guard_block_on_error: bool = False
    prompt_guard_allowlist: str = ""
    google_project_id: str | None = None
    google_region: str = "us-central1"
    http_timeout_seconds: float = 2.5
    max_keepalive_connections: int = 20
    max_connections: int = 100
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
