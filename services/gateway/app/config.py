"""Configuration. No secrets in code (threat model T-16) — values come from
environment variables, which Container Apps sources from Key Vault via
managed identity, and local dev sources from a gitignored .env file."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    aegis_env: Literal["dev", "test", "prod"] = "dev"
    auth_mode: Literal["dev", "entra"] = "dev"

    # Database
    database_url: str = "postgresql://aegis:aegis@localhost:5432/aegis"

    # Entra ID (auth_mode=entra)
    entra_tenant_id: str = ""
    entra_audience: str = ""

    # Dev auth only — never used when auth_mode=entra
    dev_jwt_secret: str = "dev-only-not-a-real-secret-change-me"

    # Azure OpenAI — keyless: the gateway authenticates with its managed
    # identity / developer credential via DefaultAzureCredential (T-16)
    openai_endpoint: str = ""
    openai_deployment: str = "gpt-5-4-mini"
    openai_api_version: str = "2024-12-01-preview"
    openai_max_tokens: int = 800

    # Guardrail budgets (T-11, T-17)
    max_prompt_chars: int = 8000


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
