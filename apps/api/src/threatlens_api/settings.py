from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="THREATLENS_", env_file=".env", extra="ignore")

    environment: Literal["dev", "test", "prod"] = "dev"
    cors_origins: list[str] = ["http://localhost:3000"]
    llm_api_key: SecretStr | None = None
    # Off by default: no key, no outbound calls, no cost until someone turns it on.
    llm_provider: Literal["off", "anthropic"] = "off"
    llm_model: str = Field(default="claude-opus-5-5", pattern=r"^[a-z0-9][a-z0-9.\-]{1,63}$")
    llm_drafts_per_hour: int = Field(default=20, ge=1, le=1_000)
    max_request_bytes: int = 1_000_000

    @model_validator(mode="after")
    def check_prod_config(self) -> "Settings":
        # Fail at startup, not on the first request that needs the missing value.
        if self.llm_provider != "off" and not self._has_llm_key():
            raise ValueError("THREATLENS_LLM_API_KEY must be set when an LLM provider is on")
        if self.environment != "prod":
            return self
        if "*" in self.cors_origins:
            raise ValueError("Wildcard CORS origin is not allowed in prod")
        if any(not o.startswith("https://") for o in self.cors_origins):
            raise ValueError("CORS origins must use https in prod")
        if not self._has_llm_key():
            raise ValueError("THREATLENS_LLM_API_KEY must be set in prod")
        return self

    def _has_llm_key(self) -> bool:
        return self.llm_api_key is not None and len(self.llm_api_key.get_secret_value()) >= 20

    @property
    def is_prod(self) -> bool:
        return self.environment == "prod"


@lru_cache
def get_settings() -> Settings:
    return Settings()
