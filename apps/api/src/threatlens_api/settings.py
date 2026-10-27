from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="THREATLENS_", env_file=".env", extra="ignore")

    environment: Literal["dev", "test", "prod"] = "dev"
    cors_origins: list[str] = ["http://localhost:3000"]
    llm_api_key: SecretStr | None = None
    max_request_bytes: int = 1_000_000

    @model_validator(mode="after")
    def check_prod_config(self) -> "Settings":
        # Fail at startup, not on the first request that needs the missing value.
        if self.environment != "prod":
            return self
        if "*" in self.cors_origins:
            raise ValueError("Wildcard CORS origin is not allowed in prod")
        if any(not o.startswith("https://") for o in self.cors_origins):
            raise ValueError("CORS origins must use https in prod")
        if self.llm_api_key is None or len(self.llm_api_key.get_secret_value()) < 20:
            raise ValueError("THREATLENS_LLM_API_KEY must be set in prod")
        return self

    @property
    def is_prod(self) -> bool:
        return self.environment == "prod"


@lru_cache
def get_settings() -> Settings:
    return Settings()
