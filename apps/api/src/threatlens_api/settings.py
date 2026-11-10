from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="THREATLENS_", env_file=".env", extra="ignore")

    environment: Literal["dev", "test", "prod"] = "dev"
    cors_origins: list[str] = ["http://localhost:3000"]
    llm_api_key: SecretStr | None = None
    # In AWS the key lives in Secrets Manager and only its ARN is configured (prod refuses
    # the key itself in an environment variable, where it would show in the console).
    llm_api_key_secret_id: str | None = Field(
        default=None,
        pattern=r"^arn:aws:secretsmanager:[a-z0-9-]+:\d{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}$",
    )
    # Off by default: no key, no outbound calls, no cost until someone turns it on.
    llm_provider: Literal["off", "anthropic"] = "off"
    llm_model: str = Field(default="claude-opus-5-5", pattern=r"^[a-z0-9][a-z0-9.\-]{1,63}$")
    llm_drafts_per_hour: int = Field(default=20, ge=1, le=1_000)
    # Per user as well, so one account can't use up everyone's drafts.
    llm_drafts_per_user_per_hour: int = Field(default=5, ge=1, le=1_000)
    max_request_bytes: int = 1_000_000
    # DynamoDB write units (1 per KB written) per user per hour. 20,000 is about $0.60 a day
    # per account at on-demand prices, far above a person editing by hand even on a model
    # near the size limit (~340 units a save).
    write_units_per_user_per_hour: int = Field(default=20_000, ge=100, le=10_000_000)

    # "local" runs a stand-in token issuer in this process; prod must use Cognito.
    auth_mode: Literal["local", "cognito"] = "local"
    auth_client_id: str = Field(default="threatlens-local", pattern=r"^[A-Za-z0-9_-]{1,128}$")
    cognito_region: str | None = Field(default=None, pattern=r"^[a-z]{2}(-[a-z]+)+-\d$")
    cognito_user_pool_id: str | None = Field(
        default=None, pattern=r"^[a-z]{2}(-[a-z]+)+-\d_[A-Za-z0-9]+$"
    )

    # "memory" loses everything on restart and only works with one process: dev and tests.
    store: Literal["memory", "dynamodb"] = "memory"
    dynamodb_table: str = Field(default="threatlens", pattern=r"^[A-Za-z0-9_.-]{3,255}$")
    # Only for DynamoDB Local. Unset in AWS, where boto3 picks the regional endpoint.
    dynamodb_endpoint_url: str | None = Field(default=None, pattern=r"^https?://[^\s/?#]+/?$")
    # Unset: an in-process queue and files kept in memory, for local work. Prod needs both.
    scan_queue_url: str | None = Field(default=None, pattern=r"^https://[^\s?#]+$")
    uploads_bucket: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
    # OSV, EPSS and KEV are free public services; don't let one account hammer them.
    scans_per_hour: int = Field(default=200, ge=1, le=100_000)
    scans_per_user_per_hour: int = Field(default=10, ge=1, le=10_000)
    aws_region: str = Field(default="eu-west-2", pattern=r"^[a-z]{2}(-[a-z]+)+-\d$")
    # JSON in AWS, so CloudWatch can query fields; plain text is easier to read locally.
    log_format: Literal["text", "json"] = "text"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @model_validator(mode="after")
    def check_prod_config(self) -> "Settings":
        # Fail at startup, not on the first request that needs the missing value.
        if self.llm_provider != "off" and not (self._has_llm_key() or self.llm_api_key_secret_id):
            raise ValueError(
                "THREATLENS_LLM_API_KEY or _LLM_API_KEY_SECRET_ID must be set when an LLM "
                "provider is on"
            )
        if self.auth_mode == "cognito":
            if not (self.cognito_region and self.cognito_user_pool_id):
                raise ValueError("Cognito auth needs THREATLENS_COGNITO_REGION and _USER_POOL_ID")
            if not self.cognito_user_pool_id.startswith(f"{self.cognito_region}_"):
                raise ValueError(
                    "THREATLENS_COGNITO_USER_POOL_ID is not in THREATLENS_COGNITO_REGION"
                )
        if self.environment != "prod":
            return self
        if self.auth_mode != "cognito":
            # The local issuer hands a token to anyone who asks for one.
            raise ValueError("THREATLENS_AUTH_MODE must be cognito in prod")
        if self.store != "dynamodb":
            raise ValueError("THREATLENS_STORE must be dynamodb in prod")
        if self.scan_queue_url is None or self.uploads_bucket is None:
            raise ValueError("THREATLENS_SCAN_QUEUE_URL and _UPLOADS_BUCKET must be set in prod")
        if self.dynamodb_endpoint_url is not None:
            raise ValueError("THREATLENS_DYNAMODB_ENDPOINT_URL is for DynamoDB Local, not prod")
        if self.log_format != "json":
            raise ValueError("THREATLENS_LOG_FORMAT must be json in prod")
        if "*" in self.cors_origins:
            raise ValueError("Wildcard CORS origin is not allowed in prod")
        if any(not o.startswith("https://") for o in self.cors_origins):
            raise ValueError("CORS origins must use https in prod")
        if self.llm_api_key is not None:
            raise ValueError(
                "THREATLENS_LLM_API_KEY isn't allowed in prod; use _LLM_API_KEY_SECRET_ID"
            )
        return self

    def _has_llm_key(self) -> bool:
        return self.llm_api_key is not None and len(self.llm_api_key.get_secret_value()) >= 20

    @property
    def auth_issuer(self) -> str:
        if self.auth_mode == "local":
            return "threatlens-local"
        return (
            f"https://cognito-idp.{self.cognito_region}.amazonaws.com/{self.cognito_user_pool_id}"
        )

    @property
    def is_prod(self) -> bool:
        return self.environment == "prod"


@lru_cache
def get_settings() -> Settings:
    return Settings()
