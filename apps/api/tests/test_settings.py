import pytest
from pydantic import ValidationError

from threatlens_api.settings import Settings

GOOD_KEY = "k" * 32


def prod(**overrides):
    values = {
        "environment": "prod",
        "cors_origins": ["https://threatlens.example.com"],
        "llm_api_key": GOOD_KEY,
    }
    return Settings(**{**values, **overrides}, _env_file=None)


def test_dev_defaults_need_nothing():
    s = Settings(_env_file=None)
    assert s.environment == "dev"
    assert not s.is_prod


def test_valid_prod_config():
    assert prod().is_prod


def test_prod_requires_llm_key():
    with pytest.raises(ValidationError, match="LLM_API_KEY"):
        prod(llm_api_key=None)


def test_prod_rejects_short_key():
    with pytest.raises(ValidationError, match="LLM_API_KEY"):
        prod(llm_api_key="short")


def test_llm_is_off_by_default():
    assert Settings(_env_file=None).llm_provider == "off"


def test_turning_llm_on_needs_a_key_in_any_environment():
    with pytest.raises(ValidationError, match="LLM provider is on"):
        Settings(llm_provider="anthropic", _env_file=None)
    with pytest.raises(ValidationError, match="LLM provider is on"):
        Settings(llm_provider="anthropic", llm_api_key="short", _env_file=None)


@pytest.mark.parametrize("model", ["", "Claude Opus", "../../v1/admin", "a" * 70])
def test_rejects_odd_model_names(model):
    with pytest.raises(ValidationError):
        Settings(llm_model=model, _env_file=None)


def test_rejects_unknown_provider_and_bad_draft_cap():
    with pytest.raises(ValidationError):
        Settings(llm_provider="openai", _env_file=None)
    with pytest.raises(ValidationError):
        Settings(llm_drafts_per_hour=0, _env_file=None)


def test_prod_rejects_wildcard_cors():
    with pytest.raises(ValidationError, match="Wildcard"):
        prod(cors_origins=["*"])


def test_prod_rejects_plain_http_origin():
    with pytest.raises(ValidationError, match="https"):
        prod(cors_origins=["http://threatlens.example.com"])


def test_reads_from_env(monkeypatch):
    monkeypatch.setenv("THREATLENS_ENVIRONMENT", "test")
    monkeypatch.setenv("THREATLENS_CORS_ORIGINS", '["http://localhost:4000"]')
    s = Settings(_env_file=None)
    assert s.environment == "test"
    assert s.cors_origins == ["http://localhost:4000"]


def test_secret_not_in_repr():
    assert GOOD_KEY not in repr(prod())
