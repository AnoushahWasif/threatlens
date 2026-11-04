import pytest
from pydantic import ValidationError

from threatlens_api.settings import Settings

GOOD_KEY = "k" * 32
SECRET_ARN = "arn:aws:secretsmanager:eu-west-2:123456789012:secret:threatlens/llm-AbCdEf"
COGNITO = {
    "auth_mode": "cognito",
    "cognito_region": "eu-west-2",
    "cognito_user_pool_id": "eu-west-2_AbC123",
}


def prod(**overrides):
    values = {
        "environment": "prod",
        "cors_origins": ["https://threatlens.example.com"],
        "llm_api_key_secret_id": SECRET_ARN,
        "store": "dynamodb",
        "scan_queue_url": "https://sqs.eu-west-2.amazonaws.com/123456789012/threatlens-scans",
        "uploads_bucket": "threatlens-uploads",
        **COGNITO,
    }
    return Settings(**{**values, **overrides}, _env_file=None)


def test_dev_defaults_need_nothing():
    s = Settings(_env_file=None)
    assert s.environment == "dev"
    assert not s.is_prod


def test_valid_prod_config():
    assert prod().is_prod


def test_prod_refuses_the_llm_key_itself_in_the_environment():
    with pytest.raises(ValidationError, match="isn't allowed in prod"):
        prod(llm_api_key=GOOD_KEY)


def test_prod_runs_with_drafting_off_and_no_key():
    assert prod(llm_api_key_secret_id=None).llm_provider == "off"


def test_prod_drafting_needs_the_secret():
    assert prod(llm_provider="anthropic").llm_api_key_secret_id == SECRET_ARN
    with pytest.raises(ValidationError, match="SECRET_ID"):
        prod(llm_provider="anthropic", llm_api_key_secret_id=None)


@pytest.mark.parametrize(
    "arn",
    [
        "threatlens/llm-key",
        "arn:aws:s3:::bucket",
        "arn:aws:secretsmanager:eu-west-2:123:secret:x",
        "arn:aws:secretsmanager:eu-west-2:123456789012:secret:a b",
    ],
)
def test_secret_id_must_be_a_secrets_manager_arn(arn):
    with pytest.raises(ValidationError):
        Settings(llm_api_key_secret_id=arn, _env_file=None)


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


def test_prod_refuses_the_local_token_issuer():
    with pytest.raises(ValidationError, match="must be cognito in prod"):
        prod(auth_mode="local")


def test_cognito_needs_region_and_pool():
    with pytest.raises(ValidationError, match="needs THREATLENS_COGNITO_REGION"):
        Settings(auth_mode="cognito", _env_file=None)
    with pytest.raises(ValidationError, match="not in THREATLENS_COGNITO_REGION"):
        Settings(**{**COGNITO, "cognito_region": "us-east-1"}, _env_file=None)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("cognito_region", "eu-west-2/../x"),
        ("cognito_user_pool_id", "eu-west-2_abc/../../evil"),
        ("cognito_user_pool_id", "eu-west-2_abc.evil.example"),
        ("auth_client_id", "abc def"),
    ],
)
def test_rejects_values_that_would_change_the_issuer_url(field, value):
    with pytest.raises(ValidationError):
        Settings(**{**COGNITO, field: value}, _env_file=None)


def test_issuer_url():
    s = Settings(**COGNITO, _env_file=None)
    assert s.auth_issuer == "https://cognito-idp.eu-west-2.amazonaws.com/eu-west-2_AbC123"
    assert Settings(_env_file=None).auth_issuer == "threatlens-local"


def test_prod_refuses_the_memory_store():
    with pytest.raises(ValidationError, match="THREATLENS_STORE"):
        prod(store="memory")


def test_prod_refuses_a_dynamodb_local_endpoint():
    with pytest.raises(ValidationError, match="DynamoDB Local"):
        prod(dynamodb_endpoint_url="http://localhost:8000")


@pytest.mark.parametrize(
    "url",
    [
        "localhost:8000",
        "ftp://localhost:8000",
        "http://localhost:8000/x",
        "http://a b",
        "http://h?x",
    ],
)
def test_dynamodb_endpoint_must_be_a_plain_url(url):
    with pytest.raises(ValidationError):
        Settings(dynamodb_endpoint_url=url, _env_file=None)


@pytest.mark.parametrize("table", ["ab", "bad table", "x" * 256, "t;drop"])
def test_dynamodb_table_name_is_checked(table):
    with pytest.raises(ValidationError):
        Settings(dynamodb_table=table, _env_file=None)


@pytest.mark.parametrize("missing", ["scan_queue_url", "uploads_bucket"])
def test_prod_needs_a_queue_and_a_bucket(missing):
    with pytest.raises(ValidationError, match="SCAN_QUEUE_URL"):
        prod(**{missing: None})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scan_queue_url", "http://sqs.example.com/q"),
        ("scan_queue_url", "https://sqs.example.com/q?x=1"),
        ("uploads_bucket", "Bad_Bucket"),
        ("uploads_bucket", "-starts-with-dash"),
        ("uploads_bucket", "ab"),
    ],
)
def test_queue_and_bucket_are_checked(field, value):
    with pytest.raises(ValidationError):
        Settings(**{field: value}, _env_file=None)
