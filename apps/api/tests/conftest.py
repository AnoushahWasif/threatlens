import os
import uuid

import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

from threatlens_api.main import create_app
from threatlens_api.models import Dependency
from threatlens_api.repository import create_table, dynamodb_client
from threatlens_api.settings import Settings

# Set in CI to a DynamoDB Local container: the whole suite then runs against the real
# engine instead of the in-memory store. Repository tests use moto when it's unset.
DYNAMODB_URL = os.environ.get("THREATLENS_TEST_DYNAMODB_URL")


@pytest.fixture
def aws_env(monkeypatch):
    # Fake credentials, so nothing in a test can ever reach a real AWS account.
    for name, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": "eu-west-2",
    }.items():
        monkeypatch.setenv(name, value)


@pytest.fixture
def dynamodb(aws_env):
    """A client and an empty table of its own, on DynamoDB Local or moto."""
    table = f"test-{uuid.uuid4().hex[:12]}"
    if DYNAMODB_URL:
        client = dynamodb_client("eu-west-2", DYNAMODB_URL)
        create_table(client, table)
        yield client, table
        client.delete_table(TableName=table)
    else:
        with mock_aws():
            client = dynamodb_client("eu-west-2")
            create_table(client, table)
            yield client, table


@pytest.fixture
def settings(request):
    if DYNAMODB_URL:
        db_client, table = request.getfixturevalue("dynamodb")
        return Settings(
            environment="test",
            cors_origins=["http://localhost:3000"],
            store="dynamodb",
            dynamodb_endpoint_url=DYNAMODB_URL,
            dynamodb_table=table,
            _env_file=None,
        )
    return Settings(environment="test", cors_origins=["http://localhost:3000"], _env_file=None)


@pytest.fixture
def app(settings):
    app = create_app(settings)

    # Test-only routes to exercise validation and crash handling before real endpoints exist.
    @app.post("/_echo")
    async def echo(dep: Dependency):
        return dep

    @app.get("/_boom")
    async def boom():
        raise RuntimeError("secret internal detail")

    return app


@pytest.fixture
def token(app):
    """Access tokens from the app's own local issuer: `token("bob")`."""
    return app.state.local_issuer.issue


@pytest.fixture
def client(app, token):
    # Signed in as alice by default; tests about auth itself use `anon`.
    headers = {"Authorization": f"Bearer {token('alice')}"}
    return TestClient(app, raise_server_exceptions=False, headers=headers)


@pytest.fixture
def anon(app):
    return TestClient(app, raise_server_exceptions=False)
