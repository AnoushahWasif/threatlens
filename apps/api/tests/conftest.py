import pytest
from fastapi.testclient import TestClient

from threatlens_api.main import create_app
from threatlens_api.models import Dependency
from threatlens_api.settings import Settings


@pytest.fixture
def settings():
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
