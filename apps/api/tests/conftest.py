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
def client(app):
    return TestClient(app, raise_server_exceptions=False)
