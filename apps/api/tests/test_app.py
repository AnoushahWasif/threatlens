from fastapi.testclient import TestClient

from threatlens_api import __version__
from threatlens_api.main import create_app
from threatlens_api.models import Dependency
from threatlens_api.settings import Settings

VALID_DEP = {"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"}


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "version": __version__}


def test_security_headers_on_every_response(client):
    for path in ["/health", "/does-not-exist"]:
        r = client.get(path)
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["X-Frame-Options"] == "DENY"
        assert "default-src 'none'" in r.headers["Content-Security-Policy"]


def test_request_id_generated(client):
    r = client.get("/health")
    assert len(r.headers["X-Request-ID"]) == 32


def test_valid_client_request_id_is_kept(client):
    r = client.get("/health", headers={"X-Request-ID": "abc-12345678"})
    assert r.headers["X-Request-ID"] == "abc-12345678"


def test_malicious_request_id_is_replaced(client):
    r = client.get("/health", headers={"X-Request-ID": "x\r\nfake-log-line"})
    assert r.headers["X-Request-ID"] != "x\r\nfake-log-line"
    assert len(r.headers["X-Request-ID"]) == 32


def test_not_found_uses_error_shape(client):
    r = client.get("/nope")
    assert r.status_code == 404
    body = r.json()["error"]
    assert body["code"] == "not_found"
    assert body["request_id"] == r.headers["X-Request-ID"]


def test_method_not_allowed(client):
    r = client.delete("/health")
    assert r.status_code == 405
    assert r.json()["error"]["code"] == "method_not_allowed"


def test_validation_error_does_not_echo_input(client):
    payload = {**VALID_DEP, "version": "<script>alert(1)</script>"}
    r = client.post("/_echo", json=payload)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "validation_error"
    assert "<script>" not in r.text
    assert r.json()["error"]["details"][0]["loc"] == ["body", "version"]


def test_unknown_field_rejected(client):
    r = client.post("/_echo", json={**VALID_DEP, "is_admin": True})
    assert r.status_code == 422


def test_valid_body_accepted(client):
    r = client.post("/_echo", json=VALID_DEP)
    assert r.status_code == 200
    assert r.json()["ecosystem"] == "PyPI"


def test_oversized_body_rejected(settings):
    small = Settings(environment="test", max_request_bytes=100, _env_file=None)
    app = create_app(small)

    @app.post("/_echo")
    async def echo(dep: Dependency):
        return dep

    r = TestClient(app).post("/_echo", json={**VALID_DEP, "name": "a" * 200})
    assert r.status_code == 413
    assert r.json()["error"]["code"] == "payload_too_large"


def test_crash_returns_generic_500(client):
    r = client.get("/_boom")
    assert r.status_code == 500
    assert r.json()["error"]["code"] == "internal_error"
    assert "secret internal detail" not in r.text
    assert r.json()["error"]["request_id"] == r.headers["X-Request-ID"]
    assert r.headers["X-Frame-Options"] == "DENY"


def test_docs_on_in_dev_off_in_prod(client):
    assert client.get("/docs").status_code == 200
    prod = Settings(
        environment="prod",
        cors_origins=["https://threatlens.example.com"],
        llm_api_key="k" * 32,
        _env_file=None,
    )
    prod_client = TestClient(create_app(prod))
    assert prod_client.get("/docs").status_code == 404
    assert prod_client.get("/openapi.json").status_code == 404


def test_cors_allows_only_configured_origin(client):
    ok = client.get("/health", headers={"Origin": "http://localhost:3000"})
    assert ok.headers["access-control-allow-origin"] == "http://localhost:3000"
    bad = client.get("/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in bad.headers
