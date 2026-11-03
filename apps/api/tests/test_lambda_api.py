import base64
import json

import pytest


def event(path, method="GET", headers=None, body=None, claims=None):
    """An API Gateway HTTP API (payload 2.0) event, as Lambda receives it."""
    return {
        "version": "2.0",
        "routeKey": "$default",
        "rawPath": path,
        "rawQueryString": "",
        "headers": {"host": "api.example.com", **(headers or {})},
        "requestContext": {
            "accountId": "123456789012",
            "apiId": "abc123",
            "domainName": "api.example.com",
            "http": {
                "method": method,
                "path": path,
                "protocol": "HTTP/1.1",
                "sourceIp": "203.0.113.7",
                "userAgent": "test",
            },
            "requestId": "req-1",
            "stage": "$default",
            "time": "03/Nov/2026:12:00:00 +0000",
            "timeEpoch": 1_793_000_000_000,
            **({"authorizer": {"jwt": {"claims": claims, "scopes": None}}} if claims else {}),
        },
        "body": body,
        "isBase64Encoded": False,
    }


class Context:
    function_name = "threatlens-api"
    aws_request_id = "lambda-req-1"

    def get_remaining_time_in_millis(self):
        return 29_000


@pytest.fixture(scope="module")
def handler():
    from threatlens_api.lambda_api import handler

    return handler


def test_health_through_the_lambda_handler(handler):
    r = handler(event("/health"), Context())
    assert r["statusCode"] == 200
    assert json.loads(r["body"])["status"] == "ok"
    assert r["headers"]["x-content-type-options"] == "nosniff"


def test_authorizer_claims_in_the_event_are_not_trusted(handler):
    # Even if the gateway passed claims for alice, no bearer token means no access.
    r = handler(event("/projects", claims={"sub": "alice", "client_id": "x"}), Context())
    assert r["statusCode"] == 401


def test_binary_upload_body_reaches_the_app(handler):
    body = base64.b64encode(b"jinja2==2.10\n").decode()
    e = event("/projects/00000000-0000-4000-8000-000000000000/scans", "POST", body=body)
    e["isBase64Encoded"] = True
    e["rawQueryString"] = "filename=requirements.txt"
    r = handler(e, Context())
    assert r["statusCode"] == 401  # reached the app's own auth check, not a 500
