"""Runs inside the AWS Lambda Python 3.12 image, against the unzipped package only (CI).

Proves the zip imports on Lambda's own Linux and Python, with Linux wheels for
pydantic-core and cryptography, and that both handlers answer.
"""

import json

from threatlens_api.lambda_api import handler
from threatlens_api.worker import lambda_handler_for


def check(ok: bool, what: object) -> None:
    # Not assert: that is skipped under python -O.
    if not ok:
        raise SystemExit(f"lambda smoke test failed: {what}")


class Context:
    function_name = "threatlens-api"
    aws_request_id = "smoke"

    def get_remaining_time_in_millis(self):
        return 29_000


def http_event(path: str) -> dict:
    return {
        "version": "2.0",
        "routeKey": "$default",
        "rawPath": path,
        "rawQueryString": "",
        "headers": {"host": "smoke"},
        "requestContext": {
            "http": {"method": "GET", "path": path, "protocol": "HTTP/1.1", "sourceIp": "1.2.3.4"},
            "requestId": "smoke",
            "stage": "$default",
        },
        "isBase64Encoded": False,
    }


health = handler(http_event("/health"), Context())
check(health["statusCode"] == 200, health)
check(json.loads(health["body"])["status"] == "ok", health)

denied = handler(http_event("/projects"), Context())
check(denied["statusCode"] == 401, denied)


class NoWork:
    def handle(self, message):
        raise SystemExit("lambda smoke test failed: an odd message reached the worker")


worker = lambda_handler_for(NoWork())
result = worker({"Records": [{"messageId": "1", "body": "not json"}]})
check(result == {"batchItemFailures": []}, result)
print("lambda smoke test: ok")
