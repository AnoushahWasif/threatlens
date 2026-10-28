"""JSON over HTTP with the retry and size rules every outside service gets (OSV, EPSS, KEV)."""

import time
from collections.abc import Callable

import httpx

from threatlens_api import __version__

MAX_RETRY_AFTER = 30.0
RETRY_STATUSES = {429, 500, 502, 503, 504}


class FetchError(Exception):
    pass


def default_http(base_url: str, timeout: float = 10.0) -> httpx.Client:
    return httpx.Client(
        base_url=base_url,
        timeout=httpx.Timeout(timeout, connect=5.0),
        follow_redirects=False,
        headers={"user-agent": f"threatlens/{__version__}"},
    )


class JsonFetcher:
    def __init__(
        self,
        http: httpx.Client,
        name: str,
        error: type[FetchError] = FetchError,
        max_retries: int = 3,
        backoff: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.http, self.name, self.error = http, name, error
        self.max_retries, self.backoff, self.sleep = max_retries, backoff, sleep

    def request(
        self,
        method: str,
        path: str,
        *,
        max_bytes: int,
        body: dict | None = None,
        params: dict | None = None,
    ):
        reason, delay = "no attempt made", 0.0
        for attempt in range(self.max_retries + 1):
            if attempt:
                self.sleep(delay)
            try:
                resp = self.http.request(method, path, json=body, params=params)
            except httpx.TransportError as exc:
                reason = type(exc).__name__
                delay = self.backoff * 2**attempt
                continue
            if resp.status_code in RETRY_STATUSES:
                reason = f"HTTP {resp.status_code}"
                delay = _retry_after(resp) or self.backoff * 2**attempt
                continue
            if resp.status_code != 200:
                raise self.error(f"{self.name} returned HTTP {resp.status_code}")
            if len(resp.content) > max_bytes:
                raise self.error(f"{self.name} response too large")
            try:
                return resp.json()
            except ValueError as exc:
                raise self.error(f"{self.name} response is not JSON") from exc
        raise self.error(
            f"{self.name} unavailable after {self.max_retries + 1} attempts ({reason})"
        )


def _retry_after(resp: httpx.Response) -> float | None:
    try:
        return min(float(resp.headers["retry-after"]), MAX_RETRY_AFTER)
    except (KeyError, ValueError):
        return None
