"""KEV client tests against the CISA feed recorded on 28 Oct 2026, trimmed to 6 entries."""

import json
from pathlib import Path

import httpx
import pytest

from threatlens_api import kev as kev_module
from threatlens_api.kev import MAX_STALE, TTL, KevClient, KevError, parse

FEED = json.loads(
    (Path(__file__).parent / "fixtures" / "kev" / "kev.json").read_text(encoding="utf-8")
)


@pytest.fixture(autouse=True)
def small_feed_allowed(monkeypatch):
    # The real feed has 1760 entries; the fixture keeps 6.
    monkeypatch.setattr(kev_module, "MIN_ENTRIES", 1)


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


def client(handler=None, **kwargs):
    seen = []

    def recorder(request):
        seen.append(request)
        return (handler or (lambda r: httpx.Response(200, json=FEED)))(request)

    http = httpx.Client(base_url="https://www.cisa.gov", transport=httpx.MockTransport(recorder))
    kwargs.setdefault("sleep", lambda s: None)
    return KevClient(http=http, **kwargs), seen


def test_recorded_feed_is_parsed():
    kev, seen = client()
    catalog = kev.catalog()
    assert "CVE-2021-44228" in catalog
    assert "CVE-2024-22195" not in catalog
    assert catalog.entries["CVE-2021-44228"].ransomware is True
    assert catalog.entries["CVE-2026-48356"].ransomware is False
    assert catalog.version == "2026.10.27"
    assert not catalog.stale
    assert seen[0].url.path.endswith("known_exploited_vulnerabilities.json")


def test_catalog_is_downloaded_once_a_day():
    clock = Clock()
    kev, seen = client(clock=clock)
    kev.catalog()
    clock.now += TTL - 1
    kev.catalog()
    assert len(seen) == 1
    clock.now += 2
    kev.catalog()
    assert len(seen) == 2


def test_failed_refresh_uses_the_last_good_copy_marked_stale():
    clock = Clock()
    responses = iter([httpx.Response(200, json=FEED)] + [httpx.Response(503)] * 10)
    kev, _ = client(lambda r: next(responses), clock=clock, max_retries=1)
    kev.catalog()
    clock.now += TTL + 1
    catalog = kev.catalog()
    assert catalog.stale
    assert "CVE-2021-44228" in catalog


def test_copy_older_than_the_stale_limit_is_not_used():
    clock = Clock()
    responses = iter([httpx.Response(200, json=FEED)] + [httpx.Response(503)] * 10)
    kev, _ = client(lambda r: next(responses), clock=clock, max_retries=1)
    kev.catalog()
    clock.now += MAX_STALE + 1
    with pytest.raises(KevError):
        kev.catalog()


def test_no_copy_and_no_feed_raises():
    kev, seen = client(lambda r: httpx.Response(503), max_retries=2)
    with pytest.raises(KevError, match="unavailable after 3 attempts"):
        kev.catalog()
    assert len(seen) == 3


def test_count_mismatch_is_rejected():
    with pytest.raises(KevError, match="count"):
        parse({**FEED, "count": FEED["count"] + 1}, 0)


def test_short_feed_is_rejected_at_the_real_limit(monkeypatch):
    monkeypatch.setattr(kev_module, "MIN_ENTRIES", 1000)
    with pytest.raises(KevError, match="short"):
        parse(FEED, 0)


def test_empty_feed_is_rejected():
    with pytest.raises(KevError):
        parse({**FEED, "count": 0, "vulnerabilities": []}, 0)


@pytest.mark.parametrize(
    "raw",
    [
        {},
        {"catalogVersion": "x", "count": 1, "vulnerabilities": [{"dateAdded": "2026-01-01"}]},
        {"catalogVersion": "x", "count": "many", "vulnerabilities": []},
        {"catalogVersion": "x", "count": 1, "vulnerabilities": "CVE-2021-44228"},
    ],
)
def test_malformed_feed_is_rejected(raw):
    with pytest.raises(KevError):
        parse(raw, 0)


def test_entries_with_junk_cve_ids_are_dropped():
    junk = {**FEED["vulnerabilities"][0], "cveID": "<script>"}
    feed = {**FEED, "count": FEED["count"] + 1, "vulnerabilities": [*FEED["vulnerabilities"], junk]}
    catalog = parse(feed, 0)
    assert "<script>" not in catalog
    assert len(catalog.entries) == FEED["count"]


def test_non_json_feed_fails():
    kev, _ = client(lambda r: httpx.Response(200, content=b"<html>maintenance</html>"))
    with pytest.raises(KevError, match="not JSON"):
        kev.catalog()


def test_redirect_is_not_followed():
    kev, seen = client(lambda r: httpx.Response(302, headers={"location": "https://evil.test/"}))
    with pytest.raises(KevError, match="HTTP 302"):
        kev.catalog()
    assert len(seen) == 1
