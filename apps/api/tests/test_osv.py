"""OSV client tests against responses recorded from api.osv.dev on 28 Oct 2026.

No test touches the network: a MockTransport serves the recorded JSON from tests/fixtures/osv.
"""

import json
from pathlib import Path

import httpx
import pytest

from threatlens_api.models import Dependency, Ecosystem, Severity
from threatlens_api.osv import (
    BATCH_SIZE,
    MAX_RETRY_AFTER,
    OsvClient,
    OsvError,
    TTLCache,
    key,
    merge_aliases,
)

FIXTURES = Path(__file__).parent / "fixtures" / "osv"

JINJA2 = Dependency(name="jinja2", version="2.10", ecosystem=Ecosystem.PYPI)
LODASH = Dependency(name="lodash", version="4.17.15", ecosystem=Ecosystem.NPM)
LEFT_PAD = Dependency(name="left-pad", version="1.3.0", ecosystem=Ecosystem.NPM)
RECORDED = [JINJA2, LODASH, LEFT_PAD]


def recorded_osv(request: httpx.Request) -> httpx.Response:
    """Answers like api.osv.dev did when the fixtures were recorded."""
    if request.url.path == "/v1/querybatch":
        queries = json.loads(request.content)["queries"]
        recorded = json.loads((FIXTURES / "querybatch.json").read_text())["results"]
        by_dep = {
            (d.ecosystem.value, d.name, d.version): r
            for d, r in zip(RECORDED, recorded, strict=True)
        }
        results = [
            by_dep.get((q["package"]["ecosystem"], q["package"]["name"], q["version"]), {})
            for q in queries
        ]
        return httpx.Response(200, json={"results": results})
    if request.url.path.startswith("/v1/vulns/"):
        path = FIXTURES / f"{request.url.path.rsplit('/', 1)[-1]}.json"
        if path.exists():
            return httpx.Response(200, content=path.read_bytes())
        return httpx.Response(404, json={"code": 5, "message": "Bug not found."})
    return httpx.Response(404)


class Recorder:
    """Wraps a handler, keeps every request it saw."""

    def __init__(self, handler=recorded_osv):
        self.handler, self.requests = handler, []

    def __call__(self, request):
        self.requests.append(request)
        return self.handler(request)


def client(handler=None, **kwargs):
    recorder = handler if isinstance(handler, Recorder) else Recorder(handler or recorded_osv)
    http = httpx.Client(base_url="https://api.osv.dev", transport=httpx.MockTransport(recorder))
    kwargs.setdefault("sleep", lambda s: None)
    return OsvClient(http=http, **kwargs), recorder


# --- happy path on real data


def test_scan_finds_recorded_vulnerabilities():
    osv, _ = client()
    result = osv.scan(RECORDED)
    assert result.complete
    assert key(LEFT_PAD) in result.vulns
    assert result.vulns[key(LEFT_PAD)] == []
    assert len(result.vulns[key(LODASH)]) == 6


def test_ghsa_and_pysec_duplicates_merge_into_one_finding():
    # OSV lists 12 ids for jinja2 2.10, but they're 6 bugs, each published as GHSA + PYSEC.
    osv, _ = client()
    vulns = osv.scan([JINJA2]).vulns[key(JINJA2)]
    assert len(vulns) == 6
    assert all(v.id.startswith("GHSA-") for v in vulns)  # the record with a severity wins


def test_vuln_details_are_parsed():
    osv, _ = client()
    v = osv.vuln("GHSA-462w-v97r-4m45")
    assert v.severity == Severity.HIGH
    assert "CVE-2019-10906" in v.aliases
    assert v.cvss_vectors[0].startswith("CVSS:3.0/")
    assert v.fixed_versions(JINJA2) == ["2.10.1"]


def test_fixed_version_comes_from_the_matching_package_only():
    # GHSA-p6mc also covers lodash-es (fixed 4.17.20) and lodash.set (never fixed).
    osv, _ = client()
    assert osv.vuln("GHSA-p6mc-m468-83gw").fixed_versions(LODASH) == ["4.17.19"]


def test_moderate_maps_to_medium():
    osv, _ = client()
    assert osv.vuln("GHSA-29mw-wpgm-hmr9").severity == Severity.MEDIUM


def test_pysec_without_severity_is_unknown_not_low():
    osv, _ = client()
    assert osv.vuln("PYSEC-2019-217").severity == Severity.UNKNOWN


# --- caching


def test_second_scan_is_served_from_cache():
    osv, rec = client()
    osv.scan(RECORDED)
    calls = len(rec.requests)
    assert osv.scan(RECORDED).vulns.keys() == {key(d) for d in RECORDED}
    assert len(rec.requests) == calls


def test_clean_packages_are_cached_too():
    osv, rec = client()
    osv.scan([LEFT_PAD])
    osv.scan([LEFT_PAD])
    assert len(rec.requests) == 1


def test_cache_expires():
    now = [1000.0]
    ids_cache = TTLCache(ttl=60, clock=lambda: now[0])
    osv, rec = client(ids_cache=ids_cache)
    osv.scan([LEFT_PAD])
    now[0] += 61
    osv.scan([LEFT_PAD])
    assert len(rec.requests) == 2


def test_cache_size_is_capped():
    cache = TTLCache(ttl=60, max_items=3)
    for i in range(10):
        cache.set(i, i)
    assert len(cache) == 3
    assert cache.get(0) is None
    assert cache.get(9) == 9


def test_large_scan_is_split_into_batches():
    deps = [
        Dependency(name=f"pkg{i}", version="1.0.0", ecosystem=Ecosystem.PYPI)
        for i in range(BATCH_SIZE * 2 + 5)
    ]
    osv, rec = client()
    result = osv.scan(deps)
    assert result.complete
    sizes = [len(json.loads(r.content)["queries"]) for r in rec.requests]
    assert sizes == [BATCH_SIZE, BATCH_SIZE, 5]


# --- OSV misbehaving: never crash, never report "clean" for something not checked


def fails_n_times(n, status=503, headers=None):
    count = [0]

    def handler(request):
        count[0] += 1
        if count[0] <= n:
            return httpx.Response(status, headers=headers or {})
        return recorded_osv(request)

    return handler


def test_retries_a_temporary_outage():
    slept = []
    osv, rec = client(fails_n_times(2), sleep=slept.append, backoff=0.5)
    assert osv.scan([LEFT_PAD]).complete
    assert slept == [0.5, 1.0]


def test_retry_after_is_honoured_but_capped():
    slept = []
    osv, _ = client(fails_n_times(1, 429, {"retry-after": "3600"}), sleep=slept.append)
    osv.scan([LEFT_PAD])
    assert slept == [MAX_RETRY_AFTER]


def test_persistent_outage_marks_dependencies_unchecked():
    osv, rec = client(lambda r: httpx.Response(500), max_retries=2)
    result = osv.scan(RECORDED)
    assert not result.complete
    assert result.failed == RECORDED
    assert result.vulns == {}
    assert len(rec.requests) == 3


def test_network_errors_are_retried_then_reported():
    def down(request):
        raise httpx.ConnectError("connection refused", request=request)

    osv, rec = client(down, max_retries=1)
    assert osv.scan([LEFT_PAD]).failed == [LEFT_PAD]
    assert len(rec.requests) == 2


def test_client_errors_are_not_retried():
    osv, rec = client(lambda r: httpx.Response(400, json={"message": "bad"}))
    assert osv.scan([LEFT_PAD]).failed == [LEFT_PAD]
    assert len(rec.requests) == 1


def test_redirects_are_not_followed():
    # A redirect could point the client at any host; OSV has no reason to send one.
    osv, rec = client(
        lambda r: httpx.Response(302, headers={"location": "http://169.254.169.254/"})
    )
    assert osv.scan([LEFT_PAD]).failed == [LEFT_PAD]
    assert all(r.url.host == "api.osv.dev" for r in rec.requests)


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, content=b"<html>maintenance</html>"),
        httpx.Response(200, json={"unexpected": True}),
        httpx.Response(200, json={"results": []}),  # wrong count
        httpx.Response(200, json={"results": [{"vulns": "not-a-list"}]}),
    ],
)
def test_malformed_batch_responses_fail_safely(response):
    osv, _ = client(lambda r: response)
    result = osv.scan([LEFT_PAD])
    assert result.failed == [LEFT_PAD]
    assert key(LEFT_PAD) not in result.vulns


def test_oversized_response_is_rejected(monkeypatch):
    monkeypatch.setattr("threatlens_api.osv.MAX_RESPONSE_BYTES", 100)
    osv, _ = client()
    assert osv.scan([JINJA2]).failed == [JINJA2]


def test_failed_lookups_are_not_cached():
    osv, rec = client(fails_n_times(1, 400))
    assert not osv.scan([LEFT_PAD]).complete
    assert osv.scan([LEFT_PAD]).complete


def test_one_failed_detail_does_not_sink_other_packages():
    def no_lodash_details(request):
        if request.url.path.startswith("/v1/vulns/GHSA-") and "p6mc" in request.url.path:
            return httpx.Response(500)
        return recorded_osv(request)

    osv, _ = client(no_lodash_details, max_retries=0)
    result = osv.scan(RECORDED)
    assert result.failed == [LODASH]
    assert len(result.vulns[key(JINJA2)]) == 6


# --- hostile ids in responses


@pytest.mark.parametrize(
    "bad_id",
    ["../../admin", "GHSA-x/../../etc", "ghsa-lowercase", "", "A" * 200, "GHSA-x?y=1", "CVE-1 2"],
)
def test_hostile_vuln_ids_never_reach_a_url(bad_id):
    def handler(request):
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": bad_id}]}]})
        raise AssertionError(f"unexpected request to {request.url}")

    osv, _ = client(handler)
    assert osv.scan([LEFT_PAD]).failed == [LEFT_PAD]


def test_response_for_a_different_id_is_rejected():
    def handler(request):
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-aaaa"}]}]})
        return httpx.Response(200, json={"id": "GHSA-bbbb"})

    osv, _ = client(handler)
    assert osv.scan([LEFT_PAD]).failed == [LEFT_PAD]


def test_junk_aliases_and_long_summary_are_trimmed():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "id": "GHSA-abcd",
                "summary": "x" * 5000,
                "aliases": ["CVE-2024-1", "<script>", "../x"],
                "affected": [
                    {
                        "package": {"name": "a", "ecosystem": "npm"},
                        "ranges": [{"events": [{"fixed": "1.0; rm -rf /"}]}],
                    }
                ],
            },
        )

    osv, _ = client(handler)
    v = osv.vuln("GHSA-abcd")
    assert len(v.summary) == 1000
    assert v.aliases == ("CVE-2024-1",)
    assert v.fixed_versions(Dependency(name="a", version="0.1", ecosystem=Ecosystem.NPM)) == []


# --- pagination


def test_next_page_token_is_followed():
    def handler(request):
        query = json.loads(request.content)["queries"][0]
        if "page_token" not in query:
            return httpx.Response(
                200, json={"results": [{"vulns": [{"id": "GHSA-0001"}], "next_page_token": "p2"}]}
            )
        assert query["page_token"] == "p2"
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-0002"}]}]})

    osv, _ = client(handler)
    ids, failed = osv.vuln_ids([LEFT_PAD])
    assert ids[key(LEFT_PAD)] == ["GHSA-0001", "GHSA-0002"]
    assert failed == []


def test_endless_pagination_is_cut_off():
    def handler(request):
        return httpx.Response(
            200, json={"results": [{"vulns": [{"id": "GHSA-0001"}], "next_page_token": "again"}]}
        )

    osv, rec = client(handler)
    _, failed = osv.vuln_ids([LEFT_PAD])
    assert failed == [LEFT_PAD]
    assert len(rec.requests) == 10


def test_empty_page_result_fails_instead_of_crashing():
    def handler(request):
        query = json.loads(request.content)["queries"][0]
        if "page_token" not in query:
            return httpx.Response(200, json={"results": [{"next_page_token": "p2"}]})
        return httpx.Response(200, json={"results": []})

    osv, _ = client(handler)
    assert osv.vuln_ids([LEFT_PAD])[1] == [LEFT_PAD]


# --- alias merging


def test_merge_aliases_handles_chains_and_keeps_unrelated():
    osv, _ = client()
    a = osv.vuln("GHSA-462w-v97r-4m45")
    b = osv.vuln("PYSEC-2019-217")
    c = osv.vuln("GHSA-p6mc-m468-83gw")
    assert merge_aliases([b, a, c]) == [a, c]
    assert merge_aliases([]) == []


def test_invalid_id_is_refused_before_any_request():
    osv, rec = client()
    with pytest.raises(OsvError):
        osv.vuln("../etc/passwd")
    assert rec.requests == []
