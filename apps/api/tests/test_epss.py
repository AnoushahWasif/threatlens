"""EPSS client tests against a response recorded from api.first.org on 28 Oct 2026."""

import json
from pathlib import Path

import httpx
import pytest

from threatlens_api.epss import MAX_PARAM_CHARS, MAX_PER_REQUEST, EpssClient, chunks

RECORDED = json.loads((Path(__file__).parent / "fixtures" / "epss" / "epss.json").read_text())
BY_CVE = {row["cve"]: row for row in RECORDED["data"]}


def recorded_epss(request: httpx.Request) -> httpx.Response:
    asked = request.url.params["cve"].split(",")
    rows = [BY_CVE[c] for c in asked if c in BY_CVE]
    return httpx.Response(200, json={**RECORDED, "total": len(rows), "data": rows})


def client(handler=recorded_epss, **kwargs):
    seen = []

    def recorder(request):
        seen.append(request)
        return handler(request)

    http = httpx.Client(base_url="https://api.first.org", transport=httpx.MockTransport(recorder))
    kwargs.setdefault("sleep", lambda s: None)
    return EpssClient(http=http, **kwargs), seen


def respond(rows, total=None):
    return lambda request: httpx.Response(
        200, json={"total": len(rows) if total is None else total, "data": rows}
    )


def test_recorded_scores_are_parsed():
    epss, _ = client()
    result = epss.scores(["CVE-2021-44228", "CVE-2024-22195"])
    assert result.scores["CVE-2021-44228"].epss == pytest.approx(0.99999)
    assert result.scores["CVE-2024-22195"].epss == pytest.approx(0.00892)
    assert result.scores["CVE-2024-22195"].percentile == pytest.approx(0.59295)
    assert result.scores["CVE-2024-22195"].date == "2026-10-28"
    assert not result.failed


def test_cve_epss_does_not_know_is_unscored_not_failed():
    epss, _ = client()
    result = epss.scores(["CVE-1999-0000"])
    assert result.scores == {}
    assert result.failed == set()


def test_second_lookup_is_cached_including_unknown_cves():
    epss, seen = client()
    epss.scores(["CVE-2021-44228", "CVE-1999-0000"])
    again = epss.scores(["CVE-2021-44228", "CVE-1999-0000"])
    assert len(seen) == 1
    assert "CVE-2021-44228" in again.scores
    assert "CVE-1999-0000" not in again.scores


def test_duplicates_and_non_cve_ids_are_not_sent():
    epss, seen = client()
    epss.scores(["CVE-2021-44228", "CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q", "cve-2021-1,x"])
    assert seen[0].url.params["cve"] == "CVE-2021-44228"


def test_nothing_to_look_up_makes_no_request():
    epss, seen = client()
    assert epss.scores(["GHSA-jfh8-c2jp-5v3q"]).scores == {}
    assert seen == []


def test_chunks_respect_count_and_length_limits():
    cves = [f"CVE-2026-{n:07d}" for n in range(1000)]
    parts = chunks(cves)
    assert sum(len(p) for p in parts) == 1000
    assert all(len(p) <= MAX_PER_REQUEST for p in parts)
    assert all(len(",".join(p)) <= MAX_PARAM_CHARS for p in parts)


def test_large_lookup_is_split_into_requests():
    epss, seen = client()
    epss.scores([f"CVE-2026-{n:05d}" for n in range(250)])
    assert len(seen) == 3


def test_rows_for_cves_we_did_not_ask_about_are_ignored():
    row = {"cve": "CVE-2000-0001", "epss": "0.9", "percentile": "0.9", "date": "2026-10-28"}
    epss, _ = client(respond([row]))
    result = epss.scores(["CVE-2021-44228"])
    assert result.scores == {}


@pytest.mark.parametrize("bad", ["nan", "inf", "-0.1", "1.5", "high", None])
def test_values_that_are_not_probabilities_fail_the_chunk(bad):
    row = {"cve": "CVE-2021-44228", "epss": bad, "percentile": "0.5", "date": "2026-10-28"}
    epss, _ = client(respond([row]))
    result = epss.scores(["CVE-2021-44228"])
    assert result.scores == {}
    assert result.failed == {"CVE-2021-44228"}


def test_partial_page_fails_instead_of_dropping_rows():
    epss, _ = client(respond([BY_CVE["CVE-2021-44228"]], total=2))
    result = epss.scores(["CVE-2021-44228", "CVE-2024-22195"])
    assert result.failed == {"CVE-2021-44228", "CVE-2024-22195"}


@pytest.mark.parametrize("body", [b"not json", b'{"data": "x"}', b"[]"])
def test_malformed_responses_fail_safely(body):
    epss, _ = client(lambda r: httpx.Response(200, content=body))
    assert epss.scores(["CVE-2021-44228"]).failed == {"CVE-2021-44228"}


def test_outage_is_retried_then_reported_and_not_cached():
    epss, seen = client(lambda r: httpx.Response(503), max_retries=2)
    assert epss.scores(["CVE-2021-44228"]).failed == {"CVE-2021-44228"}
    assert len(seen) == 3
    assert len(epss.cache) == 0


def test_one_failed_chunk_does_not_sink_the_others():
    calls = []

    def flaky(request):
        calls.append(request)
        return httpx.Response(400) if len(calls) == 1 else recorded_epss(request)

    epss, _ = client(flaky)
    cves = [f"CVE-2026-{n:05d}" for n in range(MAX_PER_REQUEST)] + ["CVE-2021-44228"]
    result = epss.scores(cves)
    assert len(result.failed) == MAX_PER_REQUEST
    assert "CVE-2021-44228" in result.scores
