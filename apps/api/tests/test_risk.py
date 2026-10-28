"""Risk score and enrichment tests. Network calls use the recorded OSV, EPSS and KEV fixtures."""

from uuid import uuid4

import httpx
import pytest
from test_epss import client as epss_client
from test_kev import FEED
from test_osv import JINJA2, LEFT_PAD, LODASH
from test_osv import client as osv_client

from threatlens_api import kev as kev_module
from threatlens_api.kev import KevClient
from threatlens_api.models import Dependency, Ecosystem, Finding, Severity
from threatlens_api.osv import ScanResult, Vuln, key
from threatlens_api.risk import WEIGHTS, enrich, rank, risk_score


@pytest.fixture(autouse=True)
def small_feed_allowed(monkeypatch):
    monkeypatch.setattr(kev_module, "MIN_ENTRIES", 1)


def kev_client(handler=None):
    transport = httpx.MockTransport(handler or (lambda r: httpx.Response(200, json=FEED)))
    http = httpx.Client(base_url="https://www.cisa.gov", transport=transport)
    return KevClient(http=http, sleep=lambda s: None, max_retries=0)


# --- the formula


def test_kev_counts_as_certain_exploitation():
    assert risk_score(Severity.CRITICAL, 0.01, in_kev=True) == 100
    assert risk_score(Severity.HIGH, None, in_kev=True) == 75


def test_epss_scales_the_score():
    assert risk_score(Severity.CRITICAL, 0.5, in_kev=False) == 50
    assert risk_score(Severity.MEDIUM, 0.2, in_kev=False) == 10


def test_no_epss_and_not_in_kev_is_unscored_not_zero():
    assert risk_score(Severity.CRITICAL, None, in_kev=False) is None


def test_zero_epss_is_a_real_zero():
    assert risk_score(Severity.CRITICAL, 0.0, in_kev=False) == 0


def test_unknown_severity_is_weighted_like_medium_not_low():
    assert WEIGHTS[Severity.UNKNOWN] == WEIGHTS[Severity.MEDIUM] > WEIGHTS[Severity.LOW]


@pytest.mark.parametrize("severity", list(Severity))
@pytest.mark.parametrize("epss", [0.0, 0.00001, 0.5, 1.0])
@pytest.mark.parametrize("in_kev", [True, False])
def test_score_always_fits_the_model_bounds(severity, epss, in_kev):
    assert 0 <= risk_score(severity, epss, in_kev) <= 100


def test_low_epss_kev_entry_outranks_unexploited_high_epss():
    assert risk_score(Severity.HIGH, 0.01, True) > risk_score(Severity.HIGH, 0.9, False)


# --- ranking


def finding(vuln_id, severity, risk, name="pkg"):
    dep = Dependency(name=name, version="1.0", ecosystem=Ecosystem.PYPI)
    return Finding(
        project_id=uuid4(), dependency=dep, vuln_id=vuln_id, severity=severity, risk_score=risk
    )


def test_rank_puts_highest_risk_first_and_unscored_last():
    findings = [
        finding("CVE-2000-0001", Severity.CRITICAL, None),
        finding("CVE-2000-0002", Severity.LOW, 2.0),
        finding("CVE-2000-0003", Severity.HIGH, 40.0),
        finding("CVE-2000-0004", Severity.MEDIUM, None),
    ]
    assert [f.vuln_id for f in rank(findings)] == [
        "CVE-2000-0003",
        "CVE-2000-0002",
        "CVE-2000-0001",  # unscored, but critical before medium
        "CVE-2000-0004",
    ]


def test_ties_break_on_severity_then_name_so_order_is_stable():
    findings = [
        finding("CVE-2000-0001", Severity.LOW, 5.0, name="b"),
        finding("CVE-2000-0002", Severity.HIGH, 5.0, name="b"),
        finding("CVE-2000-0003", Severity.HIGH, 5.0, name="a"),
    ]
    assert [f.vuln_id for f in rank(findings)] == [
        "CVE-2000-0003",
        "CVE-2000-0002",
        "CVE-2000-0001",
    ]


def test_zero_risk_ranks_above_unscored():
    findings = [
        finding("CVE-2000-0001", Severity.LOW, None),
        finding("CVE-2000-0002", Severity.LOW, 0.0),
    ]
    assert rank(findings)[0].vuln_id == "CVE-2000-0002"


# --- enrichment on recorded data


def scan_recorded():
    osv, _ = osv_client()
    deps = [JINJA2, LODASH, LEFT_PAD]
    return deps, osv.scan(deps)


def test_recorded_scan_is_ranked_by_exploit_likelihood():
    deps, scan = scan_recorded()
    epss, _ = epss_client()
    result = enrich(uuid4(), deps, scan, epss, kev_client())
    assert result.complete
    top = result.findings[0]
    # lodash CVE-2021-23337 has the highest EPSS (0.213) of the recorded bugs and is HIGH.
    assert top.dependency.name == "lodash"
    assert top.epss == pytest.approx(0.21333)
    assert top.risk_score == pytest.approx(100 * 0.21333 * 0.75, abs=0.01)
    scores = [f.risk_score for f in result.findings]
    assert scores == sorted(scores, reverse=True)
    assert len(result.findings) == 6 + 6  # jinja2's 6 merged bugs, lodash's 6


def test_epss_is_looked_up_once_per_cve_for_the_whole_scan():
    deps, scan = scan_recorded()
    epss, seen = epss_client()
    enrich(uuid4(), deps, scan, epss, kev_client())
    assert len(seen) == 1


def synthetic_scan(vuln):
    dep = Dependency(name="log4j-core", version="2.14.1", ecosystem=Ecosystem.MAVEN)
    return [dep], ScanResult(vulns={key(dep): [vuln]})


def log4shell(aliases=("CVE-2021-44228",)):
    return Vuln("GHSA-jfh8-c2jp-5v3q", "Log4Shell", aliases, Severity.CRITICAL, (), {})


def test_kev_finding_scores_full_risk():
    deps, scan = synthetic_scan(log4shell())
    epss, _ = epss_client()
    finding = enrich(uuid4(), deps, scan, epss, kev_client()).findings[0]
    assert finding.in_kev
    assert finding.risk_score == 100


def test_vuln_without_a_cve_is_unscored_and_still_listed():
    deps, scan = synthetic_scan(log4shell(aliases=()))
    epss, seen = epss_client()
    result = enrich(uuid4(), deps, scan, epss, kev_client())
    assert result.findings[0].risk_score is None
    assert result.findings[0].epss is None
    assert seen == []


def test_highest_epss_wins_when_a_bug_has_several_cves():
    deps, scan = synthetic_scan(log4shell(aliases=("CVE-2024-22195", "CVE-2019-10906")))
    epss, _ = epss_client()
    finding = enrich(uuid4(), deps, scan, epss, kev_client()).findings[0]
    assert finding.epss == pytest.approx(0.03534)


def test_kev_outage_marks_the_result_incomplete_not_clean():
    deps, scan = synthetic_scan(log4shell())
    epss, _ = epss_client()
    result = enrich(uuid4(), deps, scan, epss, kev_client(lambda r: httpx.Response(503)))
    assert not result.kev_available
    assert not result.complete
    finding = result.findings[0]
    assert not finding.in_kev
    assert finding.risk_score == pytest.approx(99.999)  # falls back to EPSS alone


def test_epss_outage_leaves_findings_unscored_and_result_incomplete():
    deps, scan = scan_recorded()
    epss, _ = epss_client(lambda r: httpx.Response(503), max_retries=0)
    result = enrich(uuid4(), deps, scan, epss, kev_client())
    assert not result.complete
    assert result.epss_failed
    assert all(f.risk_score is None for f in result.findings)


def test_osv_failures_carry_through_as_unchecked():
    deps = [JINJA2]
    scan = ScanResult(failed=[JINJA2])
    epss, _ = epss_client()
    result = enrich(uuid4(), deps, scan, epss, kev_client())
    assert result.unchecked == [JINJA2]
    assert result.findings == []
    assert not result.complete


def test_osv_alias_with_a_dot_does_not_break_the_finding():
    deps, scan = synthetic_scan(log4shell(aliases=("CVE-2021-44228", "RHSA-2021:5132.1")))
    epss, _ = epss_client()
    finding = enrich(uuid4(), deps, scan, epss, kev_client()).findings[0]
    assert "RHSA-2021:5132.1" in finding.aliases
