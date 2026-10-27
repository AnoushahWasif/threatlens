from uuid import uuid4

import pytest
from pydantic import ValidationError

from threatlens_api.models import Dependency, Ecosystem, Finding, ProjectCreate


def dep(**overrides):
    return Dependency(**{"name": "requests", "version": "2.31.0", "ecosystem": "PyPI", **overrides})


@pytest.mark.parametrize(
    ("name", "ecosystem"),
    [
        ("@angular/core", "npm"),
        ("org.apache.logging.log4j:log4j-core", "Maven"),
        ("github.com/gin-gonic/gin", "Go"),
        ("serde_json", "crates.io"),
        ("Newtonsoft.Json", "NuGet"),
    ],
)
def test_real_package_names_accepted(name, ecosystem):
    assert dep(name=name, ecosystem=ecosystem).name == name


@pytest.mark.parametrize("name", ["", " ", "../../etc/passwd", "pkg name", "pkg;rm -rf", "a" * 215])
def test_bad_package_names_rejected(name):
    with pytest.raises(ValidationError):
        dep(name=name)


@pytest.mark.parametrize("version", ["1.0.0", "2.0.0-rc.1", "1.2.3+build.5", "1:2.3-4", "^1.2"])
def test_real_versions_accepted(version):
    assert dep(version=version).version == version


@pytest.mark.parametrize("version", ["", "1.0 beta", "$(whoami)", "1" * 129])
def test_bad_versions_rejected(version):
    with pytest.raises(ValidationError):
        dep(version=version)


def test_unknown_ecosystem_rejected():
    with pytest.raises(ValidationError):
        dep(ecosystem="pip")


def test_ecosystem_values_match_osv():
    assert {e.value for e in Ecosystem} >= {"PyPI", "npm", "Maven", "Go", "crates.io", "NuGet"}


def test_whitespace_is_stripped():
    assert ProjectCreate(name="  my app  ").name == "my app"


def test_extra_fields_rejected():
    with pytest.raises(ValidationError):
        ProjectCreate(name="x", owner_id="someone-else")


def finding(**overrides):
    values = {"project_id": uuid4(), "dependency": dep(), "vuln_id": "GHSA-j8r2-6x86-q33q"}
    return Finding(**{"risk_score": 10, **values, **overrides})


@pytest.mark.parametrize("vuln_id", ["CVE-2021-44228", "GHSA-j8r2-6x86-q33q", "PYSEC-2023-74"])
def test_vuln_ids_accepted(vuln_id):
    assert finding(vuln_id=vuln_id).vuln_id == vuln_id


@pytest.mark.parametrize("vuln_id", ["cve-2021-44228", "2021-44228", "CVE", "<b>CVE-1</b>"])
def test_bad_vuln_ids_rejected(vuln_id):
    with pytest.raises(ValidationError):
        finding(vuln_id=vuln_id)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("cvss_score", 10.1),
        ("cvss_score", -1),
        ("epss", 1.5),
        ("risk_score", 101),
        ("risk_score", -1),
    ],
)
def test_score_bounds(field, value):
    with pytest.raises(ValidationError):
        finding(**{field: value})


def test_finding_defaults():
    f = finding()
    assert f.severity == "unknown"
    assert f.in_kev is False
    assert f.aliases == []
