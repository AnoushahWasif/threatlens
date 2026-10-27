import json

import pytest

from threatlens_api import ingest
from threatlens_api.ingest import IngestError, parse, parse_purl


def names(result):
    return {(d.name, d.version) for d in result.dependencies}


def reasons(result):
    return {s.reason for s in result.skipped}


# --- requirements.txt ---


def test_requirements_happy_path():
    text = "requests==2.31.0\nDjango==4.2.7\n"
    result = parse("requirements.txt", text.encode())
    assert names(result) == {("requests", "2.31.0"), ("django", "4.2.7")}
    assert result.format == "requirements.txt"


def test_requirements_real_world_noise():
    text = """
    # production deps
    requests[security]==2.31.0  # pinned for CVE-2023-32681
    urllib3 == 2.0.7 ; python_version >= "3.8"
    Flask_Login===0.6.3
    numpy>=1.24
    pandas
    -r base.txt
    --index-url https://pypi.org/simple
    -e .
    git+https://github.com/org/repo.git#egg=thing
    mypkg @ https://example.com/mypkg-1.0.tar.gz
    """
    result = parse("requirements-prod.txt", text.encode())
    assert names(result) == {
        ("requests", "2.31.0"),
        ("urllib3", "2.0.7"),
        ("flask-login", "0.6.3"),
    }
    assert "not pinned to an exact version" in reasons(result)
    assert "pip option or nested file not followed" in reasons(result)
    assert "URL or VCS dependency has no version" in reasons(result)
    assert len(result.skipped) == 7


def test_requirements_duplicates_collapse():
    result = parse("requirements.txt", b"Requests==2.31.0\nrequests==2.31.0\n")
    assert len(result.dependencies) == 1


def test_requirements_handles_bom_and_crlf():
    result = parse("requirements.txt", "﻿requests==2.31.0\r\nflask==3.0.0\r\n".encode())
    assert names(result) == {("requests", "2.31.0"), ("flask", "3.0.0")}


def test_injection_like_version_is_skipped_not_accepted():
    result = parse("requirements.txt", b"requests==2.31.0$(whoami)\n")
    assert result.dependencies == []
    assert result.skipped


# --- package-lock.json ---


def lock_v3():
    return {
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/@angular/core": {"version": "16.2.0"},
            "node_modules/express/node_modules/debug": {"version": "2.6.9"},
            "node_modules/local-lib": {"link": True, "resolved": "../local-lib"},
            "node_modules/broken": {},
        },
    }


def test_package_lock_v3():
    result = parse("package-lock.json", json.dumps(lock_v3()).encode())
    assert names(result) == {("express", "4.18.2"), ("@angular/core", "16.2.0"), ("debug", "2.6.9")}
    direct = {d.name: d.direct for d in result.dependencies}
    assert direct == {"express": True, "@angular/core": True, "debug": False}
    assert reasons(result) == {"local symlinked package", "no version in lockfile"}


def test_package_lock_v1_nested():
    data = {
        "lockfileVersion": 1,
        "dependencies": {
            "lodash": {"version": "4.17.20"},
            "a": {"version": "1.0.0", "dependencies": {"minimist": {"version": "0.0.8"}}},
            "mine": {"version": "file:../mine"},
        },
    }
    result = parse("package-lock.json", json.dumps(data).encode())
    assert names(result) == {("lodash", "4.17.20"), ("a", "1.0.0"), ("minimist", "0.0.8")}
    assert {d.name: d.direct for d in result.dependencies}["minimist"] is False
    assert "no registry version in lockfile" in reasons(result)


def test_package_lock_without_sections_is_an_error():
    with pytest.raises(IngestError, match="no packages or dependencies"):
        parse("package-lock.json", b'{"name": "x"}')


def test_package_lock_not_an_object():
    with pytest.raises(IngestError, match="JSON object"):
        parse("package-lock.json", b"[1, 2, 3]")


# --- CycloneDX ---


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        ("pkg:pypi/Requests@2.31.0", ("PyPI", "requests", "2.31.0")),
        ("pkg:npm/%40angular/core@16.2.0", ("npm", "@angular/core", "16.2.0")),
        (
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar",
            ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
        ),
        (
            "pkg:golang/github.com/gin-gonic/gin@v1.9.0",
            ("Go", "github.com/gin-gonic/gin", "v1.9.0"),
        ),
        ("pkg:cargo/serde@1.0.188", ("crates.io", "serde", "1.0.188")),
        ("pkg:nuget/Newtonsoft.Json@13.0.1", ("NuGet", "Newtonsoft.Json", "13.0.1")),
    ],
)
def test_parse_purl(purl, expected):
    ecosystem, name, version = parse_purl(purl)
    assert (ecosystem.value, name, version) == expected


@pytest.mark.parametrize(
    "purl", ["pkg:deb/debian/curl@7.0", "pkg:pypi/requests", "not-a-purl", "pkg:npm@1.0"]
)
def test_unsupported_purls(purl):
    assert parse_purl(purl) is None


def test_cyclonedx_with_nested_components():
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"name": "requests", "purl": "pkg:pypi/requests@2.31.0"},
            {
                "name": "framework",
                "purl": "pkg:npm/express@4.18.2",
                "components": [{"name": "debug", "purl": "pkg:npm/debug@2.6.9"}],
            },
            {"name": "openssl", "purl": "pkg:deb/debian/openssl@3.0.11"},
            {"name": "no-purl-lib", "version": "1.0"},
        ],
    }
    result = parse("bom.json", json.dumps(sbom).encode())
    assert names(result) == {("requests", "2.31.0"), ("express", "4.18.2"), ("debug", "2.6.9")}
    assert reasons(result) == {"no supported package URL (purl)"}
    assert len(result.skipped) == 2


def test_json_that_is_not_cyclonedx_is_rejected():
    with pytest.raises(IngestError, match="Unsupported file"):
        parse("data.json", b'{"hello": "world"}')


# --- hostile and broken input ---


def test_unsupported_filename():
    with pytest.raises(IngestError, match="Unsupported file"):
        parse("Gemfile.lock", b"GEM\n")


def test_too_large():
    with pytest.raises(IngestError, match="larger than"):
        parse("requirements.txt", b"a" * (ingest.MAX_BYTES + 1))


def test_not_utf8():
    with pytest.raises(IngestError, match="UTF-8"):
        parse("requirements.txt", b"\xff\xfe\x00bad")


def test_invalid_json_reports_line():
    with pytest.raises(IngestError, match="line 2"):
        parse("package-lock.json", b'{\n "packages": ,\n}')


def test_deeply_nested_json():
    payload = b"[" * 100_000 + b"]" * 100_000
    with pytest.raises(IngestError, match="nested too deeply"):
        parse("package-lock.json", payload)


def test_dependency_cap(monkeypatch):
    monkeypatch.setattr(ingest, "MAX_DEPENDENCIES", 3)
    text = "\n".join(f"pkg{i}==1.0.0" for i in range(5))
    with pytest.raises(IngestError, match="More than 3"):
        parse("requirements.txt", text.encode())


def test_long_skipped_refs_are_truncated():
    result = parse("requirements.txt", ("x" * 500 + ">=1").encode())
    assert len(result.skipped[0].ref) <= 120


def test_path_in_filename_is_ignored():
    result = parse("uploads/../../requirements.txt", b"requests==2.31.0\n")
    assert len(result.dependencies) == 1
