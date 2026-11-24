import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "check_own_sbom.py"
spec = importlib.util.spec_from_file_location("check_own_sbom", SCRIPT)
check_own_sbom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_own_sbom)


def sbom(*components) -> bytes:
    return json.dumps({"bomFormat": "CycloneDX", "components": list(components)}).encode()


LOCKFILE = {"type": "application", "name": "apps/api/uv.lock"}
FASTAPI = {"type": "library", "name": "fastapi", "purl": "pkg:pypi/fastapi@0.115.0"}
NEXT = {"type": "library", "name": "@next/env", "purl": "pkg:npm/%40next/env@16.4.3"}


def test_both_ecosystems_and_lockfile_components_pass():
    found, counts = check_own_sbom.problems("own.cdx.json", sbom(LOCKFILE, FASTAPI, NEXT))
    assert found == []
    assert counts == {"PyPI": 1, "npm": 1}


def test_missing_ecosystem_fails():
    found, _ = check_own_sbom.problems("own.cdx.json", sbom(FASTAPI))
    assert found == ["no npm packages"]


def test_skipped_package_fails():
    bad = {"type": "library", "name": "x", "purl": "pkg:npm/x@"}
    found, _ = check_own_sbom.problems("own.cdx.json", sbom(FASTAPI, NEXT, bad))
    assert found == ["skipped pkg:npm/x@: no supported package URL (purl)"]


def test_file_the_parser_refuses_fails():
    found, counts = check_own_sbom.problems("own.cdx.json", b"{not json")
    assert found == ["the parser refused the file: Invalid JSON at line 1"]
    assert not counts


def test_main_exits_with_the_problems(tmp_path, capsys):
    path = tmp_path / "own.cdx.json"
    path.write_bytes(sbom(FASTAPI))
    with pytest.raises(SystemExit, match="no npm packages"):
        check_own_sbom.main(["check_own_sbom.py", str(path)])
    assert "PyPI packages: 1" in capsys.readouterr().out


def test_main_passes_quietly_on_a_good_file(tmp_path, capsys):
    path = tmp_path / "own.cdx.json"
    path.write_bytes(sbom(FASTAPI, NEXT))
    check_own_sbom.main(["check_own_sbom.py", str(path)])
    assert capsys.readouterr().out == "PyPI packages: 1\nnpm packages: 1\n"


def test_a_component_without_a_purl_that_isnt_a_lockfile_fails():
    library = {"type": "library", "name": "mystery"}
    found, _ = check_own_sbom.problems("own.cdx.json", sbom(LOCKFILE, FASTAPI, NEXT, library))
    assert found == ["skipped mystery: no supported package URL (purl)"]


def test_a_nested_lockfile_component_is_still_fine():
    outer = {"type": "application", "name": "repo", "components": [LOCKFILE]}
    found, _ = check_own_sbom.problems("own.cdx.json", sbom(outer, FASTAPI, NEXT))
    assert found == []


def test_an_application_with_a_purl_that_gets_skipped_fails():
    odd = {"type": "application", "name": "tool", "purl": "pkg:npm/tool@"}
    found, _ = check_own_sbom.problems("own.cdx.json", sbom(FASTAPI, NEXT, odd))
    assert found == ["skipped pkg:npm/tool@: no supported package URL (purl)"]


@pytest.mark.parametrize(
    "dev",
    [
        {"type": "library", "name": "pytest", "purl": "pkg:pypi/pytest@8.3.0"},
        {"type": "library", "name": "vitest", "purl": "pkg:npm/vitest@3.2.0"},
    ],
)
def test_a_dev_only_tool_in_the_shipped_sbom_fails(dev):
    found, _ = check_own_sbom.problems("own.cdx.json", sbom(FASTAPI, NEXT, dev))
    assert found == [f"dev-only package {dev['name']}"]
