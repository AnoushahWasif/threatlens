"""Runs ThreatLens's own parser on the SBOM that CI makes of ThreatLens (CI only).

Fails if anything other than a lockfile entry gets skipped, if either ecosystem is
missing, or if a dev-only tool is in it (the SBOM is meant to list what ships), so a
change in Trivy's output or in our parser shows up here before a user's upload does.

Usage: uv run python scripts/check_own_sbom.py threatlens.cdx.json
"""

import json
import sys
from collections import Counter
from pathlib import Path

from threatlens_api.ingest import IngestError, parse
from threatlens_api.models import Ecosystem

WANTED = {"pkg:pypi/": Ecosystem.PYPI, "pkg:npm/": Ecosystem.NPM}
# Direct dev dependencies that never ship; one of them here means dev tools got in.
DEV_ONLY = {"pytest", "ruff", "moto", "vitest", "eslint", "jsdom"}


def _lockfile_refs(content: bytes) -> set[str]:
    """Trivy lists each lockfile as an "application" component without a purl."""
    stack, refs = list(json.loads(content).get("components") or []), set()
    while stack:
        comp = stack.pop()
        if isinstance(comp, dict):
            stack.extend(comp.get("components") or [])
            if comp.get("type") == "application" and not comp.get("purl"):
                refs.add(str(comp.get("name")))
    return refs


def problems(filename: str, content: bytes) -> tuple[list[str], Counter]:
    try:
        result = parse(filename, content)
    except IngestError as exc:
        return [f"the parser refused the file: {exc}"], Counter()
    counts = Counter(dep.ecosystem for dep in result.dependencies)
    found = [f"no {eco.value} packages" for eco in WANTED.values() if not counts[eco]]
    lockfiles = _lockfile_refs(content)
    found += [f"skipped {s.ref}: {s.reason}" for s in result.skipped if s.ref not in lockfiles]
    found += sorted(f"dev-only package {d.name}" for d in result.dependencies if d.name in DEV_ONLY)
    return found, counts


def main(argv: list[str]) -> None:
    if len(argv) != 2:
        raise SystemExit("usage: check_own_sbom.py <cyclonedx.json>")
    path = Path(argv[1])
    found, counts = problems(path.name, path.read_bytes())
    for eco, n in sorted(counts.items()):
        print(f"{eco.value} packages: {n}")
    if found:
        raise SystemExit("own SBOM check failed:\n" + "\n".join(found))


if __name__ == "__main__":
    main(sys.argv)
