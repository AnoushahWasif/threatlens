"""Runs ThreatLens's own parser on the SBOM that CI makes of ThreatLens (CI only).

Fails if a PyPI or npm package in the SBOM gets skipped, or if either ecosystem is
missing, so a change in Trivy's output or in our parser shows up here before a user's
upload does.

Usage: uv run python scripts/check_own_sbom.py threatlens.cdx.json
"""

import sys
from collections import Counter
from pathlib import Path

from threatlens_api.ingest import IngestError, parse
from threatlens_api.models import Ecosystem

WANTED = {"pkg:pypi/": Ecosystem.PYPI, "pkg:npm/": Ecosystem.NPM}


def problems(filename: str, content: bytes) -> tuple[list[str], Counter]:
    try:
        result = parse(filename, content)
    except IngestError as exc:
        return [f"the parser refused the file: {exc}"], Counter()
    counts = Counter(dep.ecosystem for dep in result.dependencies)
    found = [f"no {eco.value} packages" for eco in WANTED.values() if not counts[eco]]
    # Trivy also lists each lockfile as a component without a purl; those skips are fine.
    found += [
        f"skipped {s.ref}: {s.reason}" for s in result.skipped if s.ref.startswith(tuple(WANTED))
    ]
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
