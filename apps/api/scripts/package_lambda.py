"""Builds build/api.zip for Lambda (Python 3.12, x86_64): locked runtime dependencies as
Linux wheels, then our package. Dev dependencies and tests stay out.

    uv run python scripts/package_lambda.py
"""

import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
# Lambda's limit is 250 MB unzipped; stay well under it so a new dependency is noticed.
MAX_UNZIPPED_MB = 150


def run(*args: str) -> str:
    # Fixed arguments, nothing from outside.
    return subprocess.run(args, cwd=ROOT, check=True, capture_output=True, text=True).stdout  # noqa: S603


def main() -> None:
    shutil.rmtree(BUILD, ignore_errors=True)
    package = BUILD / "package"
    package.mkdir(parents=True)
    requirements = BUILD / "requirements.txt"
    # From the lockfile, with hashes, so the zip has exactly what CI tested.
    requirements.write_text(
        run(
            "uv",
            "export",
            "--frozen",
            "--no-dev",
            "--no-emit-project",
            "--format",
            "requirements-txt",
        )
    )
    run(
        "uv",
        "pip",
        "install",
        "--quiet",
        "--target",
        str(package),
        "--python-platform",
        "x86_64-manylinux2014",
        "--python-version",
        "3.12",
        "--only-binary",
        ":all:",
        "-r",
        str(requirements),
    )
    shutil.copytree(ROOT / "src" / "threatlens_api", package / "threatlens_api")
    for cache in package.rglob("__pycache__"):
        shutil.rmtree(cache, ignore_errors=True)

    size = sum(f.stat().st_size for f in package.rglob("*") if f.is_file()) / 1e6
    if size > MAX_UNZIPPED_MB:
        sys.exit(f"Lambda package is {size:.0f} MB unzipped, over the {MAX_UNZIPPED_MB} MB budget")
    with zipfile.ZipFile(BUILD / "api.zip", "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for f in sorted(package.rglob("*")):
            if f.is_file():
                z.write(f, f.relative_to(package))
    zipped = (BUILD / "api.zip").stat().st_size / 1e6
    print(f"build/api.zip: {zipped:.1f} MB zipped, {size:.0f} MB unzipped")


if __name__ == "__main__":
    main()
