"""Turn an uploaded SBOM or lockfile into a list of exact package versions.

Only exact versions are useful: OSV answers "is version X affected", not "is >=2.0".
Anything that can't be resolved to one is returned in `skipped` with a reason, so the
UI can tell the user what wasn't checked instead of silently dropping it.
"""

import json
import re
from dataclasses import dataclass, field
from urllib.parse import unquote

from pydantic import ValidationError

from threatlens_api.models import Dependency, Ecosystem

MAX_BYTES = 5_000_000
MAX_DEPENDENCIES = 20_000


class IngestError(ValueError):
    """The file can't be read at all. Shown to the user as-is, so keep messages safe."""


@dataclass
class Skipped:
    ref: str
    reason: str


@dataclass
class IngestResult:
    format: str
    dependencies: list[Dependency] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)
    _seen: set[tuple] = field(default_factory=set, repr=False)

    def add(self, name: str, version: str, ecosystem: Ecosystem, direct: bool, ref: str) -> None:
        try:
            dep = Dependency(name=name, version=version, ecosystem=ecosystem, direct=direct)
        except ValidationError:
            self.skipped.append(Skipped(_short(ref), "invalid package name or version"))
            return
        key = (dep.ecosystem, dep.name, dep.version)
        if key in self._seen:
            return
        if len(self.dependencies) >= MAX_DEPENDENCIES:
            raise IngestError(f"More than {MAX_DEPENDENCIES} dependencies")
        self._seen.add(key)
        self.dependencies.append(dep)


def _short(text: str, limit: int = 120) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def parse(filename: str, content: bytes) -> IngestResult:
    if len(content) > MAX_BYTES:
        raise IngestError(f"File is larger than {MAX_BYTES // 1_000_000} MB")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IngestError("File is not valid UTF-8 text") from exc

    name = filename.rsplit("/", 1)[-1].lower()
    if name.endswith(".txt") and "requirements" in name:
        return parse_requirements(text)
    if name == "package-lock.json":
        return parse_package_lock(_load_json(text))
    if name.endswith(".json"):
        data = _load_json(text)
        if isinstance(data, dict) and data.get("bomFormat") == "CycloneDX":
            return parse_cyclonedx(data)
    raise IngestError(
        "Unsupported file. Upload a CycloneDX JSON SBOM, requirements.txt or package-lock.json"
    )


def _load_json(text: str):
    try:
        return json.loads(text)
    except RecursionError as exc:  # absurdly deep nesting, e.g. [[[[...]]]]
        raise IngestError("JSON is nested too deeply") from exc
    except json.JSONDecodeError as exc:
        raise IngestError(f"Invalid JSON at line {exc.lineno}") from exc


# --- requirements.txt ---------------------------------------------------------------

_REQ_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[[^\]]*\])?"  # extras: requests[security]
    r"\s*(?P<spec>[^;#]*)"
)
_PINNED = re.compile(r"^===?\s*(?P<version>[A-Za-z0-9._+!-]+)$")


def pypi_name(name: str) -> str:
    # PEP 503: Django, django and dJango-REST_framework all mean the same project.
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(text: str) -> IngestResult:
    result = IngestResult(format="requirements.txt")
    for raw in text.splitlines():
        line = re.sub(r"\s+#.*$", "", raw).strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            result.skipped.append(Skipped(_short(line), "pip option or nested file not followed"))
            continue
        if "://" in line or line.startswith("git+") or " @ " in line:
            result.skipped.append(Skipped(_short(line), "URL or VCS dependency has no version"))
            continue
        match = _REQ_LINE.match(line)
        if not match:
            result.skipped.append(Skipped(_short(line), "could not parse line"))
            continue
        pinned = _PINNED.match(match["spec"].strip())
        if not pinned:
            result.skipped.append(Skipped(_short(line), "not pinned to an exact version"))
            continue
        result.add(pypi_name(match["name"]), pinned["version"], Ecosystem.PYPI, True, line)
    return result


# --- package-lock.json --------------------------------------------------------------


def parse_package_lock(data) -> IngestResult:
    if not isinstance(data, dict):
        raise IngestError("package-lock.json must be a JSON object")
    result = IngestResult(format="package-lock.json")

    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2 and 3
        for path, info in packages.items():
            if not path or not isinstance(info, dict):
                continue  # "" is the root project itself
            if info.get("link"):
                result.skipped.append(Skipped(path, "local symlinked package"))
                continue
            name = info.get("name") or path.rsplit("node_modules/", 1)[-1]
            version = info.get("version")
            if not isinstance(version, str):
                result.skipped.append(Skipped(path, "no version in lockfile"))
                continue
            direct = path.count("node_modules/") == 1
            result.add(name, version, Ecosystem.NPM, direct, path)
        return result

    deps = data.get("dependencies")
    if isinstance(deps, dict):  # lockfileVersion 1: nested tree
        _walk_v1(deps, result, depth=0)
        return result
    raise IngestError("package-lock.json has no packages or dependencies section")


def _walk_v1(deps: dict, result: IngestResult, depth: int) -> None:
    for name, info in deps.items():
        if not isinstance(info, dict):
            continue
        version = info.get("version")
        if isinstance(version, str) and not version.startswith(("file:", "link:", "git")):
            result.add(name, version, Ecosystem.NPM, depth == 0, name)
        else:
            result.skipped.append(Skipped(name, "no registry version in lockfile"))
        nested = info.get("dependencies")
        if isinstance(nested, dict):
            _walk_v1(nested, result, depth + 1)


# --- CycloneDX ----------------------------------------------------------------------

_PURL_TYPES = {
    "pypi": Ecosystem.PYPI,
    "npm": Ecosystem.NPM,
    "maven": Ecosystem.MAVEN,
    "golang": Ecosystem.GO,
    "cargo": Ecosystem.CARGO,
    "nuget": Ecosystem.NUGET,
}


def parse_purl(purl: str) -> tuple[Ecosystem, str, str] | None:
    """pkg:type/namespace/name@version?qualifiers#subpath -> (ecosystem, name, version)."""
    if not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    if "/" not in body or "@" not in body:
        return None
    purl_type, rest = body.split("/", 1)
    path, version = rest.rsplit("@", 1)
    ecosystem = _PURL_TYPES.get(purl_type.lower())
    if ecosystem is None or not version:
        return None
    parts = [unquote(p) for p in path.split("/")]
    if ecosystem is Ecosystem.MAVEN:
        name = ":".join(parts)  # group/artifact -> group:artifact, as OSV expects
    elif ecosystem is Ecosystem.PYPI:
        name = pypi_name(parts[-1])
    else:
        name = "/".join(parts)  # keeps @scope/pkg and Go module paths whole
    return ecosystem, name, unquote(version)


def parse_cyclonedx(data: dict) -> IngestResult:
    result = IngestResult(format="CycloneDX")
    components = data.get("components") or []
    if not isinstance(components, list):
        raise IngestError("CycloneDX components must be a list")

    # Walk nested components without recursion, so a hostile file can't blow the stack.
    stack = list(components)
    while stack:
        comp = stack.pop()
        if not isinstance(comp, dict):
            continue
        stack.extend(c for c in comp.get("components") or [] if isinstance(c, dict))
        ref = str(comp.get("purl") or comp.get("name") or "component")
        parsed = parse_purl(comp["purl"]) if isinstance(comp.get("purl"), str) else None
        if parsed is None:
            result.skipped.append(Skipped(_short(ref), "no supported package URL (purl)"))
            continue
        ecosystem, name, version = parsed
        result.add(name, version, ecosystem, True, ref)
    return result
