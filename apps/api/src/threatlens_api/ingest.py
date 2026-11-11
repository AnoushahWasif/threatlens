"""Turn an uploaded SBOM or lockfile into a list of exact package versions.

Only exact versions are useful: OSV answers "is version X affected", not "is >=2.0".
Anything that can't be resolved to one is returned in `skipped` with a reason, so the
UI can tell the user what wasn't checked instead of silently dropping it.
"""

import json
import re
import tomllib
from dataclasses import dataclass, field
from urllib.parse import unquote

import yaml
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
    if name == "uv.lock":
        return parse_uv_lock(_load_toml(text))
    if name == "poetry.lock":
        return parse_poetry_lock(_load_toml(text))
    if name == "pnpm-lock.yaml":
        return parse_pnpm_lock(_load_yaml(text))
    if name.endswith(".json"):
        data = _load_json(text)
        if isinstance(data, dict) and data.get("bomFormat") == "CycloneDX":
            return parse_cyclonedx(data)
    raise IngestError(
        "Unsupported file. Upload a CycloneDX JSON SBOM, requirements.txt, package-lock.json, "
        "pnpm-lock.yaml, uv.lock or poetry.lock"
    )


def _load_json(text: str):
    try:
        return json.loads(text)
    except RecursionError as exc:  # absurdly deep nesting, e.g. [[[[...]]]]
        raise IngestError("JSON is nested too deeply") from exc
    except json.JSONDecodeError as exc:
        raise IngestError(f"Invalid JSON at line {exc.lineno}") from exc


def _load_toml(text: str) -> dict:
    try:
        return tomllib.loads(text)
    except RecursionError as exc:
        raise IngestError("TOML is nested too deeply") from exc
    except tomllib.TOMLDecodeError as exc:
        raise IngestError("Invalid TOML") from exc


class _NoAliasLoader(yaml.SafeLoader):
    # pnpm never writes anchors or aliases. Allowing them lets a few hundred bytes of
    # "<<: [*m, *m, ...]" merge keys copy pairs exponentially (107 s for 582 bytes).
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise IngestError("YAML aliases (*name) are not allowed in a lockfile")
        return super().compose_node(parent, index)


def _load_yaml(text: str):
    # Safe loader only: no Python objects, and no aliases (see _NoAliasLoader).
    # The pure-Python loader, not the 5x faster libyaml one: deep nesting (200 KB of "[",
    # or 3,000 levels of indents) overflows libyaml's C stack and kills the whole process,
    # where the Python one raises RecursionError.
    try:
        return yaml.load(text, Loader=_NoAliasLoader)  # noqa: S506 - a safe loader
    except RecursionError as exc:
        raise IngestError("YAML is nested too deeply") from exc
    except yaml.YAMLError as exc:
        raise IngestError("Invalid YAML") from exc


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


# --- uv.lock and poetry.lock ----------------------------------------------------------


def _toml_packages(data: dict, fmt: str) -> list[dict]:
    packages = data.get("package", [])
    if not isinstance(packages, list):
        raise IngestError(f"{fmt} has no [[package]] list")
    return [p for p in packages if isinstance(p, dict)]


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


NOT_INDEXED = "not from a package index (git, path or URL)"


def parse_uv_lock(data: dict) -> IngestResult:
    result = IngestResult(format="uv.lock")
    packages = _toml_packages(data, "uv.lock")
    # The project itself (and any workspace members) are editable or virtual; whatever they
    # list, in any group, is a direct dependency.
    members = [p for p in packages if {"editable", "virtual"} & _dict(p.get("source")).keys()]
    direct = set()  # a name, or (name, version) when the lockfile names the version
    for member in members:
        groups = [member.get("dependencies")]
        groups += list(_dict(member.get("optional-dependencies")).values())
        groups += list(_dict(member.get("dev-dependencies")).values())
        for group in groups:
            for dep in group if isinstance(group, list) else []:
                if isinstance(dep, dict) and isinstance(dep.get("name"), str):
                    name = pypi_name(dep["name"])
                    ver = dep.get("version")
                    direct.add((name, ver) if isinstance(ver, str) else name)

    for pkg in packages:
        if any(pkg is m for m in members):
            continue
        name, version = pkg.get("name"), pkg.get("version")
        if not isinstance(name, str):
            result.skipped.append(Skipped("[[package]]", "no package name"))
            continue
        if "registry" not in _dict(pkg.get("source")):
            result.skipped.append(Skipped(_short(name), NOT_INDEXED))
            continue
        if not isinstance(version, str):
            result.skipped.append(Skipped(_short(name), "no version in lockfile"))
            continue
        name = pypi_name(name)
        is_direct = name in direct or (name, version) in direct
        result.add(name, version, Ecosystem.PYPI, is_direct, pkg["name"])
    return result


def parse_poetry_lock(data: dict) -> IngestResult:
    result = IngestResult(format="poetry.lock")
    for pkg in _toml_packages(data, "poetry.lock"):
        name, version = pkg.get("name"), pkg.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            result.skipped.append(Skipped(_short(str(name)), "no name or version in lockfile"))
            continue
        # No source table means PyPI; "legacy" is another package index. Git, directory,
        # file and URL sources have no index version for OSV to look up.
        source = pkg.get("source")
        if isinstance(source, dict) and source.get("type") not in (None, "legacy"):
            result.skipped.append(Skipped(_short(name), NOT_INDEXED))
            continue
        # poetry.lock doesn't say which packages are direct (pyproject.toml does), so as
        # with a CycloneDX file that has no graph, every package counts as direct.
        result.add(pypi_name(name), version, Ecosystem.PYPI, True, name)
    return result


# --- pnpm-lock.yaml -------------------------------------------------------------------


def _without_peers(version: str) -> str:
    # pnpm writes peer dependencies after the version: 16.4.3(react@19.3.0)(...)
    return version.split("(", 1)[0]


def parse_pnpm_lock(data) -> IngestResult:
    if not isinstance(data, dict):
        raise IngestError("pnpm-lock.yaml must be a YAML mapping")
    version = str(data.get("lockfileVersion", ""))
    if version.split(".")[0] not in ("6", "9"):
        raise IngestError("Only pnpm lockfile versions 6 and 9 are supported (pnpm 8 and later)")
    result = IngestResult(format="pnpm-lock.yaml")

    # A workspace lists each project under importers; a single project lists its own
    # dependencies at the top level.
    importers = data.get("importers")
    projects = list(_dict(importers).values()) if importers is not None else [data]
    direct = set()
    for project in projects:
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, info in _dict(_dict(project).get(section)).items():
                ver = info.get("version") if isinstance(info, dict) else info
                if not isinstance(name, str) or not isinstance(ver, str):
                    continue
                ver = _without_peers(ver).removeprefix("/")
                # An npm alias ("string-width-cjs": npm:string-width@4) records the real
                # package as its version: string-width@4.2.3 (v6: /string-width@4.2.3).
                if "@" in ver:
                    name, _, ver = ver.rpartition("@")
                direct.add((name, ver))

    packages = data.get("packages")
    if packages is None:
        return result  # nothing installed
    if not isinstance(packages, dict):
        raise IngestError("pnpm-lock.yaml packages must be a mapping")
    for key in packages:
        if not isinstance(key, str):
            continue
        # v6 writes registry packages as /name@version, and git or tarball ones as a host
        # path like github.com/owner/repo/sha.
        if version.startswith("6") and not key.startswith("/"):
            result.skipped.append(Skipped(_short(key), "not from the npm registry"))
            continue
        spec = _without_peers(key.removeprefix("/"))
        name, sep, ver = spec.rpartition("@")
        if not sep or not name or not ver:
            result.skipped.append(Skipped(_short(key), "could not read package name and version"))
            continue
        if ":" in ver or "/" in ver:  # file:, link:, git and tarball URLs
            result.skipped.append(Skipped(_short(key), "not from the npm registry"))
            continue
        result.add(name, ver, Ecosystem.NPM, (name, ver) in direct, key)
    return result


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
