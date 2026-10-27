"""Look up known vulnerabilities for exact package versions on OSV.dev.

Two calls: /v1/querybatch returns only vuln ids per package, then /v1/vulns/{id} returns
the details. Both are cached, because the same packages come up scan after scan.

OSV is an outside service, so everything it returns is treated as untrusted input:
ids are checked before they go into a URL, responses are size-limited and validated,
and a failure marks the affected dependencies as "not checked" instead of "clean".
"""

import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from threatlens_api import __version__
from threatlens_api.models import Dependency, Ecosystem, Severity

BASE_URL = "https://api.osv.dev"
BATCH_SIZE = 1000  # OSV's own limit per querybatch call
MAX_PAGES = 10
MAX_RESPONSE_BYTES = 10_000_000
MAX_RETRY_AFTER = 30.0
RETRY_STATUSES = {429, 500, 502, 503, 504}

VULN_ID = re.compile(r"^[A-Z][A-Z0-9]*-[A-Za-z0-9\-:.]{1,60}$")
VERSION = re.compile(r"^[A-Za-z0-9._\-+~^:]{1,128}$")
GHSA_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

DepKey = tuple[Ecosystem, str, str]


class OsvError(Exception):
    pass


# --- OSV response shapes. Unknown fields are ignored: OSV adds fields over time.


class _Loose(BaseModel):
    model_config = ConfigDict(extra="ignore")


class _IdRef(_Loose):
    id: str


class _BatchResult(_Loose):
    vulns: list[_IdRef] = []
    next_page_token: str | None = None


class _BatchResponse(_Loose):
    results: list[_BatchResult]


class _Package(_Loose):
    name: str
    ecosystem: str


class _Range(_Loose):
    events: list[dict[str, str]] = []


class _Affected(_Loose):
    package: _Package | None = None
    ranges: list[_Range] = []


class _Severity(_Loose):
    type: str
    score: str


class _Vuln(_Loose):
    id: str
    summary: str = ""
    aliases: list[str] = []
    severity: list[_Severity] = []
    affected: list[_Affected] = []
    database_specific: dict = {}


@dataclass(frozen=True)
class Vuln:
    id: str
    summary: str
    aliases: tuple[str, ...]
    severity: Severity
    cvss_vectors: tuple[str, ...]
    fixed: dict[tuple[str, str], tuple[str, ...]]  # (ecosystem, name) -> fixed versions

    def fixed_versions(self, dep: Dependency) -> list[str]:
        return list(self.fixed.get((dep.ecosystem.value, dep.name.lower()), ()))

    @classmethod
    def from_osv(cls, raw: _Vuln) -> "Vuln":
        fixed: dict[tuple[str, str], list[str]] = {}
        for aff in raw.affected:
            if aff.package is None:
                continue
            # Lower-case on both sides: we only compare names here, never look them up.
            key = (aff.package.ecosystem, aff.package.name.lower())
            for rng in aff.ranges:
                for event in rng.events:
                    version = event.get("fixed", "")
                    if VERSION.match(version) and version not in fixed.setdefault(key, []):
                        fixed[key].append(version)
        label = str(raw.database_specific.get("severity", "")).upper()
        return cls(
            id=raw.id,
            summary=raw.summary[:1000],
            aliases=tuple(a for a in raw.aliases if VULN_ID.match(a))[:50],
            severity=GHSA_SEVERITY.get(label, Severity.UNKNOWN),
            cvss_vectors=tuple(s.score for s in raw.severity if s.type.startswith("CVSS"))[:5],
            fixed={k: tuple(v[:50]) for k, v in fixed.items()},
        )


class TTLCache:
    """Small in-memory cache with expiry and a size cap. DynamoDB with a TTL replaces it on AWS."""

    def __init__(self, ttl: float, max_items: int = 50_000, clock: Callable[[], float] = time.time):
        self.ttl, self.max_items, self.clock = ttl, max_items, clock
        self._data: dict = {}

    def get(self, key):
        hit = self._data.get(key)
        if hit is None:
            return None
        expires, value = hit
        if expires < self.clock():
            del self._data[key]
            return None
        return value

    def set(self, key, value) -> None:
        self._data.pop(key, None)
        if len(self._data) >= self.max_items:
            del self._data[next(iter(self._data))]  # oldest insert goes first
        self._data[key] = (self.clock() + self.ttl, value)

    def __len__(self) -> int:
        return len(self._data)


@dataclass
class ScanResult:
    vulns: dict[DepKey, list[Vuln]] = field(default_factory=dict)
    failed: list[Dependency] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.failed


def default_http() -> httpx.Client:
    return httpx.Client(
        base_url=BASE_URL,
        timeout=httpx.Timeout(10.0, connect=5.0),
        follow_redirects=False,
        headers={"user-agent": f"threatlens/{__version__}"},
    )


def key(dep: Dependency) -> DepKey:
    return (dep.ecosystem, dep.name, dep.version)


class OsvClient:
    def __init__(
        self,
        http: httpx.Client | None = None,
        ids_cache: TTLCache | None = None,
        vuln_cache: TTLCache | None = None,
        max_retries: int = 3,
        backoff: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.http = http or default_http()
        # `is None`, not `or`: an empty cache has len 0 and would be falsy.
        self.ids_cache = TTLCache(ttl=6 * 3600) if ids_cache is None else ids_cache
        self.vuln_cache = TTLCache(ttl=24 * 3600) if vuln_cache is None else vuln_cache
        self.max_retries, self.backoff, self.sleep = max_retries, backoff, sleep

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        reason, delay = "no attempt made", 0.0
        for attempt in range(self.max_retries + 1):
            if attempt:
                self.sleep(delay)
            try:
                resp = self.http.request(method, path, json=body)
            except httpx.TransportError as exc:
                reason = type(exc).__name__
                delay = self.backoff * 2**attempt
                continue
            if resp.status_code in RETRY_STATUSES:
                reason = f"HTTP {resp.status_code}"
                delay = _retry_after(resp) or self.backoff * 2**attempt
                continue
            if resp.status_code != 200:
                raise OsvError(f"OSV returned HTTP {resp.status_code}")
            if len(resp.content) > MAX_RESPONSE_BYTES:
                raise OsvError("OSV response too large")
            try:
                return resp.json()
            except ValueError as exc:
                raise OsvError("OSV response is not JSON") from exc
        raise OsvError(f"OSV unavailable after {self.max_retries + 1} attempts ({reason})")

    def _query_pages(self, query: dict, first: _BatchResult) -> list[str]:
        ids = [v.id for v in first.vulns]
        token, pages = first.next_page_token, 1
        while token:
            if pages >= MAX_PAGES:
                raise OsvError("too many result pages")
            body = {"queries": [{**query, "page_token": token}]}
            results = _BatchResponse.model_validate(
                self._request("POST", "/v1/querybatch", body)
            ).results
            if len(results) != 1:
                raise OsvError("OSV returned the wrong number of results")
            page = results[0]
            ids += [v.id for v in page.vulns]
            token, pages = page.next_page_token, pages + 1
        return ids

    def vuln_ids(self, deps: Iterable[Dependency]) -> tuple[dict[DepKey, list[str]], list]:
        found, failed, todo = {}, [], []
        for dep in deps:
            cached = self.ids_cache.get(key(dep))
            if cached is None:
                todo.append(dep)
            else:
                found[key(dep)] = cached

        for start in range(0, len(todo), BATCH_SIZE):
            chunk = todo[start : start + BATCH_SIZE]
            queries = [
                {"package": {"name": d.name, "ecosystem": d.ecosystem.value}, "version": d.version}
                for d in chunk
            ]
            try:
                batch = _BatchResponse.model_validate(
                    self._request("POST", "/v1/querybatch", {"queries": queries})
                )
                if len(batch.results) != len(chunk):
                    raise OsvError("OSV returned the wrong number of results")
            except (OsvError, ValidationError):
                failed += chunk
                continue
            for dep, query, result in zip(chunk, queries, batch.results, strict=True):
                try:
                    ids = self._query_pages(query, result)
                except (OsvError, ValidationError):
                    failed.append(dep)
                    continue
                found[key(dep)] = ids
                self.ids_cache.set(key(dep), ids)  # empty lists are cached too
        return found, failed

    def vuln(self, vuln_id: str) -> Vuln:
        # The id came from OSV's response, so check it before it becomes part of a URL path.
        if not VULN_ID.match(vuln_id):
            raise OsvError("invalid vulnerability id")
        cached = self.vuln_cache.get(vuln_id)
        if cached is not None:
            return cached
        try:
            raw = _Vuln.model_validate(self._request("GET", f"/v1/vulns/{quote(vuln_id)}"))
        except ValidationError as exc:
            raise OsvError("unexpected vulnerability format") from exc
        if raw.id != vuln_id:
            raise OsvError("OSV returned a different vulnerability than requested")
        vuln = Vuln.from_osv(raw)
        self.vuln_cache.set(vuln_id, vuln)
        return vuln

    def scan(self, deps: list[Dependency]) -> ScanResult:
        ids_by_dep, failed = self.vuln_ids(deps)
        result = ScanResult(failed=failed)
        for dep in deps:
            ids = ids_by_dep.get(key(dep))
            if ids is None:
                continue
            try:
                vulns = [self.vuln(i) for i in ids]
            except OsvError:
                result.failed.append(dep)
                continue
            result.vulns[key(dep)] = merge_aliases(vulns)
        return result


def merge_aliases(vulns: list[Vuln]) -> list[Vuln]:
    """One finding per real bug: GHSA-x and PYSEC-y with the same CVE are the same thing.

    Prefer the record that carries a severity (GHSA usually does, PYSEC doesn't).
    """
    ranked = sorted(vulns, key=lambda v: (v.severity == Severity.UNKNOWN, not v.cvss_vectors, v.id))
    kept, seen = [], set()
    for vuln in ranked:
        names = {vuln.id, *vuln.aliases}
        if names & seen:
            seen |= names
            continue
        seen |= names
        kept.append(vuln)
    return kept


def _retry_after(resp: httpx.Response) -> float | None:
    try:
        return min(float(resp.headers["retry-after"]), MAX_RETRY_AFTER)
    except (KeyError, ValueError):
        return None
