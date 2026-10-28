"""Exploit likelihood per CVE from FIRST's EPSS API (https://api.first.org/epss/).

EPSS is the probability that a CVE is exploited in the next 30 days. A CVE EPSS has
never scored is simply missing from the response; that is "no score", not an error.
"""

import math
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from threatlens_api.fetch import FetchError, JsonFetcher, default_http
from threatlens_api.osv import TTLCache

BASE_URL = "https://api.first.org"
PATH = "/data/v1/epss"
# The API returns 100 rows per page and documents a 2000-character limit on `cve`.
MAX_PER_REQUEST = 100
MAX_PARAM_CHARS = 2000
MAX_RESPONSE_BYTES = 1_000_000

CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$")


class EpssError(FetchError):
    pass


@dataclass(frozen=True)
class EpssScore:
    epss: float
    percentile: float
    date: str


_NOT_SCORED = "not scored"  # cached marker: EPSS has no row for this CVE


class _Row(BaseModel):
    model_config = ConfigDict(extra="ignore")

    cve: str
    epss: float
    percentile: float
    date: str = ""

    @field_validator("epss", "percentile")
    @classmethod
    def probability(cls, value: float) -> float:
        # Values arrive as strings ("0.008920000"); NaN and inf parse as floats, so check.
        if not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError("not a probability")
        return value


class _Response(BaseModel):
    model_config = ConfigDict(extra="ignore")

    total: int
    data: list[_Row]


@dataclass
class EpssResult:
    scores: dict[str, EpssScore] = field(default_factory=dict)
    failed: set[str] = field(default_factory=set)


def chunks(cves: list[str]) -> list[list[str]]:
    out, current, length = [], [], 0
    for cve in cves:
        extra = len(cve) + (1 if current else 0)
        if current and (len(current) == MAX_PER_REQUEST or length + extra > MAX_PARAM_CHARS):
            out.append(current)
            current, length, extra = [], 0, len(cve)
        current.append(cve)
        length += extra
    if current:
        out.append(current)
    return out


class EpssClient:
    def __init__(
        self,
        http: httpx.Client | None = None,
        cache: TTLCache | None = None,
        max_retries: int = 3,
        backoff: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.fetch = JsonFetcher(
            http or default_http(BASE_URL), "EPSS", EpssError, max_retries, backoff, sleep
        )
        # EPSS publishes once a day.
        self.cache = TTLCache(ttl=24 * 3600) if cache is None else cache

    def scores(self, cves: Iterable[str]) -> EpssResult:
        result, todo = EpssResult(), []
        for cve in dict.fromkeys(c for c in cves if CVE_ID.match(c)):
            cached = self.cache.get(cve)
            if cached is None:
                todo.append(cve)
            elif cached != _NOT_SCORED:
                result.scores[cve] = cached

        for chunk in chunks(todo):
            try:
                rows = self._fetch(chunk)
            except (EpssError, ValidationError):
                result.failed.update(chunk)
                continue
            for cve in chunk:
                row = rows.get(cve)
                if row is None:
                    self.cache.set(cve, _NOT_SCORED)
                    continue
                score = EpssScore(row.epss, row.percentile, row.date[:10])
                self.cache.set(cve, score)
                result.scores[cve] = score
        return result

    def _fetch(self, chunk: list[str]) -> dict[str, _Row]:
        raw = self.fetch.request(
            "GET", PATH, params={"cve": ",".join(chunk)}, max_bytes=MAX_RESPONSE_BYTES
        )
        resp = _Response.model_validate(raw)
        if resp.total > len(resp.data):
            raise EpssError("EPSS returned a partial page")
        asked = set(chunk)
        return {row.cve: row for row in resp.data if row.cve in asked}
