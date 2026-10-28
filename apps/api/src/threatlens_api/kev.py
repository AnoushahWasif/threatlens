"""CISA's Known Exploited Vulnerabilities catalogue (CC0), downloaded once a day.

Being in KEV means CISA has evidence of exploitation in the wild, which is a stronger
signal than any probability, so the risk score treats it as certain.
"""

import re
import time
from collections.abc import Callable
from dataclasses import dataclass

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from threatlens_api.fetch import FetchError, JsonFetcher, default_http

BASE_URL = "https://www.cisa.gov"
PATH = "/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_RESPONSE_BYTES = 20_000_000
TTL = 24 * 3600
MAX_STALE = 3 * 24 * 3600
# 1760 entries on 28 Oct 2026 and the list only grows. A much shorter feed is broken or
# truncated, and trusting it would make exploited CVEs look unexploited.
MIN_ENTRIES = 1000

CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$")


class KevError(FetchError):
    pass


@dataclass(frozen=True)
class KevEntry:
    date_added: str
    ransomware: bool


@dataclass(frozen=True)
class KevCatalog:
    version: str
    entries: dict[str, KevEntry]
    fetched_at: float
    stale: bool = False

    def __contains__(self, cve: str) -> bool:
        return cve in self.entries


class _Entry(BaseModel):
    model_config = ConfigDict(extra="ignore")

    cve_id: str = Field(alias="cveID")
    date_added: str = Field("", alias="dateAdded")
    ransomware: str = Field("", alias="knownRansomwareCampaignUse")


class _Feed(BaseModel):
    model_config = ConfigDict(extra="ignore")

    version: str = Field(alias="catalogVersion")
    count: int
    vulnerabilities: list[_Entry]


def parse(raw: dict, fetched_at: float) -> KevCatalog:
    try:
        feed = _Feed.model_validate(raw)
    except ValidationError as exc:
        raise KevError("unexpected KEV format") from exc
    if feed.count != len(feed.vulnerabilities):
        raise KevError("KEV count does not match its entries")
    if len(feed.vulnerabilities) < MIN_ENTRIES:
        raise KevError("KEV feed is suspiciously short")
    entries = {
        e.cve_id: KevEntry(e.date_added[:10], e.ransomware == "Known")
        for e in feed.vulnerabilities
        if CVE_ID.match(e.cve_id)
    }
    return KevCatalog(feed.version[:20], entries, fetched_at)


class KevClient:
    def __init__(
        self,
        http: httpx.Client | None = None,
        max_retries: int = 3,
        backoff: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ):
        self.fetch = JsonFetcher(
            http or default_http(BASE_URL, timeout=30.0),
            "KEV",
            KevError,
            max_retries,
            backoff,
            sleep,
        )
        self.clock = clock
        self._catalog: KevCatalog | None = None

    def catalog(self) -> KevCatalog:
        """The cached catalogue, refreshed daily. Raises KevError if there is no usable copy."""
        now = self.clock()
        cached = self._catalog
        if cached and now - cached.fetched_at < TTL:
            return cached
        try:
            raw = self.fetch.request("GET", PATH, max_bytes=MAX_RESPONSE_BYTES)
            self._catalog = parse(raw, now)
            return self._catalog
        except KevError:
            if cached and now - cached.fetched_at < MAX_STALE:
                return KevCatalog(cached.version, cached.entries, cached.fetched_at, stale=True)
            raise
