"""Reads the lockfiles of a public GitHub repository, pinned to one commit.

Every URL is built here from an owner and a name that passed a strict pattern, so a user
can't point the worker at any other host (no SSRF). Two GitHub API calls per scan (the
commit and the file tree); the files themselves come from raw.githubusercontent.com, which
doesn't count against the API rate limit (60 calls an hour per IP without a token).
"""

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from threatlens_api import __version__, ingest

API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"

MAX_FILES = 20
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 5_000_000
# A tree of ~100,000 files is about 15 MB of JSON; GitHub truncates past that anyway.
MAX_TREE_BYTES = 20_000_000
# For the whole fetch. Each read has its own 15 s timeout, but ~22 requests with retries
# could still run past the worker's 600 s, leaving the scan "running" until a takeover.
DEADLINE_SECONDS = 240
# Folders whose lockfiles belong to someone else's package, not to this project.
SKIP_DIRS = {"node_modules", ".git", "site-packages", "vendor"}
# Lockfiles the parser can't read yet, named in the error so "no files" isn't a mystery.
UNSUPPORTED = (
    "pnpm-lock.yaml",
    "yarn.lock",
    "uv.lock",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "Gemfile.lock",
    "composer.lock",
)

# No lookahead: pydantic's regex engine has none. Old accounts may contain "--".
_OWNER = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?"
_NAME = r"[A-Za-z0-9._-]{1,100}"
REPO = rf"^{_OWNER}/{_NAME}$"
_URL = re.compile(rf"^https://github\.com/(?P<repo>{_OWNER}/{_NAME})/?$")
_SHA = re.compile(r"^[0-9a-f]{40}$")


class RepoError(Exception):
    """The scan can't succeed by trying again. The message is shown to the user."""


class GithubUnavailable(Exception):
    """GitHub is down or slow. The worker hands the scan back to be tried again."""


class _TooLarge(Exception):
    pass


def parse_repo(text: str) -> str | None:
    """Accepts owner/name or https://github.com/owner/name(.git) and returns owner/name."""
    text = text.strip()
    match = _URL.fullmatch(text)
    repo = match["repo"] if match else text
    repo = repo.removesuffix(".git")
    if not re.fullmatch(REPO, repo) or repo.split("/")[1] in (".", ".."):
        return None
    return repo


def is_lockfile(path: str) -> bool:
    *dirs, name = path.split("/")
    if SKIP_DIRS.intersection(dirs):
        return False
    name = name.lower()
    return (
        name == "package-lock.json"
        or (name.endswith(".txt") and "requirements" in name)
        or name == "bom.json"
        or name.endswith(".cdx.json")
    )


class _Entry(BaseModel):
    model_config = ConfigDict(extra="ignore")

    path: str
    type: str
    size: int = 0


class _Tree(BaseModel):
    model_config = ConfigDict(extra="ignore")

    tree: list[_Entry]
    truncated: bool = False


@dataclass
class Snapshot:
    commit: str
    result: ingest.IngestResult
    files: list[str] = field(default_factory=list)


class GithubClient:
    def __init__(
        self,
        http: httpx.Client | None = None,
        max_retries: int = 2,
        backoff: float = 1.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        deadline: float = DEADLINE_SECONDS,
    ):
        self.http = http or httpx.Client(
            timeout=httpx.Timeout(15.0, connect=5.0),
            follow_redirects=False,
            headers={"user-agent": f"threatlens/{__version__}"},
        )
        self.max_retries, self.backoff, self.sleep = max_retries, backoff, sleep
        self.clock, self.deadline = clock, deadline

    def snapshot(self, repo: str) -> Snapshot:
        if parse_repo(repo) != repo:
            raise RepoError("Not a GitHub repository name")
        ends = self.clock() + self.deadline
        commit = self._commit(repo, ends)
        tree = self._tree(repo, commit, ends)

        merged = ingest.IngestResult(format="GitHub repo")
        wanted = sorted(
            (e for e in tree.tree if e.type == "blob" and is_lockfile(e.path)),
            key=lambda e: (e.path.count("/"), e.path),  # the project's own files first
        )
        if not wanted:
            names = {e.path.rsplit("/", 1)[-1] for e in tree.tree if e.type == "blob"}
            found = [n for n in UNSUPPORTED if n in names]
            if found:
                raise RepoError(
                    f"Found {', '.join(found[:3])}, which ThreatLens can't read yet. It reads "
                    "requirements*.txt, package-lock.json and CycloneDX SBOMs"
                )
            raise RepoError(
                "No supported files found (requirements*.txt, package-lock.json, "
                "bom.json or *.cdx.json)"
            )
        if tree.truncated:
            merged.skipped.append(ingest.Skipped(repo, "repository too large: file list cut off"))

        files, total = [], 0
        for entry in wanted:
            if len(files) == MAX_FILES:
                merged.skipped.append(ingest.Skipped(entry.path, f"over {MAX_FILES} files"))
            elif entry.size > MAX_FILE_BYTES:
                merged.skipped.append(ingest.Skipped(entry.path, "file larger than 1 MB"))
            elif total + entry.size > MAX_TOTAL_BYTES:
                merged.skipped.append(ingest.Skipped(entry.path, "over 5 MB of files"))
            else:
                try:
                    data = self._raw(repo, commit, entry.path, ends)
                except _TooLarge:
                    # The tree said it was small enough; the file itself wasn't.
                    merged.skipped.append(ingest.Skipped(entry.path, "file larger than 1 MB"))
                    continue
                total += len(data)
                files.append(entry.path)
                self._merge(merged, entry.path, data)
        return Snapshot(commit=commit, result=merged, files=files)

    def _merge(self, merged: ingest.IngestResult, path: str, data: bytes) -> None:
        try:
            parsed = ingest.parse(path, data)
        except ingest.IngestError as e:
            merged.skipped.append(ingest.Skipped(path, str(e)[:200]))
            return
        for s in parsed.skipped:
            merged.skipped.append(ingest.Skipped(ingest._short(f"{path}: {s.ref}"), s.reason))
        for d in parsed.dependencies:
            try:
                merged.add(d.name, d.version, d.ecosystem, d.direct, f"{path}: {d.name}")
            except ingest.IngestError as e:
                raise RepoError(str(e)) from e

    # --- HTTP ----------------------------------------------------------------------------

    def _commit(self, repo: str, ends: float) -> str:
        try:
            resp = self._get(
                f"{API}/repos/{repo}/commits/HEAD",
                1_000,
                {"accept": "application/vnd.github.sha"},
                ends,
            )
        except _TooLarge as e:
            raise GithubUnavailable("GitHub sent an unexpected commit id") from e
        sha = resp.strip().decode("ascii", "replace")
        if not _SHA.match(sha):
            raise GithubUnavailable("GitHub sent an unexpected commit id")
        return sha

    def _tree(self, repo: str, commit: str, ends: float) -> _Tree:
        try:
            data = self._get(
                f"{API}/repos/{repo}/git/trees/{commit}?recursive=1",
                MAX_TREE_BYTES,
                {"accept": "application/vnd.github+json"},
                ends,
            )
        except _TooLarge as e:
            raise RepoError("The repository has too many files to list") from e
        try:
            return _Tree.model_validate_json(data)
        except ValidationError as e:
            raise GithubUnavailable("GitHub sent an unexpected file list") from e

    def _raw(self, repo: str, commit: str, path: str, ends: float) -> bytes:
        return self._get(f"{RAW}/{repo}/{commit}/{quote(path)}", MAX_FILE_BYTES, {}, ends)

    def _get(self, url: str, max_bytes: int, headers: dict, ends: float) -> bytes:
        reason = "no attempt made"
        for attempt in range(self.max_retries + 1):
            if attempt:
                self.sleep(self.backoff * 2 ** (attempt - 1))
            self._check_deadline(ends)
            try:
                with self.http.stream("GET", url, headers=headers) as resp:
                    if resp.status_code >= 500:
                        reason = f"HTTP {resp.status_code}"
                        continue
                    _check_status(resp)
                    return self._read_capped(resp, max_bytes, ends)
            except httpx.TransportError as e:
                reason = type(e).__name__
        raise GithubUnavailable(f"GitHub unavailable ({reason})")

    def _check_deadline(self, ends: float) -> None:
        if self.clock() > ends:
            raise GithubUnavailable("GitHub is too slow right now")

    def _read_capped(self, resp: httpx.Response, max_bytes: int, ends: float) -> bytes:
        data = bytearray()
        for chunk in resp.iter_bytes():
            data += chunk
            if len(data) > max_bytes:
                raise _TooLarge()
            self._check_deadline(ends)  # a server trickling bytes never hits the read timeout
        return bytes(data)


def _check_status(resp: httpx.Response) -> None:
    status = resp.status_code
    if status == 200:
        return
    if status == 404:
        raise RepoError("Repository not found, or it isn't public")
    if status in (301, 302, 307, 308):
        raise RepoError("The repository has moved. Use its current name")
    if status == 409:
        raise RepoError("The repository is empty")
    if status in (403, 429) and resp.headers.get("x-ratelimit-remaining") == "0":
        raise RepoError("GitHub's rate limit was reached. Try again in an hour")
    # The secondary limit (too many requests at once) sends retry-after, with calls left.
    if status == 429 or (status == 403 and "retry-after" in resp.headers):
        raise RepoError("GitHub is limiting requests. Try again in a few minutes")
    raise RepoError(f"GitHub refused the request (HTTP {status})")
