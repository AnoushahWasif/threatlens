"""GitHub client tests against a fake GitHub (httpx MockTransport): no network."""

import json

import httpx
import pytest

from threatlens_api import github
from threatlens_api.github import (
    GithubClient,
    GithubUnavailable,
    RepoError,
    is_lockfile,
    parse_repo,
)

SHA = "a" * 40
REQS = b"jinja2==2.10\nflask>=2.0\n"
LOCK = json.dumps(
    {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "web"},
            "node_modules/next": {"version": "16.4.3"},
            "node_modules/next/node_modules/@next/env": {"version": "16.4.3"},
        },
    }
).encode()


def entry(path, size=100, type="blob"):
    return {"path": path, "type": type, "size": size, "mode": "100644", "sha": "b" * 40}


class FakeGithub:
    def __init__(self, files=None, tree=None, truncated=False):
        self.files = files if files is not None else {"requirements.txt": REQS}
        self.tree = tree if tree is not None else [entry(p, len(d)) for p, d in self.files.items()]
        self.truncated = truncated
        self.seen: list[httpx.Request] = []
        self.override = {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        url = str(request.url)
        for prefix, response in self.override.items():
            if url.startswith(prefix):
                return response(request) if callable(response) else response
        if url == "https://api.github.com/repos/octo/shop/commits/HEAD":
            return httpx.Response(200, text=SHA + "\n")
        if url == f"https://api.github.com/repos/octo/shop/git/trees/{SHA}?recursive=1":
            body = {"sha": SHA, "tree": self.tree, "truncated": self.truncated}
            return httpx.Response(200, json=body)
        prefix = f"https://raw.githubusercontent.com/octo/shop/{SHA}/"
        if url.startswith(prefix):
            path = httpx.URL(url).path.removeprefix(f"/octo/shop/{SHA}/")
            if path in self.files:
                return httpx.Response(200, content=self.files[path])
        return httpx.Response(404, json={"message": "Not Found"})


def client(fake):
    http = httpx.Client(transport=httpx.MockTransport(fake), follow_redirects=False)
    return GithubClient(http=http, sleep=lambda s: None)


# --- input ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "repo"),
    [
        ("octo/shop", "octo/shop"),
        ("  octo/shop  ", "octo/shop"),
        ("octo/shop\n", "octo/shop"),  # pasted with a newline
        ("https://github.com/octo/shop", "octo/shop"),
        ("https://github.com/octo/shop/", "octo/shop"),
        ("https://github.com/octo/shop.git", "octo/shop"),
        ("octo-cat/my.repo_2", "octo-cat/my.repo_2"),
        ("a/b", "a/b"),
    ],
)
def test_repo_names_and_urls_accepted(text, repo):
    assert parse_repo(text) == repo


@pytest.mark.parametrize(
    "text",
    [
        "",
        "octo",
        "octo/shop/tree/main",
        "http://github.com/octo/shop",  # not https
        "https://gitlab.com/octo/shop",
        "https://github.com.evil.example/octo/shop",
        "https://evil.example/github.com/octo/shop",
        "https://github.com/octo/shop?x=1",
        "https://github.com/octo/shop#readme",
        "https://user@github.com/octo/shop",
        "-octo/shop",
        "octo-/shop",
        "octo/..",
        "octo/.",
        "octo/.git",
        "octo/sh op",
        "../../etc/passwd",
        "octo/" + "x" * 101,
        "o" * 40 + "/shop",
        "octo/shop%2F..",
    ],
)
def test_anything_else_is_refused(text):
    assert parse_repo(text) is None


@pytest.mark.parametrize(
    ("path", "wanted"),
    [
        ("requirements.txt", True),
        ("api/requirements-dev.txt", True),
        ("web/package-lock.json", True),
        ("bom.json", True),
        ("sbom/app.cdx.json", True),
        ("README.md", False),
        ("package.json", False),
        ("web/node_modules/x/package-lock.json", False),
        ("venv/lib/site-packages/x/requirements.txt", False),
        ("vendor/requirements.txt", False),
    ],
)
def test_which_files_are_read(path, wanted):
    assert is_lockfile(path) is wanted


# --- fetching ---------------------------------------------------------------------------


def test_snapshot_reads_every_lockfile_at_one_commit():
    fake = FakeGithub({"requirements.txt": REQS, "web/package-lock.json": LOCK})
    snap = client(fake).snapshot("octo/shop")
    assert snap.commit == SHA
    assert snap.files == ["requirements.txt", "web/package-lock.json"]
    got = {(d.ecosystem.value, d.name, d.version, d.direct) for d in snap.result.dependencies}
    assert got == {
        ("PyPI", "jinja2", "2.10", True),
        ("npm", "next", "16.4.3", True),
        ("npm", "@next/env", "16.4.3", False),
    }
    assert [(s.ref, s.reason) for s in snap.result.skipped] == [
        ("requirements.txt: flask>=2.0", "not pinned to an exact version")
    ]
    # Two API calls; files by raw URL at the pinned commit, never a branch name.
    api = [r for r in fake.seen if r.url.host == "api.github.com"]
    assert len(api) == 2
    assert all(SHA in str(r.url) for r in fake.seen if r.url.host != "api.github.com")
    assert {r.url.host for r in fake.seen} == {"api.github.com", "raw.githubusercontent.com"}


def test_same_package_in_two_files_counted_once():
    fake = FakeGithub({"requirements.txt": REQS, "api/requirements.txt": b"jinja2==2.10\n"})
    snap = client(fake).snapshot("octo/shop")
    assert [d.name for d in snap.result.dependencies] == ["jinja2"]


def test_root_files_first_and_over_the_cap_reported():
    files = {f"svc{i:02}/requirements.txt": f"pkg{i}==1.0\n".encode() for i in range(25)}
    files["requirements.txt"] = b"root==1.0\n"
    snap = client(FakeGithub(files)).snapshot("octo/shop")
    assert snap.files[0] == "requirements.txt"
    assert len(snap.files) == github.MAX_FILES
    over = [s for s in snap.result.skipped if s.reason == "over 20 files"]
    assert len(over) == 6


def test_large_files_are_skipped_without_downloading():
    fake = FakeGithub(
        {"requirements.txt": REQS, "big/requirements.txt": b"x==1\n"},
        tree=[
            entry("requirements.txt", len(REQS)),
            entry("big/requirements.txt", github.MAX_FILE_BYTES + 1),
        ],
    )
    snap = client(fake).snapshot("octo/shop")
    assert snap.files == ["requirements.txt"]
    assert ("big/requirements.txt", "file larger than 1 MB") in [
        (s.ref, s.reason) for s in snap.result.skipped
    ]
    assert not any("big" in str(r.url) for r in fake.seen)


def test_total_size_is_capped(monkeypatch):
    monkeypatch.setattr(github, "MAX_TOTAL_BYTES", 30)
    fake = FakeGithub({"requirements.txt": b"a==1\n" * 4, "x/requirements.txt": b"b==1\n" * 4})
    snap = client(fake).snapshot("octo/shop")
    assert snap.files == ["requirements.txt"]
    assert ("x/requirements.txt", "over 5 MB of files") in [
        (s.ref, s.reason) for s in snap.result.skipped
    ]


def test_a_file_that_lies_about_its_size_is_cut_off():
    fake = FakeGithub(
        {"requirements.txt": b"a==1\n" * 300_000}, tree=[entry("requirements.txt", 10)]
    )
    with pytest.raises(RepoError, match="larger than allowed"):
        client(fake).snapshot("octo/shop")


def test_a_bad_file_is_reported_and_the_rest_still_read():
    fake = FakeGithub({"requirements.txt": REQS, "web/package-lock.json": b"{not json"})
    snap = client(fake).snapshot("octo/shop")
    assert [d.name for d in snap.result.dependencies] == ["jinja2"]
    assert ("web/package-lock.json", "Invalid JSON at line 1") in [
        (s.ref, s.reason) for s in snap.result.skipped
    ]


def test_symlinks_and_submodules_are_not_followed():
    fake = FakeGithub(
        {"requirements.txt": REQS},
        tree=[
            entry("requirements.txt", len(REQS)),
            entry("link/requirements.txt", type="commit"),
            entry("sub", type="tree"),
        ],
    )
    assert client(fake).snapshot("octo/shop").files == ["requirements.txt"]


def test_a_cut_off_file_list_is_reported():
    fake = FakeGithub(truncated=True)
    snap = client(fake).snapshot("octo/shop")
    assert ("octo/shop", "repository too large: file list cut off") in [
        (s.ref, s.reason) for s in snap.result.skipped
    ]


def test_no_lockfiles_is_a_clear_error():
    fake = FakeGithub({"README.md": b"hi"})
    with pytest.raises(RepoError, match="No supported files"):
        client(fake).snapshot("octo/shop")


def test_lockfiles_it_cant_read_yet_are_named():
    fake = FakeGithub({"web/pnpm-lock.yaml": b"x", "uv.lock": b"x", "README.md": b"x"})
    with pytest.raises(RepoError, match=r"^Found pnpm-lock.yaml, uv.lock, which ThreatLens can.t"):
        client(fake).snapshot("octo/shop")


def test_too_many_dependencies_is_a_clear_error(monkeypatch):
    monkeypatch.setattr(github.ingest, "MAX_DEPENDENCIES", 1)
    fake = FakeGithub({"requirements.txt": b"a==1\n", "x/requirements.txt": b"b==1\n"})
    with pytest.raises(RepoError, match="More than 1 dependencies"):
        client(fake).snapshot("octo/shop")


def test_a_name_that_isnt_a_repo_never_reaches_the_network():
    fake = FakeGithub()
    with pytest.raises(RepoError):
        client(fake).snapshot("https://evil.example/x")
    assert fake.seen == []


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(404), "not found, or it isn't public"),
        (httpx.Response(301, headers={"location": "https://api.github.com/x"}), "has moved"),
        (httpx.Response(409), "is empty"),
        (httpx.Response(403, headers={"x-ratelimit-remaining": "0"}), "rate limit"),
        (httpx.Response(429), "rate limit"),
        (httpx.Response(403), r"refused the request \(HTTP 403\)"),
    ],
)
def test_github_refusals_are_clear_errors_not_retried(response, message):
    fake = FakeGithub()
    fake.override["https://api.github.com/repos/octo/shop/commits"] = response
    with pytest.raises(RepoError, match=message):
        client(fake).snapshot("octo/shop")
    assert len(fake.seen) == 1


def test_github_outage_is_retried_then_reported_as_unavailable():
    fake = FakeGithub()
    fake.override["https://api.github.com/"] = httpx.Response(503)
    with pytest.raises(GithubUnavailable, match="HTTP 503"):
        client(fake).snapshot("octo/shop")
    assert len(fake.seen) == 3


def test_a_blip_is_retried():
    fake = FakeGithub()
    calls = []

    def flaky(request):
        calls.append(request)
        if len(calls) == 1:
            raise httpx.ConnectTimeout("slow", request=request)
        return httpx.Response(200, text=SHA)

    fake.override["https://api.github.com/repos/octo/shop/commits"] = flaky
    assert client(fake).snapshot("octo/shop").commit == SHA
    assert len(calls) == 2


@pytest.mark.parametrize("body", ["not-a-sha", "A" * 40, SHA + "0"])
def test_an_odd_commit_id_is_not_trusted(body):
    fake = FakeGithub()
    fake.override["https://api.github.com/repos/octo/shop/commits"] = httpx.Response(200, text=body)
    with pytest.raises(GithubUnavailable, match="unexpected commit"):
        client(fake).snapshot("octo/shop")


def test_an_odd_file_list_is_not_trusted():
    fake = FakeGithub()
    fake.override["https://api.github.com/repos/octo/shop/git"] = httpx.Response(
        200, json={"tree": "nope"}
    )
    with pytest.raises(GithubUnavailable, match="unexpected file list"):
        client(fake).snapshot("octo/shop")


def test_paths_are_quoted_in_raw_urls():
    fake = FakeGithub({"a b/requirements.txt": REQS})
    snap = client(fake).snapshot("octo/shop")
    assert snap.files == ["a b/requirements.txt"]
    raw = [r for r in fake.seen if r.url.host == "raw.githubusercontent.com"]
    assert raw[0].url.raw_path.decode() == f"/octo/shop/{SHA}/a%20b/requirements.txt"
