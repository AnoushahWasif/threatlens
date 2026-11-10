"""Scanning a GitHub repo: the route, and the worker's fetch-once snapshot."""

import pytest
from test_scans import Clock, fake_pipeline

from threatlens_api import ingest
from threatlens_api.errors import ApiError
from threatlens_api.github import GithubUnavailable, RepoError, Snapshot
from threatlens_api.models import Dependency, Ecosystem, Project
from threatlens_api.repository import Conflict, MemoryRepository
from threatlens_api.scans import MemoryBlobs, Scan, ScanMessage, ScanStatus, upload_key
from threatlens_api.worker import MAX_ATTEMPTS, Worker

SHA = "c" * 40


def snapshot(skipped=1):
    result = ingest.IngestResult(format="GitHub repo")
    result.add("jinja2", "2.10", Ecosystem.PYPI, True, "requirements.txt")
    result.add("@next/env", "16.4.3", Ecosystem.NPM, False, "web/package-lock.json")
    for i in range(skipped):
        result.skipped.append(ingest.Skipped(f"requirements.txt: flask>=2.{i}", "not pinned"))
    return Snapshot(commit=SHA, result=result, files=["requirements.txt"])


class FakeGithub:
    def __init__(self, outcome=None):
        self.outcome = outcome or snapshot()
        self.calls = []

    def snapshot(self, repo):
        self.calls.append(repo)
        outcome = self.outcome.pop(0) if isinstance(self.outcome, list) else self.outcome
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


# --- through HTTP ------------------------------------------------------------------------


@pytest.fixture
def project(client):
    return client.post("/projects", json={"name": "shop"}).json()["id"]


@pytest.fixture
def scanning(app):
    runner = app.state.local_runner
    runner.worker.pipeline = fake_pipeline()
    runner.worker.github_client = FakeGithub()
    return runner


def test_repo_scan_queues_then_the_worker_fetches_and_scans(client, project, scanning):
    resp = client.post(
        f"/projects/{project}/scans/github", json={"repo": "https://github.com/octo/shop"}
    )
    assert resp.status_code == 202
    scan = resp.json()
    assert scan["repo"] == "octo/shop" and scan["status"] == "queued"
    assert scan["format"] == "GitHub repo" and scan["commit"] is None
    assert resp.headers["location"] == f"/projects/{project}/scans/{scan['id']}"

    scanning.run_pending()
    done = client.get(f"/projects/{project}/scans/{scan['id']}").json()
    assert done["status"] == "done"
    assert done["commit"] == SHA
    assert (done["dependencies"], done["skipped"], done["findings"]) == (2, 1, 2)
    assert done["skipped_examples"] == [
        {"ref": "requirements.txt: flask>=2.0", "reason": "not pinned"}
    ]
    findings = client.get(f"/projects/{project}/findings").json()
    assert {(f["dependency"]["name"], f["dependency"]["direct"]) for f in findings} == {
        ("jinja2", True),
        ("@next/env", False),
    }
    assert scanning.worker.github_client.calls == ["octo/shop"]


@pytest.mark.parametrize(
    "repo", ["https://evil.example/octo/shop", "octo", "../../x", "octo/shop/tree/main"]
)
def test_a_bad_repo_is_refused_before_anything_is_queued(app, client, project, repo):
    resp = client.post(f"/projects/{project}/scans/github", json={"repo": repo})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "bad_repo"
    assert app.state.scan_queue.items.empty()
    # A typo doesn't use up the hourly scans.
    assert app.state.scan_budget.take("alice") is None


@pytest.mark.parametrize("body", [{}, {"repo": ""}, {"repo": "x" * 301}, {"repo": "a/b", "x": 1}])
def test_body_is_checked(client, project, body):
    assert client.post(f"/projects/{project}/scans/github", json=body).status_code == 422


def test_repo_scans_share_the_hourly_scan_limit(app, client, project):
    for _ in range(app.state.settings.scans_per_user_per_hour):
        assert client.post(f"/projects/{project}/scans/github", json={"repo": "a/b"}).is_success
    resp = client.post(f"/projects/{project}/scans/github", json={"repo": "a/b"})
    assert resp.status_code == 429 and "retry-after" in resp.headers


def test_someone_elses_project_is_404(app, client, anon, token, project):
    anon.headers["authorization"] = f"Bearer {token('mallory')}"
    resp = anon.post(f"/projects/{project}/scans/github", json={"repo": "a/b"})
    assert resp.status_code == 404
    assert app.state.scan_queue.items.empty()


def test_a_repo_scan_that_cant_be_queued_says_failed(app, client, project):
    class Down:
        def send(self, message):
            raise ApiError(503, "queue_unavailable", "Can't start a scan right now")

    app.state.scan_queue = Down()
    created = []
    real_create = app.state.repo.create_scan
    app.state.repo.create_scan = lambda scan: (created.append(scan.id), real_create(scan))
    resp = client.post(f"/projects/{project}/scans/github", json={"repo": "a/b"})
    assert resp.status_code == 503
    (scan_id,) = created
    assert client.get(f"/projects/{project}/scans/{scan_id}").json()["status"] == "failed"


# --- the worker ----------------------------------------------------------------------------


@pytest.fixture
def setup():
    repo, blobs, clock = MemoryRepository(), MemoryBlobs(), Clock()
    project = Project(name="p", owner_id="alice")
    repo.create_project("alice", project, max_per_user=5)
    scan = Scan(
        project_id=project.id,
        owner_id="alice",
        filename="repo.cdx.json",
        format="GitHub repo",
        repo="octo/shop",
    )
    repo.create_scan(scan)
    calls = []
    gh = FakeGithub()
    worker = Worker(repo, blobs, fake_pipeline(calls), clock=clock, github_client=gh)
    return repo, blobs, worker, gh, ScanMessage.for_scan(scan), calls


def stored(repo, message):
    return repo.load_scan(message.owner, message.project_id, message.scan_id)[0]


def test_the_snapshot_is_stored_and_a_retry_does_not_fetch_again(setup):
    repo, blobs, worker, gh, message, calls = setup
    worker.pipeline = fake_pipeline_failing_once(calls)
    with pytest.raises(RuntimeError):
        worker.handle(message)
    scan = stored(repo, message)
    assert scan.status == ScanStatus.QUEUED and scan.commit == SHA
    # Counts were saved with the snapshot, before the scan itself failed.
    assert (scan.dependencies, scan.skipped) == (2, 1)

    worker.handle(message)
    assert gh.calls == ["octo/shop"]  # fetched once
    assert stored(repo, message).status == ScanStatus.DONE
    assert calls[-1] == ["jinja2", "@next/env"]
    parsed = ingest.parse("repo.cdx.json", blobs.get(upload_key(scan)))
    assert [(d.name, d.direct) for d in parsed.dependencies] == [
        ("jinja2", True),
        ("@next/env", False),
    ]


def fake_pipeline_failing_once(calls):
    inner, state = fake_pipeline(calls), {"failed": False}

    def run(project_id, deps):
        if not state["failed"]:
            state["failed"] = True
            raise RuntimeError("osv down")
        return inner(project_id, deps)

    return run


def test_a_repo_problem_fails_the_scan_at_once_with_its_message(setup):
    repo, blobs, worker, gh, message, calls = setup
    gh.outcome = RepoError("Repository not found, or it isn't public")
    worker.handle(message)  # no raise: retrying can't help
    scan = stored(repo, message)
    assert scan.status == ScanStatus.FAILED
    assert scan.error == "Repository not found, or it isn't public"
    assert scan.attempts == 1 and calls == []
    assert blobs.get(upload_key(scan)) is None


def test_github_down_is_handed_back_then_given_up(setup):
    repo, _, worker, gh, message, calls = setup
    gh.outcome = GithubUnavailable("GitHub unavailable (HTTP 503)")
    for _ in range(MAX_ATTEMPTS - 1):
        with pytest.raises(GithubUnavailable):
            worker.handle(message)
    worker.handle(message)  # the last attempt fails the scan instead of raising
    scan = stored(repo, message)
    assert scan.status == ScanStatus.FAILED and scan.attempts == MAX_ATTEMPTS
    assert scan.error == "The scan kept failing. Try again later"
    assert len(gh.calls) == MAX_ATTEMPTS and calls == []


def test_github_down_once_then_fine(setup):
    repo, _, worker, gh, message, _ = setup
    gh.outcome = [GithubUnavailable("blip"), snapshot()]
    with pytest.raises(GithubUnavailable):
        worker.handle(message)
    worker.handle(message)
    assert stored(repo, message).status == ScanStatus.DONE


def test_many_skipped_entries_are_counted_and_only_the_first_few_kept(setup):
    repo, _, worker, gh, message, _ = setup
    gh.outcome = snapshot(skipped=50)
    worker.handle(message)
    scan = stored(repo, message)
    assert scan.skipped == 50 and len(scan.skipped_examples) == 20


def test_a_long_skipped_ref_is_cut_to_fit(setup):
    repo, _, worker, gh, message, _ = setup
    snap = snapshot(skipped=0)
    snap.result.skipped.append(ingest.Skipped("x" * 500, "y" * 500))
    gh.outcome = snap
    worker.handle(message)
    [example] = stored(repo, message).skipped_examples
    assert (len(example.ref), len(example.reason)) == (120, 200)


def test_losing_the_scan_after_the_snapshot_leaves_it_to_the_winner(setup):
    repo, blobs, worker, gh, message, calls = setup
    real_save = repo.save_scan
    saves = []

    def save(scan, version):
        saves.append(scan.status)
        if len(saves) == 2:  # the save right after the snapshot
            raise Conflict()
        return real_save(scan, version)

    repo.save_scan = save
    worker.handle(message)
    assert calls == []  # didn't go on to scan
    # The snapshot is there for whoever took the scan over.
    assert blobs.get(upload_key(stored(repo, message))) is not None


def test_an_upload_scan_never_touches_github(setup):
    repo, blobs, worker, gh, _, _ = setup
    project_id = stored_project(repo)
    scan = Scan(project_id=project_id, owner_id="alice", filename="requirements.txt", format="r")
    blobs.put(upload_key(scan), b"jinja2==2.10\n")
    repo.create_scan(scan)
    worker.handle(ScanMessage.for_scan(scan))
    assert gh.calls == []


def stored_project(repo):
    return repo.list_projects("alice")[0].id


def test_an_upload_scan_whose_file_is_gone_still_fails_as_before(setup):
    repo, _, worker, gh, _, _ = setup
    scan = Scan(
        project_id=stored_project(repo), owner_id="alice", filename="requirements.txt", format="r"
    )
    repo.create_scan(scan)
    message = ScanMessage.for_scan(scan)
    worker.handle(message)
    assert "no longer there" in stored(repo, message).error
    assert gh.calls == []


def test_dependency_fields_survive_as_the_pipeline_sees_them(setup):
    _, _, worker, _, message, calls = setup
    seen = []

    def capture(project_id, deps):
        seen.extend(deps)
        return fake_pipeline()(project_id, deps)

    worker.pipeline = capture
    worker.handle(message)
    assert seen == [
        Dependency(name="jinja2", version="2.10", ecosystem=Ecosystem.PYPI),
        Dependency(name="@next/env", version="16.4.3", ecosystem=Ecosystem.NPM, direct=False),
    ]
