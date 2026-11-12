import json
import time
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import boto3
import pytest
from botocore.exceptions import EndpointConnectionError
from fastapi.testclient import TestClient
from moto import mock_aws

from threatlens_api.errors import ApiError
from threatlens_api.models import Finding, Project, Severity
from threatlens_api.repository import MemoryRepository
from threatlens_api.risk import Enriched
from threatlens_api.scans import (
    MemoryBlobs,
    S3Blobs,
    Scan,
    ScanMessage,
    ScanStatus,
    SqsQueue,
    parse_message,
    upload_key,
)
from threatlens_api.worker import MAX_ATTEMPTS, SCAN_TIMEOUT, Worker, lambda_handler_for

REQUIREMENTS = b"jinja2==2.10\nrequests==2.19.0\nflask>=2.0\n"
MISSING = "00000000-0000-4000-8000-000000000000"


def fake_pipeline(calls=None, unchecked=0):
    def run(project_id, deps):
        if calls is not None:
            calls.append([d.name for d in deps])
        findings = [
            Finding(
                project_id=project_id,
                dependency=d,
                vuln_id=f"PYSEC-2024-{i}",
                severity=Severity.HIGH,
                epss=0.5,
                risk_score=50.0,
            )
            for i, d in enumerate(deps)
        ]
        return Enriched(findings=findings, unchecked=deps[:unchecked])

    return run


@pytest.fixture
def scanning(app):
    """The app with a fake OSV/EPSS/KEV pipeline; run `scanning.run()` to work the queue."""
    calls = []
    runner = app.state.local_runner
    runner.worker.pipeline = fake_pipeline(calls)

    class Scanning:
        worker = runner.worker

        def run(self):
            runner.run_pending()

    s = Scanning()
    s.calls = calls
    return s


@pytest.fixture
def project(client):
    return client.post("/projects", json={"name": "shop api"}).json()["id"]


def upload(client, project_id, data=REQUIREMENTS, filename="requirements.txt"):
    return client.post(f"/projects/{project_id}/scans", params={"filename": filename}, content=data)


# --- through HTTP ------------------------------------------------------------------------


def test_upload_returns_at_once_then_the_worker_fills_in_findings(client, project, scanning):
    r = upload(client, project)
    assert r.status_code == 202
    scan = r.json()
    assert r.headers["location"] == f"/projects/{project}/scans/{scan['id']}"
    assert (scan["status"], scan["dependencies"], scan["skipped"]) == ("queued", 2, 1)
    assert scan["skipped_examples"][0]["ref"].startswith("flask")
    assert "owner_id" not in scan
    assert client.get(f"/projects/{project}/findings").json() == []  # nothing finished yet

    scanning.run()
    done = client.get(f"/projects/{project}/scans/{scan['id']}").json()
    assert (done["status"], done["findings"], done["attempts"]) == ("done", 2, 1)
    assert done["finished_at"] is not None
    findings = client.get(f"/projects/{project}/findings").json()
    assert sorted(f["dependency"]["name"] for f in findings) == ["jinja2", "requests"]
    assert scanning.calls == [["jinja2", "requests"]]


def test_findings_come_from_the_newest_finished_scan(client, project, scanning):
    upload(client, project)
    scanning.run()
    upload(client, project, b"django==3.2.0\n")
    # The second one hasn't run: the first scan's findings still show.
    assert len(client.get(f"/projects/{project}/findings").json()) == 2
    scanning.run()
    names = [f["dependency"]["name"] for f in client.get(f"/projects/{project}/findings").json()]
    assert names == ["django"]


@pytest.mark.parametrize(
    ("data", "filename"),
    [
        (b"\xff\xfe not utf-8", "requirements.txt"),
        (b"{not json", "package-lock.json"),
        (b"jinja2==2.10\n", "notes.md"),
        (b'{"bomFormat": "SPDX"}', "sbom.json"),
    ],
)
def test_a_bad_file_is_refused_before_anything_is_queued(app, client, project, data, filename):
    r = upload(client, project, data, filename)
    assert (r.status_code, r.json()["error"]["code"]) == (422, "bad_file")
    assert app.state.scan_queue.items.empty()


@pytest.mark.parametrize("filename", ["", "../etc/passwd", "a/b.txt", "x" * 101, ".hidden"])
def test_filename_is_checked(client, project, filename):
    assert upload(client, project, filename=filename).status_code == 422


def test_scans_of_someone_elses_project_are_404(app, client, anon, token, project, scanning):
    scan = upload(client, project).json()
    scanning.run()
    bob = {"Authorization": f"Bearer {token('bob')}"}
    as_bob = TestClient(app, headers=bob, raise_server_exceptions=False)
    assert upload(as_bob, project).status_code == 404
    for path in (f"/projects/{project}/scans/{scan['id']}", f"/projects/{project}/findings"):
        r = anon.get(path, headers=bob)
        assert (r.status_code, r.json()["error"]["code"]) == (404, "not_found")
    assert anon.get(f"/projects/{project}/findings").status_code == 401


def test_missing_project_and_scan_are_404(client, project):
    assert upload(client, MISSING).status_code == 404
    assert client.get(f"/projects/{MISSING}/findings").status_code == 404
    assert client.get(f"/projects/{project}/scans/{MISSING}").status_code == 404


def test_upload_size_is_capped_even_without_content_length(app, client, project):
    app.state.settings.max_request_bytes = 1_000

    def chunks():
        for _ in range(20):
            yield b"a==1.0\n" * 20

    r = client.post(
        f"/projects/{project}/scans", params={"filename": "requirements.txt"}, content=chunks()
    )
    assert (r.status_code, r.json()["error"]["code"]) == (413, "payload_too_large")


def test_scan_limit_per_user(app, client, project):
    app.state.scan_budget.per_user = 2
    for _ in range(2):
        assert upload(client, project).status_code == 202
    r = upload(client, project)
    assert (r.status_code, r.json()["error"]["code"]) == (429, "scan_limit")
    assert int(r.headers["retry-after"]) > 0


def test_a_scan_that_cant_be_queued_says_failed_not_queued(app, client, project):
    class Down:
        def send(self, message):
            raise ApiError(503, "queue_unavailable", "Can't start a scan right now")

    app.state.scan_queue = Down()
    created = []
    real_create = app.state.repo.create_scan
    app.state.repo.create_scan = lambda scan: (created.append(scan.id), real_create(scan))
    r = upload(client, project)
    assert (r.status_code, r.json()["error"]["code"]) == (503, "queue_unavailable")
    (scan_id,) = created
    assert client.get(f"/projects/{project}/scans/{scan_id}").json()["status"] == "failed"


def test_a_lost_findings_file_is_an_error_not_an_empty_list(app, client, project, scanning):
    scan = upload(client, project).json()
    scanning.run()
    done = client.get(f"/projects/{project}/scans/{scan['id']}").json()
    assert done["findings_file"].endswith(f"{scan['id']}-1.json")
    app.state.blobs._data.pop(done["findings_file"])
    assert client.get(f"/projects/{project}/findings").status_code == 500


# --- the worker ----------------------------------------------------------------------------


class Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 3, 12, tzinfo=UTC)

    def __call__(self):
        return self.now


@pytest.fixture
def setup():
    """A repo, files and a worker with a controllable clock, plus one queued scan."""
    repo, blobs, clock = MemoryRepository(), MemoryBlobs(), Clock()
    project = Project(name="p", owner_id="alice")
    repo.create_project("alice", project, max_per_user=5)
    scan = Scan(
        project_id=project.id, owner_id="alice", filename="requirements.txt", format="requirements"
    )
    blobs.put(upload_key(scan), REQUIREMENTS)
    repo.create_scan(scan)
    calls = []
    worker = Worker(repo, blobs, fake_pipeline(calls), clock=clock)
    return repo, blobs, clock, worker, ScanMessage.for_scan(scan), calls


def stored(repo, message):
    return repo.load_scan(message.owner, message.project_id, message.scan_id)[0]


def test_a_repeat_delivery_does_nothing(setup):
    repo, _, _, worker, message, calls = setup
    worker.handle(message)
    worker.handle(message)
    assert len(calls) == 1
    assert stored(repo, message).attempts == 1


def test_a_scan_running_elsewhere_is_left_alone_until_it_times_out(setup):
    repo, _, clock, worker, message, calls = setup
    scan, version = repo.load_scan(message.owner, message.project_id, message.scan_id)
    scan.status, scan.started_at, scan.attempts = ScanStatus.RUNNING, clock(), 1
    repo.save_scan(scan, version)

    worker.handle(message)
    assert calls == []
    clock.now += SCAN_TIMEOUT + timedelta(seconds=1)  # that worker died
    worker.handle(message)
    assert stored(repo, message).status == ScanStatus.DONE
    assert stored(repo, message).attempts == 2


def test_a_crash_is_handed_back_then_given_up_after_three_attempts(setup):
    repo, _, _, worker, message, _ = setup

    def broken(project_id, deps):
        raise RuntimeError("OSV client bug")

    worker.pipeline = broken
    for attempt in range(1, MAX_ATTEMPTS + 1):
        # The last attempt marks the scan failed and returns: there's nothing left to retry.
        with pytest.raises(RuntimeError) if attempt < MAX_ATTEMPTS else nullcontext():
            worker.handle(message)
        scan = stored(repo, message)
        assert scan.attempts == attempt
    assert (scan.status, scan.error) == (
        ScanStatus.FAILED,
        "The scan kept failing. Upload the file again later",
    )
    assert "OSV client bug" not in scan.model_dump_json()  # internals stay in the logs


def test_a_crash_then_success_on_the_next_delivery(setup):
    repo, _, _, worker, message, calls = setup
    flaky = iter([RuntimeError("timeout"), None])

    def sometimes(project_id, deps):
        error = next(flaky)
        if error:
            raise error
        return fake_pipeline(calls)(project_id, deps)

    worker.pipeline = sometimes
    with pytest.raises(RuntimeError):
        worker.handle(message)
    assert stored(repo, message).status == ScanStatus.QUEUED
    worker.handle(message)
    assert (stored(repo, message).status, stored(repo, message).attempts) == (ScanStatus.DONE, 2)


def test_a_missing_upload_fails_the_scan_without_retrying(setup):
    repo, blobs, _, worker, message, calls = setup
    blobs._data.clear()
    worker.handle(message)
    scan = stored(repo, message)
    assert (scan.status, calls) == (ScanStatus.FAILED, [])
    assert "no longer there" in scan.error


def test_a_message_for_a_scan_that_doesnt_exist_is_dropped(setup):
    _, _, _, worker, message, calls = setup
    worker.handle(message.model_copy(update={"scan_id": uuid4()}))
    worker.handle(message.model_copy(update={"owner": "mallory"}))  # can't reach alice's
    assert calls == []


def test_two_workers_racing_for_one_scan_run_it_once(setup):
    repo, blobs, clock, worker, message, calls = setup
    other = Worker(repo, blobs, fake_pipeline(calls), clock=clock)

    # Both read "queued"; the second worker's claim lands first.
    real_save = repo.save_scan
    first = {"done": False}

    def save_after_other_claims(scan, version):
        if not first["done"]:
            first["done"] = True
            other.handle(message)
        return real_save(scan, version)

    repo.save_scan = save_after_other_claims
    worker.handle(message)
    assert len(calls) == 1
    assert stored(repo, message).status == ScanStatus.DONE


def test_a_partial_scan_says_so(setup):
    repo, _, _, worker, message, _ = setup
    worker.pipeline = fake_pipeline(unchecked=1)
    worker.handle(message)
    scan = stored(repo, message)
    assert (scan.status, scan.unchecked, scan.complete) == (ScanStatus.DONE, 1, False)


def test_an_old_scan_finishing_late_does_not_replace_a_newer_one(setup):
    repo, blobs, clock, worker, message, _ = setup
    newer = Scan(
        project_id=message.project_id, owner_id="alice", filename="r.txt", format="requirements"
    )
    newer.finished_at = clock.now + timedelta(hours=1)
    repo.set_latest_scan(newer)
    worker.handle(message)  # finishes "now", before the newer one
    assert repo.latest_scan("alice", message.project_id) == newer.id


# --- Lambda handler and messages ------------------------------------------------------------


def test_lambda_reports_only_the_failed_messages(setup):
    repo, _, _, worker, message, _ = setup

    def boom(project_id, deps):
        raise RuntimeError("boom")

    worker.pipeline = boom
    handler = lambda_handler_for(worker)
    event = {
        "Records": [
            {"messageId": "m1", "body": message.model_dump_json()},
            {"messageId": "m2", "body": "not a scan message"},
            {"messageId": "m3", "body": json.dumps({"owner": "x", "project_id": "bad"})},
        ]
    }
    assert handler(event) == {"batchItemFailures": [{"itemIdentifier": "m1"}]}


@pytest.mark.parametrize(
    "body",
    [
        "",
        "[]",
        json.dumps({"owner": "a", "project_id": str(uuid4()), "scan_id": str(uuid4()), "x": 1}),
        json.dumps({"owner": "a#b", "project_id": str(uuid4()), "scan_id": str(uuid4())}),
    ],
)
def test_odd_messages_are_dropped(body):
    assert parse_message(body) is None


# --- S3 and SQS (moto) ------------------------------------------------------------------------


@pytest.fixture
def aws(aws_env):
    with mock_aws():
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket="uploads", CreateBucketConfiguration={"LocationConstraint": "eu-west-2"}
        )
        sqs = boto3.client("sqs", region_name="eu-west-2")
        url = sqs.create_queue(QueueName="scans")["QueueUrl"]
        yield s3, sqs, url


def test_s3_round_trip_with_kms_and_missing_key(aws):
    s3, _, _ = aws
    blobs = S3Blobs(s3, "uploads")
    blobs.put("uploads/a/b", b"data")
    assert blobs.get("uploads/a/b") == b"data"
    assert s3.head_object(Bucket="uploads", Key="uploads/a/b")["ServerSideEncryption"] == "aws:kms"
    assert blobs.get("uploads/nope") is None


def test_sqs_message_carries_ids_only(aws):
    _, sqs, url = aws
    message = ScanMessage(
        owner="alice", project_id=uuid4(), scan_id=uuid4(), request_id="0123456789abcdef"
    )
    SqsQueue(sqs, url).send(message)
    (received,) = sqs.receive_message(QueueUrl=url)["Messages"]
    assert set(json.loads(received["Body"])) == {"owner", "project_id", "scan_id", "request_id"}
    assert parse_message(received["Body"]) == message


def test_a_message_from_before_request_ids_still_parses():
    body = json.dumps({"owner": "alice", "project_id": str(uuid4()), "scan_id": str(uuid4())})
    assert parse_message(body).request_id is None


@pytest.mark.parametrize("bad", ["short", "x" * 65, 'a"}\n{"forged', "éééééééé", 5])
def test_a_message_with_a_bad_request_id_is_dropped(bad):
    body = {"owner": "alice", "project_id": str(uuid4()), "scan_id": str(uuid4())}
    assert parse_message(json.dumps(body | {"request_id": bad})) is None


def test_s3_and_sqs_outages_are_503():
    class Broken:
        def __getattr__(self, name):
            def call(**kwargs):
                raise EndpointConnectionError(endpoint_url="http://localhost:1")

            return call

    for call in (
        lambda: S3Blobs(Broken(), "b").put("k", b""),
        lambda: S3Blobs(Broken(), "b").get("k"),
        lambda: SqsQueue(Broken(), "u").send(
            ScanMessage(owner="a", project_id=uuid4(), scan_id=uuid4())
        ),
    ):
        with pytest.raises(ApiError) as e:
            call()
        assert e.value.status == 503


def test_local_runner_thread_runs_scans_by_itself(app, token, project, client):
    app.state.local_runner.worker.pipeline = fake_pipeline()
    with TestClient(app, headers={"Authorization": f"Bearer {token('alice')}"}) as live:
        scan = upload(live, project).json()
        for _ in range(100):
            status = live.get(f"/projects/{project}/scans/{scan['id']}").json()["status"]
            if status == "done":
                break
            time.sleep(0.05)
    assert status == "done"


def test_a_scan_whose_worker_died_three_times_is_given_up(setup):
    repo, _, clock, worker, message, calls = setup
    scan, version = repo.load_scan(message.owner, message.project_id, message.scan_id)
    # Each attempt's worker died outright, so nothing ever marked it failed.
    scan.status, scan.started_at, scan.attempts = ScanStatus.RUNNING, clock(), MAX_ATTEMPTS
    repo.save_scan(scan, version)
    clock.now += SCAN_TIMEOUT + timedelta(seconds=1)
    worker.handle(message)
    assert (stored(repo, message).status, calls) == (ScanStatus.FAILED, [])


def test_a_slow_run_that_lost_its_scan_cannot_replace_the_winners_findings(setup):
    """Review of #26: the first worker runs past SCAN_TIMEOUT, a second one takes over and
    finishes, then the first finishes too. Both write a findings file; the record and
    /findings must agree on the winner's."""
    repo, blobs, clock, worker, message, _ = setup
    takeover = Worker(repo, blobs, fake_pipeline(), clock=clock)

    def slow_then_stale(project_id, deps):
        clock.now += SCAN_TIMEOUT + timedelta(seconds=1)
        takeover.handle(message)  # attempt 2 wins and saves
        return fake_pipeline(unchecked=1)(project_id, deps)  # different answer, too late

    worker.pipeline = slow_then_stale
    worker.handle(message)

    scan = stored(repo, message)
    assert (scan.status, scan.attempts, scan.unchecked) == (ScanStatus.DONE, 2, 0)
    assert scan.findings_file.endswith("-2.json")
    assert blobs.get(scan.findings_file) is not None
    assert repo.latest_scan("alice", message.project_id) == message.scan_id


def test_lambda_skips_a_record_without_a_message_id(setup):
    _, _, _, worker, message, _ = setup

    def boom(project_id, deps):
        raise RuntimeError("boom")

    worker.pipeline = boom
    handler = lambda_handler_for(worker)
    event = {
        "Records": [
            {"body": message.model_dump_json()},  # no messageId
            {"messageId": "m2", "body": message.model_dump_json()},
        ]
    }
    assert handler(event) == {"batchItemFailures": [{"itemIdentifier": "m2"}]}
