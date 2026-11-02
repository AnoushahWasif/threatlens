"""Both backends must follow the same rules, so every test here runs against each one.

"dynamodb" is moto locally and the real DynamoDB Local engine in CI.
"""

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from fastapi.testclient import TestClient

from threatlens_api.errors import ApiError
from threatlens_api.main import create_app
from threatlens_api.models import Project
from threatlens_api.repository import (
    Conflict,
    DynamoRepository,
    MemoryRepository,
    create_table,
)
from threatlens_api.settings import Settings
from threatlens_api.store import ProjectStore, ThreatModelStore
from threatlens_api.threats import (
    Threat,
    ThreatDraft,
    ThreatModel,
    ThreatModelCreate,
    ThreatSource,
    ThreatStatus,
    ThreatUpdate,
)

DYNAMODB_URL = os.environ.get("THREATLENS_TEST_DYNAMODB_URL")
ARCH = "A Next.js web app calls a FastAPI API on Lambda, which stores projects in DynamoDB."


class Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def __call__(self):
        return self.now


@pytest.fixture(params=["memory", "dynamodb"])
def backend(request):
    clock = Clock()
    if request.param == "memory":
        return MemoryRepository(clock=clock), clock
    client, table = request.getfixturevalue("dynamodb")
    return DynamoRepository(client, table, clock=clock), clock


@pytest.fixture
def repo(backend):
    return backend[0]


@pytest.fixture
def threaded_repo(repo):
    if isinstance(repo, DynamoRepository) and not DYNAMODB_URL:
        pytest.skip("moto isn't thread-safe; CI runs this against DynamoDB Local")
    return repo


def model(owner="alice", **overrides) -> ThreatModel:
    return ThreatModel(name="ThreatLens", architecture=ARCH, owner_id=owner, **overrides)


def threat(title="Forged session token", **overrides) -> ThreatDraft:
    return ThreatDraft(
        category="spoofing", title=title, description="Replays a stolen token.", **overrides
    )


# --- threat models -------------------------------------------------------------------


def test_round_trip_keeps_everything_but_never_stores_the_owner_in_the_body(repo):
    m = model()
    repo.create_model(m, max_per_user=5)
    loaded, version = repo.load_model("alice", m.id)
    assert (loaded, version) == (m, 1)
    assert loaded.owner_id == "alice"
    assert "alice" not in m.model_dump_json()


def test_another_users_model_is_simply_not_there(repo):
    m = model()
    repo.create_model(m, max_per_user=5)
    assert repo.load_model("bob", m.id) is None
    assert repo.load_model("alice", uuid4()) is None


def test_save_needs_the_version_it_read(repo):
    m = model()
    repo.create_model(m, max_per_user=5)
    first, v1 = repo.load_model("alice", m.id)
    second, _ = repo.load_model("alice", m.id)

    first.name = "first"
    repo.save_model(first, v1)
    second.name = "second"
    with pytest.raises(Conflict):
        repo.save_model(second, v1)  # stale: would have overwritten "first"

    loaded, v2 = repo.load_model("alice", m.id)
    assert (loaded.name, v2) == ("first", 2)


def test_save_of_a_model_that_was_never_created_is_refused(repo):
    with pytest.raises(Conflict):
        repo.save_model(model(), 1)
    assert repo.load_model("alice", model().id) is None


def test_per_user_cap_is_exact_and_per_kind(repo):
    for _ in range(3):
        repo.create_model(model(), max_per_user=3)
    with pytest.raises(ApiError) as e:
        repo.create_model(model(), max_per_user=3)
    assert (e.value.status, e.value.code) == (409, "too_many_models")
    # Other users, and projects, have their own counts.
    repo.create_model(model("bob"), max_per_user=3)
    repo.create_project("alice", Project(name="p", owner_id="alice"), max_per_user=3)


def test_cap_holds_when_creates_race(threaded_repo):
    repo = threaded_repo
    errors = []

    def create(_):
        try:
            repo.create_model(model(), max_per_user=5)
        except ApiError as e:
            errors.append(e.code)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(create, range(20)))
    created = 20 - len(errors)
    assert created == 5
    assert set(errors) <= {"too_many_models", "edit_conflict"}
    assert errors.count("too_many_models") >= 1


def test_too_large_to_store_is_refused_not_truncated(repo):
    # 4-byte characters: within the field limits, over DynamoDB's 400 KB item limit.
    big = "🔥" * 1_000
    m = model()
    repo.create_model(m, max_per_user=5)
    loaded, version = repo.load_model("alice", m.id)
    loaded.threats = [big_threat(f"T{i}", big) for i in range(100)]
    with pytest.raises(ApiError) as e:
        repo.save_model(loaded, version)
    assert (e.value.status, e.value.code) == (409, "too_large")
    assert repo.load_model("alice", m.id) == (m, 1)


def big_threat(title, text):
    return Threat(
        category="tampering",
        title=title,
        description=text,
        mitigation=text,
        status=ThreatStatus.DRAFT,
        source=ThreatSource.LLM,
    )


# --- draft lease ---------------------------------------------------------------------


def test_only_one_draft_lease_at_a_time_and_it_runs_out(backend):
    repo, clock = backend
    m = model()
    repo.create_model(m, max_per_user=5)
    first = repo.claim_draft("alice", m.id, 60)
    assert first is not None
    assert repo.claim_draft("alice", m.id, 60) is None

    # The holder died without releasing: after the lease runs out, someone else may draft.
    clock.now += 61
    second = repo.claim_draft("alice", m.id, 60)
    assert second not in (None, first)

    # The first holder waking up late must not release the second one's lease.
    repo.release_draft("alice", m.id, first)
    assert repo.claim_draft("alice", m.id, 60) is None
    repo.release_draft("alice", m.id, second)
    assert repo.claim_draft("alice", m.id, 60) is not None


def test_lease_is_per_model_and_per_owner(repo):
    a, b = model(), model()
    repo.create_model(a, max_per_user=5)
    repo.create_model(b, max_per_user=5)
    assert repo.claim_draft("alice", a.id, 60) is not None
    assert repo.claim_draft("alice", b.id, 60) is not None
    # Bob can't claim (or create) anything under alice's model id.
    assert repo.claim_draft("bob", a.id, 60) is None
    assert repo.load_model("bob", a.id) is None


def test_claim_on_a_missing_model_creates_nothing(repo):
    missing = uuid4()
    assert repo.claim_draft("alice", missing, 60) is None
    repo.release_draft("alice", missing, "whatever")
    assert repo.load_model("alice", missing) is None


def test_saving_during_a_draft_keeps_the_lease(repo):
    m = model()
    repo.create_model(m, max_per_user=5)
    lease = repo.claim_draft("alice", m.id, 60)
    loaded, version = repo.load_model("alice", m.id)
    loaded.name = "renamed while drafting"
    repo.save_model(loaded, version)
    assert repo.claim_draft("alice", m.id, 60) is None
    repo.release_draft("alice", m.id, lease)


# --- projects ------------------------------------------------------------------------


def test_projects_round_trip_and_isolation(repo):
    mine = [Project(name=f"p{i}", owner_id="alice") for i in range(3)]
    for p in mine:
        repo.create_project("alice", p, max_per_user=5)
    repo.create_project("bob", Project(name="bob's", owner_id="bob"), max_per_user=5)

    assert sorted(p.name for p in repo.list_projects("alice")) == ["p0", "p1", "p2"]
    assert repo.get_project("alice", mine[0].id) == mine[0]
    assert repo.get_project("bob", mine[0].id) is None
    assert repo.list_projects("carol") == []


def test_project_cap(repo):
    for i in range(2):
        repo.create_project("alice", Project(name=f"p{i}", owner_id="alice"), max_per_user=2)
    with pytest.raises(ApiError) as e:
        repo.create_project("alice", Project(name="p", owner_id="alice"), max_per_user=2)
    assert e.value.code == "too_many_projects"


def test_listing_follows_every_page(dynamodb):
    client, table = dynamodb

    class OnePerPage:
        """Forces DynamoDB to page after every item, as it does past 1 MB."""

        def __getattr__(self, name):
            return getattr(client, name)

        def query(self, **kwargs):
            return client.query(**kwargs, Limit=1)

    repo = DynamoRepository(OnePerPage(), table)
    for i in range(4):
        repo.create_project("alice", Project(name=f"p{i}", owner_id="alice"), max_per_user=10)
    assert len(repo.list_projects("alice")) == 4


# --- stored data that doesn't validate -------------------------------------------------


def test_corrupt_items_fail_closed(dynamodb):
    client, table = dynamodb
    repo = DynamoRepository(client, table)
    good = model()
    repo.create_model(good, max_per_user=5)
    copied_id = uuid4()

    def put(sk, body):
        client.put_item(
            TableName=table,
            Item={
                "pk": {"S": "USER#alice"},
                "sk": {"S": sk},
                "body": {"S": body},
                "ver": {"N": "1"},
            },
        )

    put(f"TM#{uuid4()}", "{not json")
    put(f"TM#{copied_id}", good.model_dump_json())  # valid model, but under another id
    put(f"PROJECT#{uuid4()}", '{"name": "x"}')

    bad_ids = [
        UUID(i["sk"]["S"][3:])
        for i in client.scan(TableName=table)["Items"]
        if i["sk"]["S"].startswith("TM#") and i["sk"]["S"] != f"TM#{good.id}"
    ]
    for model_id in bad_ids:
        with pytest.raises(RuntimeError, match="failed validation"):
            repo.load_model("alice", model_id)
    with pytest.raises(RuntimeError, match="failed validation"):
        repo.list_projects("alice")


# --- DynamoDB errors ---------------------------------------------------------------------


class Broken:
    def __init__(self, error):
        self.error = error

    def __getattr__(self, name):
        def call(**kwargs):
            raise self.error

        return call


def client_error(code):
    return ClientError({"Error": {"Code": code, "Message": "x"}}, "Query")


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (client_error("ProvisionedThroughputExceededException"), 503, "storage_busy"),
        (client_error("ThrottlingException"), 503, "storage_busy"),
        (EndpointConnectionError(endpoint_url="http://localhost:1"), 503, "storage_unavailable"),
    ],
)
@pytest.mark.parametrize(
    "call",
    [
        lambda r: r.list_projects("alice"),
        lambda r: r.load_model("alice", uuid4()),
        lambda r: r.create_model(model(), max_per_user=5),
        lambda r: r.claim_draft("alice", uuid4(), 60),
    ],
    ids=["query", "get", "transaction", "update"],
)
def test_dynamodb_trouble_is_a_503(error, status, code, call):
    with pytest.raises(ApiError) as e:
        call(DynamoRepository(Broken(error), "t"))
    assert (e.value.status, e.value.code) == (status, code)


def test_other_dynamodb_errors_are_not_hidden():
    # A wrong table name or missing permission is a bug to see in the logs, not a 503.
    with pytest.raises(ClientError):
        DynamoRepository(Broken(client_error("ResourceNotFoundException")), "t").list_projects("a")


def test_storage_outage_reaches_the_client_as_json(app, token):
    app.state.projects.repo = DynamoRepository(
        Broken(EndpointConnectionError(endpoint_url="http://localhost:1")), "t"
    )
    client = TestClient(app, headers={"Authorization": f"Bearer {token('alice')}"})
    r = client.get("/projects")
    assert (r.status_code, r.json()["error"]["code"]) == (503, "storage_unavailable")


def test_create_table_is_idempotent(dynamodb):
    client, table = dynamodb
    create_table(client, table)  # already exists: no error


def test_dynamodb_local_gets_its_table_at_startup(monkeypatch, aws_env):
    made = []
    monkeypatch.setattr("threatlens_api.main.create_table", lambda c, t: made.append(t))
    settings = Settings(
        store="dynamodb", dynamodb_endpoint_url="http://localhost:8000", _env_file=None
    )
    with TestClient(create_app(settings)):
        pass
    assert made == ["threatlens"]

    made.clear()
    with TestClient(create_app(Settings(store="dynamodb", _env_file=None))):
        pass
    assert made == []  # in AWS, Terraform owns the table


# --- store: changes that race --------------------------------------------------------------


class Interrupting:
    """A repository where someone else saves between our read and our save, `times` times."""

    def __init__(self, inner, store_factory, times):
        self.inner, self.times, self.store_factory = inner, times, store_factory
        self.saves = 0

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def save_model(self, m, version):
        self.saves += 1
        if self.times:
            self.times -= 1
            other = self.store_factory(self.inner)
            other.add_threat(m.owner_id, m.id, threat(f"Theirs {self.times}"))
        return self.inner.save_model(m, version)


def test_a_clashing_change_is_applied_again_on_the_fresh_copy(repo):
    plain = ThreatModelStore(repo)
    m = plain.create("alice", ThreatModelCreate(name="x", architecture=ARCH))
    racing = Interrupting(repo, ThreatModelStore, times=1)
    ThreatModelStore(racing).add_threat("alice", m.id, threat("Mine"))

    titles = sorted(t.title for t in plain.get("alice", m.id).threats)
    assert titles == ["Mine", "Theirs 0"]  # both kept, neither overwritten
    assert racing.saves == 2


def test_a_clash_rechecks_the_rules(repo):
    plain = ThreatModelStore(repo)
    m = plain.create("alice", ThreatModelCreate(name="x", architecture=ARCH))
    mine = plain.add_threat("alice", m.id, threat("Mine"))

    # While we rename "Mine" to "Theirs 0", someone else adds "Theirs 0". The retry sees it.
    racing = Interrupting(repo, ThreatModelStore, times=1)
    with pytest.raises(ApiError) as e:
        ThreatModelStore(racing).update_threat(
            "alice", m.id, mine.id, ThreatUpdate(title="Theirs 0")
        )
    assert e.value.code == "duplicate_threat"


def test_endless_clashes_give_up_with_409(repo):
    plain = ThreatModelStore(repo)
    m = plain.create("alice", ThreatModelCreate(name="x", architecture=ARCH))
    racing = Interrupting(repo, ThreatModelStore, times=10)
    with pytest.raises(ApiError) as e:
        ThreatModelStore(racing).add_threat("alice", m.id, threat("Mine"))
    assert (e.value.status, e.value.code) == (409, "edit_conflict")
    assert racing.saves == 3


def test_parallel_edits_all_land(threaded_repo):
    store = ThreatModelStore(threaded_repo)
    m = store.create("alice", ThreatModelCreate(name="x", architecture=ARCH))
    barrier = threading.Barrier(4)

    def add(i):
        barrier.wait()
        try:
            store.add_threat("alice", m.id, threat(f"T{i}"))
            return "ok"
        except ApiError as e:
            return e.code

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(add, range(4)))
    stored = {t.title for t in store.get("alice", m.id).threats}
    # Every success is really stored; nothing is lost to a silent overwrite.
    assert stored == {f"T{i}" for i, r in enumerate(results) if r == "ok"}
    assert set(results) <= {"ok", "edit_conflict"}


def test_project_store_lists_newest_first(repo):
    made = [
        Project(name=f"p{i}", owner_id="alice", created_at=datetime(2026, 11, i + 1, tzinfo=UTC))
        for i in (1, 0, 2)
    ]
    for p in made:
        repo.create_project("alice", p, max_per_user=5)
    store = ProjectStore(repo)
    assert [p.name for p in store.list("alice")] == ["p2", "p1", "p0"]
    with pytest.raises(ApiError) as e:
        store.get("bob", made[0].id)
    assert e.value.status == 404


def test_create_retries_a_transaction_conflict_then_gives_up(dynamodb):
    client, table = dynamodb

    class Clashing:
        def __init__(self, times):
            self.times, self.calls = times, 0

        def __getattr__(self, name):
            return getattr(client, name)

        def transact_write_items(self, **kwargs):
            self.calls += 1
            if self.times:
                self.times -= 1
                raise ClientError(
                    {
                        "Error": {"Code": "TransactionCanceledException", "Message": "x"},
                        "CancellationReasons": [{"Code": "None"}, {"Code": "TransactionConflict"}],
                    },
                    "TransactWriteItems",
                )
            return client.transact_write_items(**kwargs)

    once = Clashing(times=1)
    DynamoRepository(once, table).create_model(model(), max_per_user=5)
    assert once.calls == 2

    always = Clashing(times=10)
    with pytest.raises(ApiError) as e:
        DynamoRepository(always, table).create_model(model(), max_per_user=5)
    assert (e.value.status, e.value.code, always.calls) == (409, "edit_conflict", 3)
