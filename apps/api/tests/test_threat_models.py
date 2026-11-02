import os
from uuid import UUID

import pytest

from threatlens_api.drafting import DraftBudget, DraftError, DraftResult
from threatlens_api.main import make_drafter
from threatlens_api.settings import Settings
from threatlens_api.threats import ThreatDraft

ARCH = "A Next.js web app calls a FastAPI API on Lambda, which stores projects in DynamoDB."
MISSING = "00000000-0000-4000-8000-000000000000"
DYNAMODB_URL = os.environ.get("THREATLENS_TEST_DYNAMODB_URL")


def draft(title="Forged session token", category="spoofing"):
    return ThreatDraft(
        category=category,
        title=title,
        description="An attacker replays a stolen token.",
        mitigation="Short-lived tokens.",
    )


class FakeDrafter:
    model_name = "fake-model"

    def __init__(self, *results):
        self.results = list(results)
        self.calls = []

    async def draft(self, architecture):
        self.calls.append(architecture)
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return DraftResult(result)


@pytest.fixture
def new_model(client):
    def make(architecture=ARCH):
        r = client.post("/threat-models", json={"name": "ThreatLens", "architecture": architecture})
        assert r.status_code == 201
        return r.json()["id"]

    return make


def use(app, *results):
    fake = FakeDrafter(*results)
    app.state.drafter = fake
    return fake


def test_create_and_read(client, new_model):
    model_id = new_model()
    body = client.get(f"/threat-models/{model_id}").json()
    assert body["architecture"] == ARCH
    assert body["threats"] == []
    assert body["drafted_with"] is None


@pytest.mark.parametrize(
    "payload",
    [
        {"name": "x", "architecture": "too short"},
        {"name": "", "architecture": ARCH},
        {"name": "x", "architecture": "a" * 8_001},
        {"name": "x", "architecture": ARCH, "owner": "someone-else"},
    ],
)
def test_create_rejects_bad_input(client, payload):
    r = client.post("/threat-models", json=payload)
    assert r.status_code == 422
    assert "too short" not in r.text  # input isn't echoed back


def test_unknown_or_malformed_ids(client):
    assert client.get(f"/threat-models/{MISSING}").json()["error"]["code"] == "not_found"
    assert client.get("/threat-models/not-a-uuid").status_code == 422


def test_drafting_is_off_by_default(client, new_model):
    r = client.post(f"/threat-models/{new_model()}/draft")
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "llm_disabled"


def test_draft_stores_threats_as_drafts(app, client, new_model):
    fake = use(app, [draft(), draft("Edited scan results", "tampering")])
    model_id = new_model()
    r = client.post(f"/threat-models/{model_id}/draft")
    assert r.status_code == 200
    body = r.json()
    assert fake.calls == [ARCH]
    assert (body["added"], body["dropped"]) == (2, 0)
    assert body["model"]["drafted_with"] == "fake-model"
    assert [(t["status"], t["source"]) for t in body["model"]["threats"]] == [("draft", "llm")] * 2


def test_redraft_keeps_what_a_person_touched(app, client, new_model):
    use(
        app,
        [draft("A"), draft("B"), draft("C"), draft("D")],
        [draft("A"), draft("B"), draft("C"), draft("New")],
    )
    model_id = new_model()
    threats = client.post(f"/threat-models/{model_id}/draft").json()["model"]["threats"]
    a, b, c, _ = (t["id"] for t in threats)
    client.patch(f"/threat-models/{model_id}/threats/{a}", json={"status": "accepted"})
    client.patch(f"/threat-models/{model_id}/threats/{b}", json={"status": "rejected"})
    client.patch(f"/threat-models/{model_id}/threats/{c}", json={"mitigation": "Mine now"})
    client.post(f"/threat-models/{model_id}/threats", json=draft("Manual").model_dump())

    after = client.post(f"/threat-models/{model_id}/draft").json()["model"]["threats"]
    by_title = {t["title"]: t for t in after}
    # A, B, C were touched so they stay as they were and aren't re-added; D was untouched
    # so it's replaced; "New" arrives as a draft.
    assert sorted(by_title) == ["A", "B", "C", "Manual", "New"]
    assert by_title["A"]["status"] == "accepted"
    assert by_title["B"]["status"] == "rejected"
    assert by_title["C"]["mitigation"] == "Mine now"
    assert by_title["C"]["edited"] is True
    assert by_title["New"]["status"] == "draft"


@pytest.mark.parametrize(
    ("kind", "status", "code"),
    [
        ("refused", 422, "llm_refused"),
        ("invalid", 502, "llm_bad_output"),
        ("rate_limited", 503, "llm_busy"),
        ("upstream", 502, "llm_unavailable"),
    ],
)
def test_draft_failures_leave_the_model_unchanged(app, client, new_model, kind, status, code):
    use(app, [draft("Keep me")], DraftError(kind, "secret upstream detail"))
    model_id = new_model()
    client.post(f"/threat-models/{model_id}/draft")

    r = client.post(f"/threat-models/{model_id}/draft")
    assert r.status_code == status
    assert r.json()["error"]["code"] == code
    assert "secret" not in r.text
    assert (r.headers.get("Retry-After") == "60") == (kind == "rate_limited")
    threats = client.get(f"/threat-models/{model_id}").json()["threats"]
    assert [t["title"] for t in threats] == ["Keep me"]


def test_draft_limit(app, client, new_model):
    fake = use(app, [draft()], [draft()])
    app.state.draft_budget = DraftBudget(1)
    model_id = new_model()
    assert client.post(f"/threat-models/{model_id}/draft").status_code == 200
    r = client.post(f"/threat-models/{model_id}/draft")
    assert r.status_code == 429
    assert r.json()["error"]["code"] == "draft_limit"
    assert 0 < int(r.headers["Retry-After"]) <= 3600
    assert len(fake.calls) == 1


def test_draft_on_missing_model_costs_nothing(app, client):
    fake = use(app, [draft()])
    app.state.draft_budget = DraftBudget(1)
    assert client.post(f"/threat-models/{MISSING}/draft").status_code == 404
    assert fake.calls == []
    assert app.state.draft_budget.take() is None


def test_add_manual_threat(client, new_model):
    model_id = new_model()
    r = client.post(f"/threat-models/{model_id}/threats", json=draft().model_dump())
    assert r.status_code == 201
    assert (r.json()["status"], r.json()["source"]) == ("accepted", "manual")


@pytest.mark.parametrize(
    "payload",
    [
        {**draft().model_dump(), "category": "phishing"},
        {**draft().model_dump(), "status": "accepted"},  # status isn't set on create
        {**draft().model_dump(), "title": "x" * 121},
    ],
)
def test_add_threat_rejects_bad_input(client, new_model, payload):
    assert client.post(f"/threat-models/{new_model()}/threats", json=payload).status_code == 422


def test_update_threat(client, new_model):
    model_id = new_model()
    threat = client.post(f"/threat-models/{model_id}/threats", json=draft().model_dump()).json()
    url = f"/threat-models/{model_id}/threats/{threat['id']}"

    r = client.patch(url, json={"status": "rejected"})
    assert r.json()["status"] == "rejected"
    assert r.json()["edited"] is False  # a status change isn't an edit

    r = client.patch(url, json={"title": "Better title", "category": "repudiation"})
    assert (r.json()["title"], r.json()["category"], r.json()["edited"]) == (
        "Better title",
        "repudiation",
        True,
    )
    assert r.json()["updated_at"] > threat["updated_at"]


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"title": None},
        {"status": "approved"},
        {"title": ""},
        {"source": "llm"},  # can't relabel a manual threat as model-written
        {"id": MISSING},
    ],
)
def test_update_rejects_bad_input(client, new_model, payload):
    model_id = new_model()
    threat = client.post(f"/threat-models/{model_id}/threats", json=draft().model_dump()).json()
    r = client.patch(f"/threat-models/{model_id}/threats/{threat['id']}", json=payload)
    assert r.status_code == 422


def test_delete_threat(client, new_model):
    model_id = new_model()
    threat = client.post(f"/threat-models/{model_id}/threats", json=draft().model_dump()).json()
    url = f"/threat-models/{model_id}/threats/{threat['id']}"
    assert client.delete(url).status_code == 204
    assert client.delete(url).status_code == 404
    assert client.get(f"/threat-models/{model_id}").json()["threats"] == []


def test_threat_from_another_model_is_not_found(client, new_model):
    first, second = new_model(), new_model()
    threat = client.post(f"/threat-models/{first}/threats", json=draft().model_dump()).json()
    r = client.patch(f"/threat-models/{second}/threats/{threat['id']}", json={"title": "x"})
    assert r.status_code == 404


@pytest.mark.skipif(DYNAMODB_URL is not None, reason="the global cap is memory-store only")
def test_memory_store_has_a_global_cap(app, client, new_model):
    app.state.threat_models.repo.max_items = 1
    new_model()
    r = client.post("/threat-models", json={"name": "x", "architecture": ARCH})
    assert (r.status_code, r.json()["error"]["code"]) == (507, "storage_full")


def test_limits_on_threats(app, client, new_model):
    store = app.state.threat_models
    store.max_threats = 2
    model_id = new_model()

    for title in ("A", "B"):
        client.post(f"/threat-models/{model_id}/threats", json=draft(title).model_dump())
    r = client.post(f"/threat-models/{model_id}/threats", json=draft("C").model_dump())
    assert r.status_code == 409

    # Drafting past the cap adds nothing, and says so instead of failing silently.
    use(app, [draft("D")])
    body = client.post(f"/threat-models/{model_id}/draft").json()
    assert len(body["model"]["threats"]) == 2
    assert (body["added"], body["dropped"]) == (0, 1)


def test_make_drafter_only_when_configured():
    key = "k" * 32
    assert make_drafter(Settings(_env_file=None)) is None
    assert make_drafter(Settings(llm_api_key=key, _env_file=None)) is None  # key alone isn't "on"
    on = make_drafter(Settings(llm_provider="anthropic", llm_api_key=key, _env_file=None))
    assert on.model_name == "claude-opus-5-5"


def test_redraft_counts_repeats_of_reviewed_threats_as_dropped(app, client, new_model):
    use(app, [draft("A"), draft("B")], [draft("A"), draft("B"), draft("C")])
    model_id = new_model()
    first = client.post(f"/threat-models/{model_id}/draft").json()["model"]["threats"]
    client.patch(f"/threat-models/{model_id}/threats/{first[0]['id']}", json={"status": "accepted"})
    body = client.post(f"/threat-models/{model_id}/draft").json()
    # "A" is accepted so its repeat is skipped; "B" was untouched so it's replaced.
    assert (body["added"], body["dropped"]) == (2, 1)


def test_second_draft_while_one_is_running_is_refused(app, client, new_model):
    model_id = new_model()
    store = app.state.threat_models
    other = new_model()

    class Slow(FakeDrafter):
        nested = None

        async def draft(self, architecture):
            if self.nested is None:
                # While this LLM call is still out, the same model is asked again, and so is
                # another model. Only the first call does this, so the requests don't recurse.
                self.nested = (
                    client.post(f"/threat-models/{model_id}/draft"),
                    client.post(f"/threat-models/{other}/draft"),
                )
            return await super().draft(architecture)

    slow = Slow([draft("A")], [draft("B")], DraftError("upstream"), [draft("C")])
    app.state.drafter = slow
    assert client.post(f"/threat-models/{model_id}/draft").status_code == 200
    same, different = slow.nested
    assert same.status_code == 409
    assert same.json()["error"]["code"] == "draft_in_progress"
    assert different.status_code == 200
    assert len(slow.calls) == 2  # the refused request never reached the LLM

    # The guard is released afterwards, after a failure too.
    assert client.post(f"/threat-models/{model_id}/draft").status_code == 502
    assert len(store.get("local-alice", UUID(model_id)).threats) == 1
    assert client.post(f"/threat-models/{model_id}/draft").status_code == 200


@pytest.mark.parametrize(
    ("second", "patch"),
    [
        (("Other", "spoofing"), {"title": "forged session token"}),  # rename onto it
        (("Forged session token", "tampering"), {"category": "spoofing"}),  # move onto it
    ],
)
def test_edit_cannot_create_a_duplicate(client, new_model, second, patch):
    model_id = new_model()
    url = f"/threat-models/{model_id}/threats"
    client.post(url, json=draft().model_dump())
    second = client.post(url, json=draft(*second).model_dump()).json()
    r = client.patch(f"{url}/{second['id']}", json=patch)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "duplicate_threat"


def test_duplicate_check_ignores_the_threat_itself_and_other_categories(client, new_model):
    model_id = new_model()
    url = f"/threat-models/{model_id}/threats"
    threat = client.post(url, json=draft().model_dump()).json()
    # Same title, different case, on itself: fine.
    assert (
        client.patch(f"{url}/{threat['id']}", json={"title": "FORGED SESSION TOKEN"}).status_code
        == 200
    )
    # Same title in another category: a different threat.
    assert (
        client.post(url, json=draft("Forged session token", "tampering").model_dump()).status_code
        == 201
    )


def test_adding_a_duplicate_by_hand_is_refused(client, new_model):
    model_id = new_model()
    url = f"/threat-models/{model_id}/threats"
    assert client.post(url, json=draft().model_dump()).status_code == 201
    r = client.post(url, json=draft("  Forged Session Token  ").model_dump())
    assert r.json()["error"]["code"] == "duplicate_threat"
