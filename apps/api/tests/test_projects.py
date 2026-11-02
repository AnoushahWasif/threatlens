import pytest

MISSING = "00000000-0000-4000-8000-000000000000"


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_create_list_and_get(client):
    first = client.post("/projects", json={"name": "  shop api  ", "description": "lockfile"})
    assert first.status_code == 201
    body = first.json()
    assert body["name"] == "shop api"
    assert set(body) == {"id", "name", "description", "created_at"}  # no owner_id

    client.post("/projects", json={"name": "web"})
    listed = client.get("/projects").json()
    assert [p["name"] for p in listed] == ["web", "shop api"]
    assert client.get(f"/projects/{body['id']}").json() == body


def test_projects_are_private(client, anon, token):
    project = client.post("/projects", json={"name": "alice's"}).json()
    bob = bearer(token("bob"))
    assert anon.get("/projects", headers=bob).json() == []
    r = anon.get(f"/projects/{project['id']}", headers=bob)
    # Same answer as a project that doesn't exist, so ids can't be probed.
    missing = client.get(f"/projects/{MISSING}")
    assert (r.status_code, r.json()["error"]["code"]) == (404, "not_found")
    assert r.json()["error"]["message"] == missing.json()["error"]["message"]


@pytest.mark.parametrize("path", ["/projects", f"/projects/{MISSING}"])
def test_projects_need_sign_in(anon, path):
    assert anon.get(path).status_code == 401
    assert anon.post("/projects", json={"name": "x"}).status_code == 401


@pytest.mark.parametrize(
    "body",
    [
        {"name": ""},
        {"name": "x" * 101},
        {"name": "x", "description": "d" * 5_001},
        {"name": "x", "owner_id": "bob"},  # can't create a project for someone else
        {"name": "x", "id": MISSING},  # or choose its id
        {},
    ],
)
def test_project_input_is_checked(client, body):
    assert client.post("/projects", json=body).status_code == 422


def test_bad_project_id_is_422_not_500(client):
    assert client.get("/projects/not-a-uuid").status_code == 422


def test_project_cap(app, client):
    app.state.projects.max_per_user = 2
    for _ in range(2):
        assert client.post("/projects", json={"name": "p"}).status_code == 201
    r = client.post("/projects", json={"name": "p"})
    assert (r.status_code, r.json()["error"]["code"]) == (409, "too_many_projects")
