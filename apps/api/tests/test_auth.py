import base64
import hashlib
import hmac
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from threatlens_api.auth import LOCAL_ISSUER
from threatlens_api.drafting import DraftBudget, DraftResult
from threatlens_api.main import create_app
from threatlens_api.settings import Settings
from threatlens_api.threats import ThreatDraft

ARCH = "A Next.js web app calls a FastAPI API on Lambda, which stores projects in DynamoDB."
MODEL = {"name": "ThreatLens", "architecture": ARCH}


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def error_code(r) -> str:
    return r.json()["error"]["code"]


# --- token checks -------------------------------------------------------------


def test_health_needs_no_token(anon):
    assert anon.get("/health").status_code == 200


@pytest.mark.parametrize(
    "header",
    [None, "", "Bearer", "Bearer ", "Basic dXNlcjpwYXNz", "token abc"],
)
def test_missing_token_is_401_with_a_challenge(anon, header):
    headers = {} if header is None else {"Authorization": header}
    r = anon.get("/threat-models/00000000-0000-4000-8000-000000000000", headers=headers)
    assert r.status_code == 401
    assert error_code(r) == "auth_required"
    assert r.headers["WWW-Authenticate"] == "Bearer"


def test_valid_token_works_and_scheme_is_case_insensitive(anon, token):
    r = anon.post("/threat-models", json=MODEL, headers={"Authorization": f"bearer {token('a')}"})
    assert r.status_code == 201
    assert "owner_id" not in r.json()  # the owner is never sent back


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64json(data: dict) -> str:
    return _b64(json.dumps(data).encode())


def _forged(app, **claims):
    """A token with valid structure, signed by a key the API doesn't trust."""
    other = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    now = int(time.time())
    body = {
        "sub": "local-mallory",
        "iss": LOCAL_ISSUER,
        "client_id": "threatlens-local",
        "token_use": "access",
        "iat": now,
        "exp": now + 600,
        **claims,
    }
    return jwt.encode(body, other, algorithm="RS256", headers={"kid": app.state.local_issuer.kid})


def _hs256_with_public_key(app):
    # The classic confusion attack: sign HS256 with the server's *public* key as the secret.
    public = app.state.local_issuer._key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    now = int(time.time())
    claims = {
        "sub": "local-mallory",
        "iss": LOCAL_ISSUER,
        "client_id": "threatlens-local",
        "token_use": "access",
        "iat": now,
        "exp": now + 600,
    }
    header = {"alg": "HS256", "typ": "JWT", "kid": app.state.local_issuer.kid}
    signing_input = f"{_b64json(header)}.{_b64json(claims)}"
    signature = hmac.new(public, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64(signature)}"


def _alg_none(app):
    now = int(time.time())
    claims = {
        "sub": "local-mallory",
        "iss": LOCAL_ISSUER,
        "client_id": "threatlens-local",
        "token_use": "access",
        "iat": now,
        "exp": now + 600,
    }
    return f"{_b64json({'alg': 'none', 'kid': app.state.local_issuer.kid})}.{_b64json(claims)}."


BAD_TOKENS = {
    "expired": lambda app, t: t("alice", now=time.time() - 7_200),
    "issued in the future": lambda app, t: t("alice", iat=int(time.time()) + 3_600),
    "wrong issuer": lambda app, t: t("alice", iss="https://evil.example"),
    "other app client": lambda app, t: t("alice", client_id="someone-elses-app"),
    "id token, not access": lambda app, t: t("alice", token_use="id"),
    "no sub": lambda app, t: t("alice", sub=None),
    "no exp": lambda app, t: t("alice", exp=None),
    "odd sub": lambda app, t: t("alice", sub="alice\nadmin"),
    "non-string sub": lambda app, t: t("alice", sub=12345),
    "signed by another key": lambda app, t: _forged(app),
    "unknown kid": lambda app, t: jwt.encode(
        {"sub": "x"}, app.state.local_issuer._key, algorithm="RS256", headers={"kid": "nope"}
    ),
    "alg none": lambda app, t: _alg_none(app),
    "HS256 with the public key": lambda app, t: _hs256_with_public_key(app),
    "tampered payload": lambda app, t: (lambda p: f"{p[0]}.{p[1][:-4]}AAAA.{p[2]}")(
        t("alice").split(".")
    ),
    "garbage": lambda app, t: "not-a-jwt",
    "too long": lambda app, t: "a" * 9_000,
}


@pytest.mark.parametrize("case", list(BAD_TOKENS))
def test_bad_tokens_are_all_rejected_the_same_way(app, anon, token, case):
    bad = BAD_TOKENS[case](app, token)
    r = anon.post("/threat-models", json=MODEL, headers=bearer(bad))
    assert r.status_code == 401, case
    assert error_code(r) == "invalid_token"
    assert r.json()["error"]["message"] == "The access token is missing, expired or not valid"
    assert r.headers["WWW-Authenticate"] == 'Bearer error="invalid_token"'


def test_a_little_clock_skew_is_allowed(anon, token):
    slightly_late = token("alice", now=time.time() - 3_600 - 10)  # expired 10 s ago
    assert anon.post("/threat-models", json=MODEL, headers=bearer(slightly_late)).status_code == 201


def test_tokens_from_another_api_process_are_rejected(anon):
    # Each process makes its own local key, so a token from another one doesn't carry over.
    other = create_app(Settings(environment="test", _env_file=None))
    stranger = other.state.local_issuer.issue("alice")
    assert anon.post("/threat-models", json=MODEL, headers=bearer(stranger)).status_code == 401


# --- ownership ----------------------------------------------------------------


def test_other_users_models_look_missing(client, anon, token):
    model = client.post("/threat-models", json=MODEL).json()
    threat = client.post(
        f"/threat-models/{model['id']}/threats",
        json={"category": "spoofing", "title": "T", "description": "D"},
    ).json()
    bob = bearer(token("bob"))
    missing = anon.get("/threat-models/00000000-0000-4000-8000-000000000000", headers=bob)

    calls = [
        ("get", f"/threat-models/{model['id']}", None),
        ("post", f"/threat-models/{model['id']}/draft", None),
        (
            "post",
            f"/threat-models/{model['id']}/threats",
            {"category": "spoofing", "title": "X", "description": "D"},
        ),
        ("patch", f"/threat-models/{model['id']}/threats/{threat['id']}", {"status": "rejected"}),
        ("delete", f"/threat-models/{model['id']}/threats/{threat['id']}", None),
    ]
    for method, url, body in calls:
        kwargs = {"headers": bob, **({"json": body} if body else {})}
        r = getattr(anon, method)(url, **kwargs)
        assert r.status_code == 404, (method, url)
        # Same body as a model that doesn't exist at all, apart from the request id.
        assert error_code(r) == error_code(missing) == "not_found"
        assert r.json()["error"]["message"] == missing.json()["error"]["message"]

    # And alice's threat is untouched.
    assert client.get(f"/threat-models/{model['id']}").json()["threats"][0]["status"] == "accepted"


def test_cant_claim_a_model_for_someone_else(client):
    r = client.post("/threat-models", json={**MODEL, "owner_id": "local-bob"})
    assert r.status_code == 422


def test_per_user_model_cap(app, client, anon, token):
    app.state.threat_models.max_per_user = 2
    for _ in range(2):
        assert client.post("/threat-models", json=MODEL).status_code == 201
    r = client.post("/threat-models", json=MODEL)
    assert (r.status_code, error_code(r)) == (409, "too_many_models")
    # Bob isn't affected by alice hitting her cap.
    assert anon.post("/threat-models", json=MODEL, headers=bearer(token("bob"))).status_code == 201


class OneThreat:
    model_name = "fake"

    async def draft(self, architecture):
        return DraftResult([ThreatDraft(category="spoofing", title="T", description="D")])


def test_per_user_draft_budget(app, client, anon, token):
    app.state.drafter = OneThreat()
    app.state.draft_budget = DraftBudget(per_hour=10, per_user=1)
    alice_model = client.post("/threat-models", json=MODEL).json()["id"]
    bob = bearer(token("bob"))
    bob_model = anon.post("/threat-models", json=MODEL, headers=bob).json()["id"]

    assert client.post(f"/threat-models/{alice_model}/draft").status_code == 200
    r = client.post(f"/threat-models/{alice_model}/draft")
    assert (r.status_code, error_code(r)) == (429, "draft_limit")
    assert anon.post(f"/threat-models/{bob_model}/draft", headers=bob).status_code == 200


def test_budget_global_cap_still_applies_across_users():
    clock = [0.0]
    budget = DraftBudget(per_hour=2, per_user=5, now=lambda: clock[0])
    assert budget.take("a") is None
    assert budget.take("b") is None
    assert budget.take("c") is not None


def test_budget_forgets_idle_users_when_it_gets_big():
    clock = [0.0]
    budget = DraftBudget(per_hour=100_000, per_user=1, now=lambda: clock[0])
    for i in range(10_001):
        budget.take(f"user-{i}")
    clock[0] = 4_000
    budget.take("new")
    assert len(budget._by_user) == 1


# --- local token route --------------------------------------------------------


def test_dev_token_route(anon):
    r = anon.post("/dev/token", json={"username": "alice"})
    assert r.status_code == 200
    body = r.json()
    assert (body["token_type"], body["expires_in"]) == ("Bearer", 3_600)
    created = anon.post("/threat-models", json=MODEL, headers=bearer(body["access_token"]))
    assert created.status_code == 201


@pytest.mark.parametrize("username", ["", "Alice", "a b", "../admin", "x" * 33, "-lead"])
def test_dev_token_route_checks_the_username(anon, username):
    assert anon.post("/dev/token", json={"username": username}).status_code == 422


def cognito_settings(**overrides):
    values = {
        "environment": "test",
        "auth_mode": "cognito",
        "cognito_region": "eu-west-2",
        "cognito_user_pool_id": "eu-west-2_AbC123",
        "auth_client_id": "abc123client",
    }
    return Settings(**{**values, **overrides}, _env_file=None)


def test_no_dev_token_route_with_cognito():
    anon = TestClient(create_app(cognito_settings()), raise_server_exceptions=False)
    assert anon.post("/dev/token", json={"username": "alice"}).status_code == 404


# --- Cognito keys (JWKS), with the network call replaced -----------------------


ISSUER = "https://cognito-idp.eu-west-2.amazonaws.com/eu-west-2_AbC123"


@pytest.fixture
def pool_key():
    return rsa.generate_private_key(public_exponent=65_537, key_size=2_048)


@pytest.fixture
def cognito(monkeypatch, pool_key):
    app = create_app(cognito_settings())
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(pool_key.public_key(), as_dict=True)
    jwks = {"keys": [{**jwk, "kid": "pool-key-1", "alg": "RS256", "use": "sig"}]}
    calls = []

    def fetch():
        calls.append(1)
        return jwks

    monkeypatch.setattr(app.state.verifier.keys._client, "fetch_data", fetch)
    return TestClient(app, raise_server_exceptions=False), calls


def cognito_token(key, kid="pool-key-1", **overrides):
    now = int(time.time())
    claims = {
        "sub": "0b8f6a52-3c1d-4e9a-8f27-6d5c4b3a2e10",
        "username": "anoushah",
        "iss": ISSUER,
        "client_id": "abc123client",
        "token_use": "access",
        "scope": "openid email",
        "iat": now,
        "exp": now + 3_600,
        **overrides,
    }
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


def test_cognito_access_token_is_accepted_and_keys_are_cached(cognito, pool_key):
    client, calls = cognito
    for _ in range(3):
        r = client.post("/threat-models", json=MODEL, headers=bearer(cognito_token(pool_key)))
        assert r.status_code == 201
    assert len(calls) == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://cognito-idp.eu-west-2.amazonaws.com/eu-west-2_Other"},
        {"client_id": "another-client"},
        {"token_use": "id"},
        {"kid": "rotated-away"},
    ],
)
def test_cognito_rejects_tokens_not_for_us(cognito, pool_key, overrides):
    client, _ = cognito
    kid = overrides.pop("kid", "pool-key-1")
    r = client.post(
        "/threat-models", json=MODEL, headers=bearer(cognito_token(pool_key, kid, **overrides))
    )
    assert (r.status_code, error_code(r)) == (401, "invalid_token")


def test_cognito_keys_unreachable_is_503_not_401(monkeypatch, pool_key):
    app = create_app(cognito_settings())

    def down():
        raise jwt.PyJWKClientConnectionError("timed out")

    monkeypatch.setattr(app.state.verifier.keys._client, "fetch_data", down)
    client = TestClient(app, raise_server_exceptions=False)
    r = client.post("/threat-models", json=MODEL, headers=bearer(cognito_token(pool_key)))
    assert (r.status_code, error_code(r)) == (503, "auth_unavailable")
