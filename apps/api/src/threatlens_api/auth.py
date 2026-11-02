"""Bearer-token auth. The user id always comes from a verified token, never from the request.

Production uses Cognito access tokens, checked against the user pool's published keys.
Development uses a local stand-in issuer with a key that exists only in this process, so
the API runs the same checks in both places.
"""

import json
import logging
import math
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Protocol

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import APIRouter, Depends, Request
from pydantic import Field

from threatlens_api.errors import ApiError
from threatlens_api.models import Strict

ALGORITHM = "RS256"
LEEWAY_SECONDS = 30
MAX_TOKEN_LENGTH = 8_192
LOCAL_ISSUER = "threatlens-local"
LOCAL_TOKEN_SECONDS = 3_600
JWKS_RETRY_SECONDS = 30
_SUBJECT = re.compile(r"^[A-Za-z0-9._:@-]{1,128}$")

log = logging.getLogger("threatlens")


@dataclass(frozen=True)
class User:
    id: str
    username: str


def _unauthorized(code: str, message: str) -> ApiError:
    challenge = "Bearer" if code == "auth_required" else 'Bearer error="invalid_token"'
    return ApiError(401, code, message, headers={"WWW-Authenticate": challenge})


def invalid_token() -> ApiError:
    # One message for every reason, so a caller can't learn which check failed.
    return _unauthorized("invalid_token", "The access token is missing, expired or not valid")


class KeySource(Protocol):
    def signing_key(self, token: str): ...


class _FailFastJWKClient(jwt.PyJWKClient):
    """After a failed fetch, fails straight away for a while instead of waiting the full
    timeout again on every request. Keys already cached keep working meanwhile."""

    def __init__(self, url: str, clock: Callable[[], float]):
        super().__init__(url, cache_keys=True, lifespan=3_600, timeout=5)
        self._clock = clock
        self.down_until = 0.0

    def fetch_data(self):
        if self._clock() < self.down_until:
            raise jwt.PyJWKClientConnectionError("JWKS fetch failed recently")
        try:
            return super().fetch_data()
        except (jwt.PyJWTError, json.JSONDecodeError) as e:
            self.down_until = self._clock() + JWKS_RETRY_SECONDS
            raise jwt.PyJWKClientConnectionError("JWKS fetch failed") from e


class JwksKeys:
    """Cognito's public keys, fetched from the pool's JWKS URL and cached.

    The fetch is blocking, so callers must run it off the event loop.
    """

    def __init__(self, url: str, *, clock: Callable[[], float] = time.monotonic):
        self._client = _FailFastJWKClient(url, clock)
        self._clock = clock

    def signing_key(self, token: str):
        try:
            return self._client.get_signing_key_from_jwt(token).key
        # A garbled key set is Cognito's fault, not the token's, so it's a 503 too.
        except (jwt.PyJWKClientConnectionError, jwt.PyJWKSetError) as e:
            wait = max(self._client.down_until - self._clock(), 1)
            raise _unavailable(wait) from e
        except (jwt.PyJWKClientError, jwt.DecodeError) as e:
            raise invalid_token() from e

    def warm(self) -> bool:
        """Fetches the keys at startup so the first sign-in doesn't wait. Never raises."""
        try:
            self._client.get_signing_keys()
        except jwt.PyJWTError:
            log.warning("couldn't fetch Cognito signing keys at startup; will retry on use")
            return False
        return True


def _unavailable(wait: float) -> ApiError:
    return ApiError(
        503,
        "auth_unavailable",
        "Can't check sign-ins right now",
        headers={"Retry-After": str(max(1, math.ceil(wait)))},
    )


class LocalIssuer:
    """Dev-only stand-in for Cognito. The private key is made at startup and never stored."""

    def __init__(self, client_id: str):
        self.client_id = client_id
        self.kid = secrets.token_hex(8)
        self._key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)

    def signing_key(self, token: str):
        if jwt.get_unverified_header(token).get("kid") != self.kid:
            raise invalid_token()
        return self._key.public_key()

    def issue(self, username: str, *, now: float | None = None, **overrides) -> str:
        """An access token shaped like Cognito's. `overrides` lets tests build bad ones."""
        issued = int(now if now is not None else time.time())
        claims = {
            "sub": f"local-{username}",
            "username": username,
            "iss": LOCAL_ISSUER,
            "client_id": self.client_id,
            "token_use": "access",
            "iat": issued,
            "exp": issued + LOCAL_TOKEN_SECONDS,
            **overrides,
        }
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, self._key, algorithm=ALGORITHM, headers={"kid": self.kid})


class TokenVerifier:
    def __init__(self, keys: KeySource, issuer: str, client_id: str):
        self.keys = keys
        self.issuer = issuer
        self.client_id = client_id

    def verify(self, token: str) -> User:
        try:
            # Checked before any key lookup: "none" and HS256 (signed with the public key
            # as a shared secret) are the classic ways to forge a token.
            if jwt.get_unverified_header(token).get("alg") != ALGORITHM:
                raise invalid_token()
            claims = jwt.decode(
                token,
                self.keys.signing_key(token),
                algorithms=[ALGORITHM],
                issuer=self.issuer,
                leeway=LEEWAY_SECONDS,
                # Cognito access tokens carry client_id instead of aud; checked below.
                options={
                    "require": ["exp", "iat", "iss", "sub", "token_use", "client_id"],
                    "verify_aud": False,
                },
            )
        except jwt.PyJWTError as e:
            raise invalid_token() from e

        # An ID token, or a token for another app client of the same pool, is not ours.
        token_use = claims["token_use"]
        if token_use != "access" or claims["client_id"] != self.client_id:  # noqa: S105 claim value
            raise invalid_token()
        sub = claims["sub"]
        if not isinstance(sub, str) or not _SUBJECT.match(sub):
            raise invalid_token()
        username = claims.get("username")
        if not isinstance(username, str) or not 0 < len(username) <= 128:
            username = sub
        return User(id=sub, username=username)


# A plain def on purpose: FastAPI runs it in the threadpool, so a JWKS fetch on a cache
# miss doesn't stall the event loop (and every other request with it).
def current_user(request: Request) -> User:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        raise _unauthorized("auth_required", "Sign in to use this API")
    if len(token) > MAX_TOKEN_LENGTH:
        raise invalid_token()
    return request.app.state.verifier.verify(token)


CurrentUser = Annotated[User, Depends(current_user)]


class LocalTokenRequest(Strict):
    username: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,31}$")


# Mounted only when THREATLENS_AUTH_MODE=local, which the settings refuse in prod.
dev_router = APIRouter(prefix="/dev", tags=["dev"])


@dev_router.post("/token")
async def local_token(body: LocalTokenRequest, request: Request) -> dict:
    issuer: LocalIssuer = request.app.state.local_issuer
    return {
        "access_token": issuer.issue(body.username),
        "token_type": "Bearer",
        "expires_in": LOCAL_TOKEN_SECONDS,
    }
