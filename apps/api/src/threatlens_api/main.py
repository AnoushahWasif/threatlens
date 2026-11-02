import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from threatlens_api import __version__
from threatlens_api.auth import JwksKeys, LocalIssuer, TokenVerifier, dev_router
from threatlens_api.drafting import ClaudeDrafter, DraftBudget, Drafter
from threatlens_api.errors import ApiError
from threatlens_api.repository import (
    DynamoRepository,
    MemoryRepository,
    Repository,
    create_table,
    dynamodb_client,
)
from threatlens_api.routes_projects import router as projects_router
from threatlens_api.routes_threats import router as threats_router
from threatlens_api.settings import Settings, get_settings
from threatlens_api.store import ProjectStore, ThreatModelStore, WriteBudget

log = logging.getLogger("threatlens")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}


def error(status: int, code: str, message: str, request_id: str, details=None) -> JSONResponse:
    body = {"error": {"code": code, "message": message, "request_id": request_id}}
    if details:
        body["error"]["details"] = details
    return JSONResponse(status_code=status, content=body)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if isinstance(app.state.verifier.keys, JwksKeys):
            await run_in_threadpool(app.state.verifier.keys.warm)
        if settings.store == "dynamodb" and settings.dynamodb_endpoint_url:
            # DynamoDB Local starts empty. In AWS the table comes from Terraform.
            await run_in_threadpool(create_table, app.state.dynamodb, settings.dynamodb_table)
        yield

    app = FastAPI(
        lifespan=lifespan,
        title="ThreatLens API",
        version=__version__,
        # Don't publish the API map in prod.
        docs_url=None if settings.is_prod else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_prod else "/openapi.json",
    )
    app.state.settings = settings
    app.state.dynamodb = None
    repo: Repository
    if settings.store == "dynamodb":
        app.state.dynamodb = dynamodb_client(settings.aws_region, settings.dynamodb_endpoint_url)
        repo = DynamoRepository(app.state.dynamodb, settings.dynamodb_table)
    else:
        repo = MemoryRepository()
    # One budget for both, so a user can't spend it twice by switching between them.
    writes = WriteBudget(settings.write_units_per_user_per_hour)
    app.state.threat_models = ThreatModelStore(repo, budget=writes)
    app.state.projects = ProjectStore(repo, budget=writes)
    app.state.drafter = make_drafter(settings)
    app.state.draft_budget = DraftBudget(
        settings.llm_drafts_per_hour, per_user=settings.llm_drafts_per_user_per_hour
    )
    app.state.local_issuer = None
    if settings.auth_mode == "local":
        app.state.local_issuer = LocalIssuer(settings.auth_client_id)
        keys = app.state.local_issuer
    else:
        keys = JwksKeys(f"{settings.auth_issuer}/.well-known/jwks.json")
    app.state.verifier = TokenVerifier(keys, settings.auth_issuer, settings.auth_client_id)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
        expose_headers=["X-Request-ID"],
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        # Only accept a client-sent id if it looks like ours; otherwise it could inject into logs.
        incoming = request.headers.get("x-request-id", "")
        request_id = incoming if _valid_request_id(incoming) else uuid.uuid4().hex
        request.state.request_id = request_id

        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > settings.max_request_bytes:
            response = error(413, "payload_too_large", "Request body too large", request_id)
        else:
            # Caught here rather than in an exception handler: those run outside this
            # middleware, so a 500 would lose the request id and security headers.
            try:
                response = await call_next(request)
            except Exception:
                log.exception("unhandled error", extra={"request_id": request_id})
                response = error(500, "internal_error", "Something went wrong", request_id)

        response.headers["X-Request-ID"] = request_id
        response.headers.update(SECURITY_HEADERS)
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
        return error(exc.status_code, code, str(exc.detail), request.state.request_id)

    @app.exception_handler(ApiError)
    async def api_error(request: Request, exc: ApiError):
        response = error(exc.status, exc.code, exc.message, request.state.request_id)
        response.headers.update(exc.headers)
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # FastAPI's default echoes the submitted input back; keep only where and what went wrong.
        details = [{"loc": list(e["loc"]), "msg": e["msg"]} for e in exc.errors()]
        return error(422, "validation_error", "Invalid request", request.state.request_id, details)

    @app.get("/health")
    async def health():
        return {"status": "ok", "version": __version__}

    app.include_router(threats_router)
    app.include_router(projects_router)
    if app.state.local_issuer is not None:
        app.include_router(dev_router)
    return app


def make_drafter(settings: Settings) -> Drafter | None:
    if settings.llm_provider == "anthropic" and settings.llm_api_key is not None:
        return ClaudeDrafter(settings.llm_api_key.get_secret_value(), settings.llm_model)
    return None


def _valid_request_id(value: str) -> bool:
    return 8 <= len(value) <= 64 and all(c.isalnum() or c == "-" for c in value)


app = create_app()
