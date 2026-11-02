import logging
import math
from uuid import UUID

from fastapi import APIRouter, Request, Response
from fastapi.concurrency import run_in_threadpool

from threatlens_api.auth import CurrentUser, User
from threatlens_api.drafting import Drafter, DraftError
from threatlens_api.errors import ApiError
from threatlens_api.models import Strict
from threatlens_api.store import ThreatModelStore
from threatlens_api.threats import Threat, ThreatDraft, ThreatModel, ThreatModelCreate, ThreatUpdate

log = logging.getLogger("threatlens")

router = APIRouter(prefix="/threat-models", tags=["threat models"])

DRAFT_ERRORS = {
    "refused": (422, "llm_refused", "The model declined to draft this; write the threats by hand"),
    "invalid": (502, "llm_bad_output", "The model's answer wasn't a usable threat model"),
    "rate_limited": (503, "llm_busy", "The LLM provider is busy; try again in a minute"),
    "upstream": (502, "llm_unavailable", "Couldn't reach the LLM provider"),
}


class DraftResponse(Strict):
    model: ThreatModel
    # New drafts stored, and drafts skipped (unusable, repeats, or no room left in the model).
    added: int
    dropped: int


def _store(request: Request) -> ThreatModelStore:
    return request.app.state.threat_models


@router.post("", status_code=201)
def create_threat_model(
    body: ThreatModelCreate, user: CurrentUser, request: Request
) -> ThreatModel:
    return _store(request).create(user.id, body)


@router.get("/{model_id}")
def get_threat_model(model_id: UUID, user: CurrentUser, request: Request) -> ThreatModel:
    return _store(request).get(user.id, model_id)


# Store routes are plain defs, which FastAPI runs in its threadpool, because the DynamoDB
# client blocks. This one awaits the LLM, so its store calls go to the threadpool by hand.
@router.post("/{model_id}/draft")
async def draft_threats(model_id: UUID, user: CurrentUser, request: Request) -> DraftResponse:
    store = _store(request)
    model = await run_in_threadpool(store.get, user.id, model_id)
    drafter = request.app.state.drafter
    if drafter is None:
        raise ApiError(503, "llm_disabled", "Threat drafting is turned off on this server")

    # A lease on the stored item, so it holds across API instances and runs out if the
    # process holding it dies.
    lease = await run_in_threadpool(store.claim_draft, user.id, model_id)
    try:
        return await _draft(store, user, model, drafter, request)
    finally:
        await run_in_threadpool(store.release_draft, user.id, model_id, lease)


async def _draft(
    store: ThreatModelStore, user: User, model: ThreatModel, drafter: Drafter, request: Request
) -> DraftResponse:
    model_id = model.id

    # Counted before the call: a failed call can still be billed.
    wait = request.app.state.draft_budget.take(user.id)
    if wait is not None:
        raise ApiError(
            429,
            "draft_limit",
            "Too many drafts this hour",
            headers={"Retry-After": str(math.ceil(wait))},
        )

    try:
        result = await drafter.draft(model.architecture)
    except DraftError as e:
        # Log the kind only: the architecture text is the user's and stays out of logs.
        log.warning("threat draft failed", extra={"kind": e.kind, "model_id": str(model_id)})
        status, code, message = DRAFT_ERRORS[e.kind]
        headers = {"Retry-After": "60"} if e.kind == "rate_limited" else None
        raise ApiError(status, code, message, headers=headers) from e

    updated, added = await run_in_threadpool(
        store.replace_drafts, user.id, model_id, result.threats, drafter.model_name
    )
    return DraftResponse(
        model=updated, added=added, dropped=result.dropped + len(result.threats) - added
    )


@router.post("/{model_id}/threats", status_code=201)
def add_threat(model_id: UUID, body: ThreatDraft, user: CurrentUser, request: Request) -> Threat:
    return _store(request).add_threat(user.id, model_id, body)


@router.patch("/{model_id}/threats/{threat_id}")
def update_threat(
    model_id: UUID, threat_id: UUID, body: ThreatUpdate, user: CurrentUser, request: Request
) -> Threat:
    return _store(request).update_threat(user.id, model_id, threat_id, body)


@router.delete("/{model_id}/threats/{threat_id}", status_code=204)
def delete_threat(model_id: UUID, threat_id: UUID, user: CurrentUser, request: Request) -> Response:
    _store(request).delete_threat(user.id, model_id, threat_id)
    return Response(status_code=204)
