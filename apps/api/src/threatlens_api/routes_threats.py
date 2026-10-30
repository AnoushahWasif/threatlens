import logging
import math
from uuid import UUID

from fastapi import APIRouter, Request, Response

from threatlens_api.drafting import DraftError
from threatlens_api.errors import ApiError
from threatlens_api.store import ThreatModelStore
from threatlens_api.threats import Threat, ThreatDraft, ThreatModel, ThreatModelCreate, ThreatUpdate

log = logging.getLogger("threatlens")

# Auth and per-user ownership arrive on day 12; until then this API is local-only.
router = APIRouter(prefix="/threat-models", tags=["threat models"])

DRAFT_ERRORS = {
    "refused": (422, "llm_refused", "The model declined to draft this; write the threats by hand"),
    "invalid": (502, "llm_bad_output", "The model's answer wasn't a usable threat model"),
    "rate_limited": (503, "llm_busy", "The LLM provider is busy; try again in a minute"),
    "upstream": (502, "llm_unavailable", "Couldn't reach the LLM provider"),
}


def _store(request: Request) -> ThreatModelStore:
    return request.app.state.threat_models


@router.post("", status_code=201)
async def create_threat_model(body: ThreatModelCreate, request: Request) -> ThreatModel:
    return _store(request).create(body)


@router.get("/{model_id}")
async def get_threat_model(model_id: UUID, request: Request) -> ThreatModel:
    return _store(request).get(model_id)


@router.post("/{model_id}/draft")
async def draft_threats(model_id: UUID, request: Request) -> ThreatModel:
    store = _store(request)
    model = store.get(model_id)
    drafter = request.app.state.drafter
    if drafter is None:
        raise ApiError(503, "llm_disabled", "Threat drafting is turned off on this server")

    # Counted before the call: a failed call can still be billed.
    wait = request.app.state.draft_budget.take()
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

    store.replace_drafts(model_id, result.threats, drafter.model_name)
    return store.get(model_id)


@router.post("/{model_id}/threats", status_code=201)
async def add_threat(model_id: UUID, body: ThreatDraft, request: Request) -> Threat:
    return _store(request).add_threat(model_id, body)


@router.patch("/{model_id}/threats/{threat_id}")
async def update_threat(
    model_id: UUID, threat_id: UUID, body: ThreatUpdate, request: Request
) -> Threat:
    return _store(request).update_threat(model_id, threat_id, body)


@router.delete("/{model_id}/threats/{threat_id}", status_code=204)
async def delete_threat(model_id: UUID, threat_id: UUID, request: Request) -> Response:
    _store(request).delete_threat(model_id, threat_id)
    return Response(status_code=204)
