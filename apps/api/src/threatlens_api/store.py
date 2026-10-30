"""In-memory threat model store. Day 13 swaps this for DynamoDB behind the same methods."""

from uuid import UUID

from threatlens_api.errors import ApiError
from threatlens_api.models import _now
from threatlens_api.threats import (
    Threat,
    ThreatDraft,
    ThreatModel,
    ThreatModelCreate,
    ThreatSource,
    ThreatStatus,
    ThreatUpdate,
)

MAX_MODELS = 500
MAX_THREATS_PER_MODEL = 100
TEXT_FIELDS = {"category", "title", "description", "mitigation", "component"}


def _key(t: ThreatDraft) -> tuple[str, str]:
    return (t.category, t.title.casefold())


class ThreatModelStore:
    def __init__(self, max_models: int = MAX_MODELS, max_threats: int = MAX_THREATS_PER_MODEL):
        self._models: dict[UUID, ThreatModel] = {}
        self.max_models = max_models
        self.max_threats = max_threats

    def create(self, data: ThreatModelCreate) -> ThreatModel:
        if len(self._models) >= self.max_models:
            raise ApiError(507, "storage_full", "No room for more threat models")
        model = ThreatModel(**data.model_dump())
        self._models[model.id] = model
        return model

    def get(self, model_id: UUID) -> ThreatModel:
        model = self._models.get(model_id)
        if model is None:
            raise ApiError(404, "not_found", "Threat model not found")
        return model

    def replace_drafts(self, model_id: UUID, drafts: list[ThreatDraft], drafted_with: str) -> int:
        """Swap untouched LLM drafts for new ones. Returns how many new drafts were added.

        Anything a person has accepted, rejected, edited or written stays, and a new draft
        that repeats one of those is skipped.
        """
        model = self.get(model_id)
        kept = [
            t
            for t in model.threats
            if not (
                t.source == ThreatSource.LLM and t.status == ThreatStatus.DRAFT and not t.edited
            )
        ]
        seen = {_key(t) for t in kept}
        added = []
        for draft in drafts:
            if _key(draft) in seen or len(kept) + len(added) >= self.max_threats:
                continue
            seen.add(_key(draft))
            added.append(
                Threat(**draft.model_dump(), status=ThreatStatus.DRAFT, source=ThreatSource.LLM)
            )
        model.threats = kept + added
        model.drafted_with = drafted_with
        model.drafted_at = _now()
        return len(added)

    def add_threat(self, model_id: UUID, draft: ThreatDraft) -> Threat:
        model = self.get(model_id)
        if len(model.threats) >= self.max_threats:
            raise ApiError(409, "too_many_threats", f"A model can hold {self.max_threats} threats")
        # Written by a person, so it needs no review.
        threat = Threat(
            **draft.model_dump(), status=ThreatStatus.ACCEPTED, source=ThreatSource.MANUAL
        )
        model.threats.append(threat)
        return threat

    def update_threat(self, model_id: UUID, threat_id: UUID, update: ThreatUpdate) -> Threat:
        model = self.get(model_id)
        index, threat = self._find(model, threat_id)
        changes = update.model_dump(exclude_unset=True)
        edited = threat.edited or any(
            field in TEXT_FIELDS and value != getattr(threat, field)
            for field, value in changes.items()
        )
        # model_validate rather than model_copy(update=...), which would skip validation.
        updated = Threat.model_validate(
            {**threat.model_dump(), **changes, "edited": edited, "updated_at": _now()}
        )
        model.threats[index] = updated
        return updated

    def delete_threat(self, model_id: UUID, threat_id: UUID) -> None:
        model = self.get(model_id)
        index, _ = self._find(model, threat_id)
        del model.threats[index]

    @staticmethod
    def _find(model: ThreatModel, threat_id: UUID) -> tuple[int, Threat]:
        for i, t in enumerate(model.threats):
            if t.id == threat_id:
                return i, t
        raise ApiError(404, "not_found", "Threat not found")
