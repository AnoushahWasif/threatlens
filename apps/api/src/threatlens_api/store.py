"""Threat model rules (caps, re-drafting, no duplicates) on top of a repository.

Every change is read, applied, then saved only if nobody saved in between. On a clash the
change is applied again to the fresh copy, so two edits never overwrite each other.
"""

import math
import random
import threading
import time
from collections import deque
from collections.abc import Callable
from typing import TypeVar
from uuid import UUID

from threatlens_api.errors import ApiError
from threatlens_api.models import Project, ProjectCreate, _now
from threatlens_api.repository import Conflict, Repository
from threatlens_api.threats import (
    Threat,
    ThreatDraft,
    ThreatModel,
    ThreatModelCreate,
    ThreatSource,
    ThreatStatus,
    ThreatUpdate,
)

MAX_MODELS_PER_USER = 50
MAX_PROJECTS_PER_USER = 50
MAX_THREATS_PER_MODEL = 100
SAVE_ATTEMPTS = 3
# Longer than the slowest draft can take (90 s LLM timeout, two retries, plus a fallback),
# so a lease only runs out early if the process holding it died.
DRAFT_LEASE_SECONDS = 360
TEXT_FIELDS = {"category", "title", "description", "mitigation", "component"}
# Upper bound on what a draft adds: 25 threats at about 2.3 KB each at the field limits.
DRAFT_WRITE_ALLOWANCE = 60

T = TypeVar("T")


def _key(t: ThreatDraft) -> tuple[str, str]:
    return (t.category, t.title.casefold())


def write_units(item: ThreatModel | Project) -> int:
    # DynamoDB bills a write unit per KB of the whole item, rounded up.
    return max(1, math.ceil(len(item.model_dump_json().encode()) / 1024))


class WriteBudget:
    """Write units per user per rolling hour. Every threat edit rewrites the whole model, so
    a script editing a large model in a loop would otherwise cost real money with no LLM
    call involved. Per process; API Gateway throttling (day 16) is the shared limit."""

    WINDOW = 3_600

    def __init__(self, per_user: int, now: Callable[[], float] = time.monotonic):
        self.per_user = per_user
        self._now = now
        self._lock = threading.Lock()
        self._used: dict[str, deque[tuple[float, int]]] = {}
        self._totals: dict[str, int] = {}
        self._last_sweep = float("-inf")

    def take(self, user_id: str, units: int) -> None:
        """Use `units`, or raise 429 if they don't fit in this hour."""
        self._check(user_id, units, use=True)

    def check(self, user_id: str, units: int) -> None:
        """Raise 429 if `units` wouldn't fit, without using any. For a check before a paid
        call whose result is saved (and charged) later."""
        self._check(user_id, units, use=False)

    def _check(self, user_id: str, units: int, use: bool) -> None:
        now = self._now()
        with self._lock:
            # Drop callers with nothing left in the window, so the dicts can't grow forever.
            # At most once a minute: it's a scan over every tracked user.
            if len(self._used) > 10_000 and now - self._last_sweep >= 60:
                self._last_sweep = now
                for k in [k for k, v in self._used.items() if now - v[-1][0] >= self.WINDOW]:
                    del self._used[k], self._totals[k]
            used = self._used.setdefault(user_id, deque())
            total = self._totals.get(user_id, 0)
            while used and now - used[0][0] >= self.WINDOW:
                total -= used.popleft()[1]
            if total + units > self.per_user:
                self._totals[user_id] = total
                wait = self.WINDOW - (now - used[0][0]) if used else 1
                if not used:
                    del self._used[user_id], self._totals[user_id]
                raise ApiError(
                    429,
                    "write_limit",
                    "Too many changes this hour",
                    headers={"Retry-After": str(max(1, math.ceil(wait)))},
                )
            if use:
                used.append((now, units))
                total += units
            if used:
                self._totals[user_id] = total
            else:
                del self._used[user_id]
                self._totals.pop(user_id, None)


class ThreatModelStore:
    def __init__(
        self,
        repo: Repository,
        max_threats: int = MAX_THREATS_PER_MODEL,
        max_per_user: int = MAX_MODELS_PER_USER,
        budget: WriteBudget | None = None,
    ):
        self.repo = repo
        self.max_threats = max_threats
        self.max_per_user = max_per_user
        self.budget = budget

    def _charge(self, owner: str, units: int) -> None:
        if self.budget is not None:
            self.budget.take(owner, units)

    def check_room_to_draft(self, owner: str, model: ThreatModel) -> None:
        """Before a paid LLM call: refuse now if saving its result would go over the write
        budget, rather than paying for a draft that then can't be saved."""
        if self.budget is not None:
            self.budget.check(owner, write_units(model) + DRAFT_WRITE_ALLOWANCE)

    def create(self, owner: str, data: ThreatModelCreate) -> ThreatModel:
        model = ThreatModel(**data.model_dump(), owner_id=owner)
        self._charge(owner, write_units(model))
        self.repo.create_model(model, self.max_per_user)
        return model

    def get(self, owner: str, model_id: UUID) -> ThreatModel:
        return self._load(owner, model_id)[0]

    def _load(self, owner: str, model_id: UUID) -> tuple[ThreatModel, int]:
        found = self.repo.load_model(owner, model_id)
        # Someone else's model looks exactly like a missing one, so ids can't be probed.
        if found is None:
            raise ApiError(404, "not_found", "Threat model not found")
        return found

    def _change(self, owner: str, model_id: UUID, change: Callable[[ThreatModel], T]) -> T:
        for attempt in range(SAVE_ATTEMPTS):
            if attempt:
                # Two writers that just clashed would usually clash again at once.
                time.sleep(random.uniform(0.01, 0.05))  # noqa: S311 - timing jitter, not a secret
            model, version = self._load(owner, model_id)
            before = write_units(model)
            result = change(model)
            # DynamoDB bills an update at the larger of the item before and after, and bills
            # a failed conditional write too, so this is charged on every attempt.
            self._charge(owner, max(before, write_units(model)))
            try:
                self.repo.save_model(model, version)
            except Conflict:
                continue
            return result
        raise ApiError(409, "edit_conflict", "This threat model is being changed elsewhere")

    def claim_draft(self, owner: str, model_id: UUID) -> str:
        # A second draft while one is running would bill twice and then overwrite the first.
        lease = self.repo.claim_draft(owner, model_id, DRAFT_LEASE_SECONDS)
        if lease is None:
            raise ApiError(409, "draft_in_progress", "A draft for this model is already running")
        return lease

    def release_draft(self, owner: str, model_id: UUID, lease: str) -> None:
        self.repo.release_draft(owner, model_id, lease)

    def replace_drafts(
        self, owner: str, model_id: UUID, drafts: list[ThreatDraft], drafted_with: str
    ) -> tuple[ThreatModel, int]:
        """Swap untouched LLM drafts for new ones. Returns the model and how many were added.

        Anything a person has accepted, rejected, edited or written stays, and a new draft
        that repeats one of those is skipped.
        """

        def change(model: ThreatModel) -> tuple[ThreatModel, int]:
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
            return model, len(added)

        return self._change(owner, model_id, change)

    def add_threat(self, owner: str, model_id: UUID, draft: ThreatDraft) -> Threat:
        def change(model: ThreatModel) -> Threat:
            if len(model.threats) >= self.max_threats:
                raise ApiError(
                    409, "too_many_threats", f"A model can hold {self.max_threats} threats"
                )
            self._check_unique(model, draft)
            # Written by a person, so it needs no review.
            threat = Threat(
                **draft.model_dump(), status=ThreatStatus.ACCEPTED, source=ThreatSource.MANUAL
            )
            model.threats.append(threat)
            return threat

        return self._change(owner, model_id, change)

    def update_threat(
        self, owner: str, model_id: UUID, threat_id: UUID, update: ThreatUpdate
    ) -> Threat:
        def change(model: ThreatModel) -> Threat:
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
            self._check_unique(model, updated, ignore=threat_id)
            model.threats[index] = updated
            return updated

        return self._change(owner, model_id, change)

    def delete_threat(self, owner: str, model_id: UUID, threat_id: UUID) -> None:
        def change(model: ThreatModel) -> None:
            index, _ = self._find(model, threat_id)
            del model.threats[index]

        self._change(owner, model_id, change)

    @staticmethod
    def _check_unique(model: ThreatModel, threat: ThreatDraft, ignore: UUID | None = None) -> None:
        # Drafting dedupes on the same key, so hand edits must too, or the export lists it twice.
        if any(t.id != ignore and _key(t) == _key(threat) for t in model.threats):
            raise ApiError(
                409, "duplicate_threat", "A threat with this title is already in this category"
            )

    @staticmethod
    def _find(model: ThreatModel, threat_id: UUID) -> tuple[int, Threat]:
        for i, t in enumerate(model.threats):
            if t.id == threat_id:
                return i, t
        raise ApiError(404, "not_found", "Threat not found")


class ProjectStore:
    def __init__(
        self,
        repo: Repository,
        max_per_user: int = MAX_PROJECTS_PER_USER,
        budget: WriteBudget | None = None,
    ):
        self.repo = repo
        self.max_per_user = max_per_user
        self.budget = budget

    def create(self, owner: str, data: ProjectCreate) -> Project:
        project = Project(**data.model_dump(), owner_id=owner)
        if self.budget is not None:
            self.budget.take(owner, write_units(project))
        self.repo.create_project(owner, project, self.max_per_user)
        return project

    def list(self, owner: str) -> list[Project]:
        return sorted(self.repo.list_projects(owner), key=lambda p: p.created_at, reverse=True)

    def get(self, owner: str, project_id: UUID) -> Project:
        project = self.repo.get_project(owner, project_id)
        if project is None:
            raise ApiError(404, "not_found", "Project not found")
        return project
