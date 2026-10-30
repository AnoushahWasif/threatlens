from datetime import datetime
from enum import StrEnum
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import Field, model_validator

from threatlens_api.models import Strict, _now


class Stride(StrEnum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class ThreatStatus(StrEnum):
    DRAFT = "draft"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class ThreatSource(StrEnum):
    LLM = "llm"
    MANUAL = "manual"


Title = Annotated[str, Field(min_length=1, max_length=120)]
Text = Annotated[str, Field(min_length=1, max_length=1_000)]
Mitigation = Annotated[str, Field(max_length=1_000)]
Component = Annotated[str, Field(max_length=100)]


class ThreatDraft(Strict):
    """One threat as the LLM (or a person) writes it."""

    category: Stride
    title: Title
    description: Text
    mitigation: Mitigation = ""
    component: Component = ""


class Threat(ThreatDraft):
    id: UUID = Field(default_factory=uuid4)
    status: ThreatStatus
    source: ThreatSource
    # True once a person has changed the text; re-drafting must not throw that work away.
    edited: bool = False
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)


class ThreatUpdate(Strict):
    category: Stride | None = None
    title: Title | None = None
    description: Text | None = None
    mitigation: Mitigation | None = None
    component: Component | None = None
    status: ThreatStatus | None = None

    @model_validator(mode="after")
    def not_empty(self) -> "ThreatUpdate":
        values = self.model_dump(exclude_unset=True)
        if not values:
            raise ValueError("Nothing to update")
        if any(v is None for v in values.values()):
            raise ValueError("Fields can't be set to null")
        return self


class ThreatModelCreate(Strict):
    name: str = Field(min_length=1, max_length=100)
    # Long enough to say what talks to what; short enough to bound LLM cost per draft.
    architecture: str = Field(min_length=40, max_length=8_000)


class ThreatModel(ThreatModelCreate):
    id: UUID = Field(default_factory=uuid4)
    threats: list[Threat] = Field(default_factory=list)
    drafted_with: str | None = None
    drafted_at: datetime | None = None
    created_at: datetime = Field(default_factory=_now)
