from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class Strict(BaseModel):
    # Unknown fields are an error, not silently dropped: typos and mass-assignment both fail loudly.
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Ecosystem(StrEnum):
    """Package ecosystems, named exactly as OSV.dev expects them."""

    PYPI = "PyPI"
    NPM = "npm"
    MAVEN = "Maven"
    GO = "Go"
    CARGO = "crates.io"
    NUGET = "NuGet"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


# npm scoped names (@scope/pkg), Maven group:artifact and Go module paths all need / : @ .
PackageName = Annotated[
    str, Field(min_length=1, max_length=214, pattern=r"^[A-Za-z0-9@][A-Za-z0-9._\-/:@]*$")
]
Version = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._\-+~^:]+$")]
VulnId = Annotated[str, Field(max_length=64, pattern=r"^[A-Z][A-Z0-9]*-[A-Za-z0-9\-:]+$")]


def _now() -> datetime:
    return datetime.now(UTC)


class Dependency(Strict):
    name: PackageName
    version: Version
    ecosystem: Ecosystem
    direct: bool = True


class ProjectCreate(Strict):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=5_000)


class Project(ProjectCreate):
    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=_now)


class Finding(Strict):
    id: UUID = Field(default_factory=uuid4)
    project_id: UUID
    dependency: Dependency
    vuln_id: VulnId
    aliases: list[VulnId] = Field(default_factory=list, max_length=50)
    summary: str = Field(default="", max_length=1_000)
    severity: Severity = Severity.UNKNOWN
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    epss: float | None = Field(default=None, ge=0, le=1)
    in_kev: bool = False
    risk_score: float = Field(ge=0, le=100)
    fixed_versions: list[Version] = Field(default_factory=list, max_length=50)
