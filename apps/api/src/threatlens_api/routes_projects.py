from uuid import UUID

from fastapi import APIRouter, Request

from threatlens_api.auth import CurrentUser
from threatlens_api.models import Project, ProjectCreate
from threatlens_api.store import ProjectStore

router = APIRouter(prefix="/projects", tags=["projects"])


def _store(request: Request) -> ProjectStore:
    return request.app.state.projects


@router.get("")
def list_projects(user: CurrentUser, request: Request) -> list[Project]:
    return _store(request).list(user.id)


@router.post("", status_code=201)
def create_project(body: ProjectCreate, user: CurrentUser, request: Request) -> Project:
    return _store(request).create(user.id, body)


@router.get("/{project_id}")
def get_project(project_id: UUID, user: CurrentUser, request: Request) -> Project:
    return _store(request).get(user.id, project_id)
