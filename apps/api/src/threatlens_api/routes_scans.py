import logging
import math
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Request, Response
from fastapi.concurrency import run_in_threadpool

from threatlens_api import ingest
from threatlens_api.auth import CurrentUser
from threatlens_api.errors import ApiError
from threatlens_api.models import Finding
from threatlens_api.scans import (
    FILENAME,
    MAX_SKIPPED_SHOWN,
    Scan,
    ScanMessage,
    ScanStatus,
    SkippedRef,
    upload_key,
)
from threatlens_api.worker import FindingList

log = logging.getLogger("threatlens")

router = APIRouter(prefix="/projects/{project_id}", tags=["scans"])


async def _read_body(request: Request, limit: int) -> bytes:
    # The size middleware only sees Content-Length; a chunked upload has none, so count here.
    data = bytearray()
    async for chunk in request.stream():
        data += chunk
        if len(data) > limit:
            raise ApiError(413, "payload_too_large", "Request body too large")
    return bytes(data)


@router.post("/scans", status_code=202)
async def start_scan(
    project_id: UUID,
    filename: Annotated[str, Query(pattern=FILENAME)],
    user: CurrentUser,
    request: Request,
    response: Response,
) -> Scan:
    state = request.app.state
    # Someone else's project is a 404 before anything is read, stored or counted.
    await run_in_threadpool(state.projects.get, user.id, project_id)

    wait = state.scan_budget.take(user.id)
    if wait is not None:
        raise ApiError(
            429,
            "scan_limit",
            "Too many scans this hour",
            headers={"Retry-After": str(math.ceil(wait))},
        )

    data = await _read_body(request, state.settings.max_request_bytes)
    # Parsed now so a bad file is refused at once; the worker parses its stored copy again.
    try:
        parsed = await run_in_threadpool(ingest.parse, filename, data)
    except ingest.IngestError as e:
        # IngestError messages are written to be safe to show.
        raise ApiError(422, "bad_file", str(e)[:200]) from e

    scan = Scan(
        project_id=project_id,
        owner_id=user.id,
        filename=filename,
        format=parsed.format,
        dependencies=len(parsed.dependencies),
        skipped=len(parsed.skipped),
        skipped_examples=[
            SkippedRef(ref=s.ref[:120], reason=s.reason[:200])
            for s in parsed.skipped[:MAX_SKIPPED_SHOWN]
        ],
    )
    await run_in_threadpool(state.blobs.put, upload_key(scan), data)
    await run_in_threadpool(state.repo.create_scan, scan)
    try:
        await run_in_threadpool(state.scan_queue.send, ScanMessage.for_scan(scan))
    except ApiError:
        # Never leave a scan that says "queued" when nothing will ever run it.
        scan.status, scan.error = ScanStatus.FAILED, "Couldn't start the scan. Try again"
        await run_in_threadpool(state.repo.save_scan, scan, 1)
        raise
    response.headers["Location"] = f"/projects/{project_id}/scans/{scan.id}"
    return scan


@router.get("/scans/{scan_id}")
def get_scan(project_id: UUID, scan_id: UUID, user: CurrentUser, request: Request) -> Scan:
    found = request.app.state.repo.load_scan(user.id, project_id, scan_id)
    if found is None:
        raise ApiError(404, "not_found", "Scan not found")
    return found[0]


@router.get("/findings")
def list_findings(project_id: UUID, user: CurrentUser, request: Request) -> list[Finding]:
    """The findings of the newest finished scan, riskiest first. Empty before any scan."""
    state = request.app.state
    state.projects.get(user.id, project_id)
    scan_id = state.repo.latest_scan(user.id, project_id)
    if scan_id is None:
        return []
    found = state.repo.load_scan(user.id, project_id, scan_id)
    # The file the record names, so the findings always match the counts on the record.
    name = found[0].findings_file if found is not None else None
    data = state.blobs.get(name) if name else None
    if data is None:
        log.error("findings file missing for a finished scan", extra={"scan_id": str(scan_id)})
        raise RuntimeError("findings file missing")
    return FindingList.validate_json(data)
