"""Runs queued scans: read the upload, look every dependency up, store the findings.

Queues deliver at least once, so the same message can arrive twice, or arrive again after
a worker died halfway. Every step is safe to repeat: the scan record says what's done, and
moving it from one state to the next is a versioned save that only one worker can win.
"""

import contextlib
import logging
import queue
import threading
import time
from collections.abc import Callable
from datetime import timedelta
from uuid import UUID

from pydantic import TypeAdapter

from threatlens_api import ingest
from threatlens_api.epss import EpssClient
from threatlens_api.kev import KevClient
from threatlens_api.models import Dependency, Finding, _now
from threatlens_api.osv import OsvClient
from threatlens_api.repository import Conflict, Repository
from threatlens_api.risk import Enriched, enrich
from threatlens_api.scans import (
    Blobs,
    MemoryQueue,
    Scan,
    ScanMessage,
    ScanStatus,
    findings_key,
    parse_message,
    upload_key,
)

# A scan still "running" after this is taken to be dead and is picked up again. The SQS
# visibility timeout (day 16) must be at least this long, or a live scan gets a twin.
SCAN_TIMEOUT = timedelta(minutes=15)
MAX_ATTEMPTS = 3

Pipeline = Callable[[UUID, list[Dependency]], Enriched]
FindingList = TypeAdapter(list[Finding])

log = logging.getLogger("threatlens")


def network_pipeline() -> Pipeline:
    """OSV, EPSS and KEV for real. The clients keep their caches between scans."""
    osv, epss, kev = OsvClient(), EpssClient(), KevClient()

    def run(project_id: UUID, deps: list[Dependency]) -> Enriched:
        return enrich(project_id, deps, osv.scan(deps), epss, kev)

    return run


class Worker:
    def __init__(
        self,
        repo: Repository,
        blobs: Blobs,
        pipeline: Pipeline | None = None,
        clock: Callable = _now,
    ):
        self.repo = repo
        self.blobs = blobs
        self._pipeline = pipeline
        self._clock = clock

    @property
    def pipeline(self) -> Pipeline:
        # Built on first use, so starting the API makes no network clients it may not need.
        if self._pipeline is None:
            self._pipeline = network_pipeline()
        return self._pipeline

    @pipeline.setter
    def pipeline(self, value: Pipeline) -> None:
        self._pipeline = value

    def handle(self, message: ScanMessage) -> None:
        """Returns when the message is dealt with. Raises if it should be delivered again."""
        found = self.repo.load_scan(message.owner, message.project_id, message.scan_id)
        if found is None:
            log.warning("scan message for a missing scan", extra={"scan_id": str(message.scan_id)})
            return
        scan, version = found
        now = self._clock()
        if scan.status == ScanStatus.DONE:
            # A repeat delivery. Set the pointer again in case the first run died just
            # before it: it only ever moves forward, so repeating it is harmless.
            self.repo.set_latest_scan(scan)
            return
        if scan.status == ScanStatus.FAILED:
            return
        if scan.status == ScanStatus.RUNNING and now - scan.started_at < SCAN_TIMEOUT:
            # Another worker has it. If that one dies, its own message comes back later.
            return
        if scan.attempts >= MAX_ATTEMPTS:
            self._fail(scan, version, "The scan kept failing. Upload the file again later")
            return

        scan.status, scan.started_at, scan.attempts = ScanStatus.RUNNING, now, scan.attempts + 1
        try:
            self.repo.save_scan(scan, version)
        except Conflict:
            return  # another worker claimed it first
        version += 1

        try:
            self._run(scan, version)
        except Exception:
            log.exception("scan failed", extra={"scan_id": str(scan.id), "attempt": scan.attempts})
            if scan.attempts >= MAX_ATTEMPTS:
                self._fail(scan, version, "The scan kept failing. Upload the file again later")
                return
            # Hand it back, so the next delivery can start again straight away.
            scan.status = ScanStatus.QUEUED
            with contextlib.suppress(Conflict):
                self.repo.save_scan(scan, version)
            raise

    def _run(self, scan: Scan, version: int) -> None:
        data = self.blobs.get(upload_key(scan))
        if data is None:
            self._fail(scan, version, "The uploaded file is no longer there. Upload it again")
            return
        try:
            parsed = ingest.parse(scan.filename, data)
        except ingest.IngestError as e:
            # Checked at upload, so this means the stored file changed. Not worth a retry.
            self._fail(scan, version, str(e)[:200])
            return

        result = self.pipeline(scan.project_id, parsed.dependencies)
        self.blobs.put(
            findings_key(scan.owner_id, scan.project_id, scan.id),
            FindingList.dump_json(result.findings),
        )
        scan.status = ScanStatus.DONE
        scan.findings = len(result.findings)
        scan.unchecked = len(result.unchecked)
        scan.epss_failed = len(result.epss_failed)
        scan.kev_available, scan.kev_stale = result.kev_available, result.kev_stale
        scan.finished_at = self._clock()
        try:
            self.repo.save_scan(scan, version)
        except Conflict:
            # Too slow: the scan was taken over and the other worker's result stands.
            return
        self.repo.set_latest_scan(scan)

    def _fail(self, scan: Scan, version: int, error: str) -> None:
        scan.status, scan.error, scan.finished_at = ScanStatus.FAILED, error, self._clock()
        with contextlib.suppress(Conflict):
            self.repo.save_scan(scan, version)


def lambda_handler_for(worker: Worker):
    """An SQS-triggered Lambda handler (wired up on day 15). Reports failures per message,
    so one bad scan doesn't make the whole batch run again."""

    def handler(event: dict, context=None) -> dict:
        failures = []
        for record in event.get("Records", []):
            message = parse_message(record.get("body", ""))
            if message is None:
                log.warning("dropped a message that isn't a scan")
                continue
            try:
                worker.handle(message)
            except Exception:
                failures.append({"itemIdentifier": record["messageId"]})
        return {"batchItemFailures": failures}

    return handler


class LocalRunner:
    """Local development: runs the in-process queue in a background thread."""

    def __init__(self, queue: MemoryQueue, worker: Worker, retry_delay: float = 1.0):
        self.queue = queue
        self.worker = worker
        self.retry_delay = retry_delay
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def run_pending(self) -> None:
        """Handles everything queued so far, in this thread. Used by tests."""
        while not self.queue.items.empty():
            self._handle(self.queue.items.get_nowait(), wait=False)

    def _handle(self, message: ScanMessage, wait: bool = True) -> None:
        try:
            self.worker.handle(message)
        except Exception:
            if wait:
                time.sleep(self.retry_delay)
            self.queue.send(message)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="scan-worker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                message = self.queue.items.get(timeout=0.2)
            except queue.Empty:
                continue
            self._handle(message)


def lambda_handler(event: dict, context=None) -> dict:
    """Entry point for the worker Lambda (day 15). Built once per container and reused."""
    global _handler
    if _handler is None:
        from threatlens_api.settings import get_settings
        from threatlens_api.wiring import make_blobs, make_repository

        settings = get_settings()
        repo, _ = make_repository(settings)
        _handler = lambda_handler_for(Worker(repo, make_blobs(settings)))
    return _handler(event, context)


_handler = None
