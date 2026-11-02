"""Scan records, the file store for uploads and findings, and the scan queue.

A scan's slow part (OSV, EPSS and KEV over the network) runs in a worker, so the upload
request returns straight away. The queue message carries ids only; everything else is
read back from storage, so a message can't smuggle in data of its own.
"""

import json
import queue
import re
import threading
from datetime import datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID, uuid4

from botocore.exceptions import BotoCoreError, ClientError
from pydantic import Field

from threatlens_api.errors import ApiError
from threatlens_api.models import Strict, _now

FILENAME = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$"
_SUB = re.compile(r"^[A-Za-z0-9._:@-]{1,128}$")
MAX_SKIPPED_SHOWN = 20


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class SkippedRef(Strict):
    ref: str = Field(max_length=120)
    reason: str = Field(max_length=200)


class Scan(Strict):
    id: UUID = Field(default_factory=uuid4)
    project_id: UUID
    owner_id: str = Field(min_length=1, max_length=128, exclude=True)
    filename: str = Field(pattern=FILENAME)
    format: str = Field(max_length=40)
    status: ScanStatus = ScanStatus.QUEUED
    dependencies: int = Field(default=0, ge=0)
    # What the file listed but couldn't be checked (no exact version and so on): a count,
    # plus the first few so the user can see what kind.
    skipped: int = Field(default=0, ge=0)
    skipped_examples: list[SkippedRef] = Field(default_factory=list, max_length=MAX_SKIPPED_SHOWN)
    findings: int = Field(default=0, ge=0)
    # A partial scan says so instead of looking clean.
    unchecked: int = Field(default=0, ge=0)
    epss_failed: int = Field(default=0, ge=0)
    kev_available: bool = True
    kev_stale: bool = False
    attempts: int = Field(default=0, ge=0)
    error: str | None = Field(default=None, max_length=200)
    created_at: datetime = Field(default_factory=_now)
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @property
    def complete(self) -> bool:
        return self.unchecked == 0 and self.epss_failed == 0 and self.kev_available


def upload_key(scan: Scan) -> str:
    return f"uploads/{scan.owner_id}/{scan.project_id}/{scan.id}"


def findings_key(owner: str, project_id: UUID, scan_id: UUID) -> str:
    return f"findings/{owner}/{project_id}/{scan_id}.json"


# --- files ---------------------------------------------------------------------------


class Blobs(Protocol):
    def put(self, key: str, data: bytes) -> None: ...
    def get(self, key: str) -> bytes | None: ...


class MemoryBlobs:
    def __init__(self):
        self._data: dict[str, bytes] = {}
        self._lock = threading.Lock()

    def put(self, key: str, data: bytes) -> None:
        with self._lock:
            self._data[key] = bytes(data)

    def get(self, key: str) -> bytes | None:
        with self._lock:
            return self._data.get(key)


def _storage_error(e: Exception) -> ApiError:
    return ApiError(503, "storage_unavailable", "Can't reach storage right now")


class S3Blobs:
    """Private bucket. Encryption, versioning and public-access blocks are set in Terraform
    (day 16); the put asks for KMS encryption as well, so it can't be stored without."""

    def __init__(self, client, bucket: str):
        self._s3 = client
        self._bucket = bucket

    def put(self, key: str, data: bytes) -> None:
        try:
            self._s3.put_object(
                Bucket=self._bucket, Key=key, Body=data, ServerSideEncryption="aws:kms"
            )
        except (ClientError, BotoCoreError) as e:
            raise _storage_error(e) from e

    def get(self, key: str) -> bytes | None:
        try:
            return self._s3.get_object(Bucket=self._bucket, Key=key)["Body"].read()
        except ClientError as e:
            if e.response["Error"]["Code"] in ("NoSuchKey", "404"):
                return None
            raise _storage_error(e) from e
        except BotoCoreError as e:
            raise _storage_error(e) from e


# --- queue -----------------------------------------------------------------------------


class ScanMessage(Strict):
    owner: str = Field(pattern=_SUB.pattern)
    project_id: UUID
    scan_id: UUID

    @classmethod
    def for_scan(cls, scan: Scan) -> "ScanMessage":
        return cls(owner=scan.owner_id, project_id=scan.project_id, scan_id=scan.id)


class ScanQueue(Protocol):
    def send(self, message: ScanMessage) -> None: ...


class MemoryQueue:
    """Local development: a worker thread in the API process takes from this."""

    def __init__(self):
        self.items: queue.Queue[ScanMessage] = queue.Queue()

    def send(self, message: ScanMessage) -> None:
        self.items.put(message)


class SqsQueue:
    def __init__(self, client, url: str):
        self._sqs = client
        self._url = url

    def send(self, message: ScanMessage) -> None:
        try:
            self._sqs.send_message(QueueUrl=self._url, MessageBody=message.model_dump_json())
        except (ClientError, BotoCoreError) as e:
            raise ApiError(503, "queue_unavailable", "Can't start a scan right now") from e


def parse_message(body: str) -> ScanMessage | None:
    """None for a message that isn't ours: it's dropped, not retried forever."""
    try:
        return ScanMessage.model_validate(json.loads(body))
    except ValueError:
        return None
