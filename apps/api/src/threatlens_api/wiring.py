"""Builds storage, files and queue from settings. Shared by the API and the worker Lambda."""

import boto3
from botocore.config import Config

from threatlens_api.repository import (
    DynamoRepository,
    MemoryRepository,
    Repository,
    dynamodb_client,
)
from threatlens_api.scans import Blobs, MemoryBlobs, MemoryQueue, S3Blobs, ScanQueue, SqsQueue
from threatlens_api.settings import Settings

_CONFIG = Config(
    connect_timeout=2, read_timeout=10, retries={"mode": "standard", "max_attempts": 3}
)


def make_repository(settings: Settings) -> tuple[Repository, object | None]:
    """The repository, and the DynamoDB client if there is one (to create a local table)."""
    if settings.store == "dynamodb":
        client = dynamodb_client(settings.aws_region, settings.dynamodb_endpoint_url)
        return DynamoRepository(client, settings.dynamodb_table), client
    return MemoryRepository(), None


def make_blobs(settings: Settings) -> Blobs:
    if settings.uploads_bucket is None:
        return MemoryBlobs()
    client = boto3.client("s3", region_name=settings.aws_region, config=_CONFIG)
    return S3Blobs(client, settings.uploads_bucket)


def make_queue(settings: Settings) -> ScanQueue:
    if settings.scan_queue_url is None:
        return MemoryQueue()
    client = boto3.client("sqs", region_name=settings.aws_region, config=_CONFIG)
    return SqsQueue(client, settings.scan_queue_url)
