"""Where threat models and projects are kept.

Two backends with the same rules: in memory (dev and tests) and DynamoDB (prod). Every
key starts with the owner's id, so a request can only ever name its own user's items.

DynamoDB layout, one table:

    pk               sk              what
    USER#<sub>       TM#<id>         a threat model, threats included, as JSON
    USER#<sub>       PROJECT#<id>    a project, as JSON
    USER#<sub>       COUNTS          how many of each the user has, for the caps

A `sub` can't contain `#` (auth.py checks its characters), so keys can't be forged by
picking a clever username.
"""

import json
import logging
import random
import threading
import time
import uuid
from typing import Protocol
from uuid import UUID

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import ValidationError

from threatlens_api.errors import ApiError
from threatlens_api.models import Project
from threatlens_api.threats import ThreatModel

# DynamoDB's item limit is 400 KB including attribute names; leave room for those.
MAX_ITEM_BYTES = 350_000
# Dev only. In DynamoDB the per-user caps are the limit (decision 32).
MAX_MEMORY_ITEMS = 500

log = logging.getLogger("threatlens")


class Conflict(Exception):
    """The item changed after it was read."""


class Repository(Protocol):
    def create_model(self, model: ThreatModel, max_per_user: int) -> None: ...
    def load_model(self, owner: str, model_id: UUID) -> tuple[ThreatModel, int] | None: ...
    def save_model(self, model: ThreatModel, version: int) -> None: ...
    def claim_draft(self, owner: str, model_id: UUID, seconds: int) -> str | None: ...
    def release_draft(self, owner: str, model_id: UUID, lease: str) -> None: ...
    def create_project(self, owner: str, project: Project, max_per_user: int) -> None: ...
    def list_projects(self, owner: str) -> list[Project]: ...
    def get_project(self, owner: str, project_id: UUID) -> Project | None: ...


# Counter name -> (error code, words). The codes are the ones the web app already knows.
_CAPS = {
    "threat_models": ("too_many_models", "threat models"),
    "projects": ("too_many_projects", "projects"),
}


def too_many(counter: str, limit: int) -> ApiError:
    code, words = _CAPS[counter]
    return ApiError(409, code, f"You can have {limit} {words}")


def _body(item: ThreatModel | Project) -> str:
    body = item.model_dump_json()
    if len(body.encode()) > MAX_ITEM_BYTES:
        raise ApiError(409, "too_large", "This is too big to save. Shorten or remove some text")
    return body


def _parse_model(owner: str, model_id: UUID, body: str) -> ThreatModel:
    # owner_id is never stored in the body (it's the key), so put it back before validating.
    try:
        model = ThreatModel.model_validate({**json.loads(body), "owner_id": owner})
    except (ValueError, ValidationError) as e:
        raise _corrupt("threat model", model_id) from e
    if model.id != model_id:
        raise _corrupt("threat model", model_id)
    return model


def _parse_project(owner: str, project_id: UUID, body: str) -> Project:
    try:
        project = Project.model_validate({**json.loads(body), "owner_id": owner})
    except (ValueError, ValidationError) as e:
        raise _corrupt("project", project_id) from e
    if project.id != project_id:
        raise _corrupt("project", project_id)
    return project


def _corrupt(what: str, item_id: UUID) -> RuntimeError:
    # Fail closed: a stored item that doesn't validate is never served half-read.
    log.error("stored item failed validation", extra={"kind": what, "item_id": str(item_id)})
    return RuntimeError(f"stored {what} failed validation")


# --- In memory -------------------------------------------------------------------


class MemoryRepository:
    """Keeps JSON strings rather than live objects, so it behaves like DynamoDB: a change
    is only stored when it's saved, and a stale save is refused."""

    def __init__(self, max_items: int = MAX_MEMORY_ITEMS, clock=time.time):
        self.max_items = max_items
        self._clock = clock
        self._lock = threading.Lock()
        self._models: dict[tuple[str, UUID], tuple[str, int]] = {}
        self._projects: dict[tuple[str, UUID], str] = {}
        self._leases: dict[tuple[str, UUID], tuple[float, str]] = {}

    def _check_room(self, owner: str, what: str, items: dict, max_per_user: int) -> None:
        if sum(key[0] == owner for key in items) >= max_per_user:
            raise too_many(what, max_per_user)
        if len(self._models) + len(self._projects) >= self.max_items:
            raise ApiError(507, "storage_full", "No room for more items on this server")

    def create_model(self, model: ThreatModel, max_per_user: int) -> None:
        body = _body(model)
        with self._lock:
            self._check_room(model.owner_id, "threat_models", self._models, max_per_user)
            self._models[(model.owner_id, model.id)] = (body, 1)

    def load_model(self, owner: str, model_id: UUID) -> tuple[ThreatModel, int] | None:
        with self._lock:
            stored = self._models.get((owner, model_id))
        if stored is None:
            return None
        return _parse_model(owner, model_id, stored[0]), stored[1]

    def save_model(self, model: ThreatModel, version: int) -> None:
        body = _body(model)
        key = (model.owner_id, model.id)
        with self._lock:
            stored = self._models.get(key)
            if stored is None or stored[1] != version:
                raise Conflict
            self._models[key] = (body, version + 1)

    def claim_draft(self, owner: str, model_id: UUID, seconds: int) -> str | None:
        key, now = (owner, model_id), self._clock()
        with self._lock:
            held = self._leases.get(key)
            if key not in self._models or (held is not None and held[0] > now):
                return None
            lease = uuid.uuid4().hex
            self._leases[key] = (now + seconds, lease)
            return lease

    def release_draft(self, owner: str, model_id: UUID, lease: str) -> None:
        with self._lock:
            held = self._leases.get((owner, model_id))
            # Only our own lease: if ours ran out and someone else took one, theirs stays.
            if held is not None and held[1] == lease:
                del self._leases[(owner, model_id)]

    def create_project(self, owner: str, project: Project, max_per_user: int) -> None:
        body = _body(project)
        with self._lock:
            self._check_room(owner, "projects", self._projects, max_per_user)
            self._projects[(owner, project.id)] = body

    def list_projects(self, owner: str) -> list[Project]:
        with self._lock:
            mine = [(key[1], body) for key, body in self._projects.items() if key[0] == owner]
        return [_parse_project(owner, project_id, body) for project_id, body in mine]

    def get_project(self, owner: str, project_id: UUID) -> Project | None:
        with self._lock:
            body = self._projects.get((owner, project_id))
        return None if body is None else _parse_project(owner, project_id, body)


# --- DynamoDB --------------------------------------------------------------------

# Throttling or a DynamoDB-side fault: worth trying again shortly.
_BUSY = {
    "ProvisionedThroughputExceededException",
    "ThrottlingException",
    "RequestLimitExceeded",
    "InternalServerError",
    "ServiceUnavailable",
}


_THROTTLED = {"ThrottlingError", "ProvisionedThroughputExceeded"}


def _busy() -> ApiError:
    return ApiError(503, "storage_busy", "Storage is busy. Try again", headers={"Retry-After": "2"})


def dynamodb_client(region: str, endpoint_url: str | None = None):
    config = Config(
        connect_timeout=2,
        read_timeout=5,
        retries={"mode": "standard", "max_attempts": 3},
    )
    return boto3.client("dynamodb", region_name=region, endpoint_url=endpoint_url, config=config)


def create_table(client, name: str) -> None:
    """For DynamoDB Local and tests only. In AWS, Terraform owns the table (day 16)."""
    try:
        client.create_table(
            TableName=name,
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceInUseException":
            raise
    client.get_waiter("table_exists").wait(TableName=name)


def _s(value: str) -> dict:
    return {"S": value}


def _n(value: int | float) -> dict:
    return {"N": str(value)}


class DynamoRepository:
    def __init__(self, client, table: str, clock=time.time):
        self._db = client
        self._table = table
        self._clock = clock

    def _key(self, owner: str, sk: str) -> dict:
        return {"pk": _s(f"USER#{owner}"), "sk": _s(sk)}

    def _call(self, operation: str, **kwargs) -> dict:
        # transact_write_items names the table in each item instead.
        if operation != "transact_write_items":
            kwargs["TableName"] = self._table
        try:
            return getattr(self._db, operation)(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in _BUSY:
                log.warning("dynamodb busy", extra={"code": code, "operation": operation})
                raise _busy() from e
            raise
        except BotoCoreError as e:
            # Connection refused, timeouts, no credentials: the store can't be reached.
            log.warning("dynamodb unreachable", extra={"error": type(e).__name__})
            raise ApiError(503, "storage_unavailable", "Can't reach storage right now") from e

    def _create(self, owner: str, counter: str, item: dict, max_per_user: int) -> None:
        """Puts a new item and bumps the user's counter in one transaction, so the cap holds
        even when two creates race."""
        count = {
            "Update": {
                "TableName": self._table,
                "Key": self._key(owner, "COUNTS"),
                "UpdateExpression": "ADD #c :one",
                "ConditionExpression": "attribute_not_exists(#c) OR #c < :max",
                "ExpressionAttributeNames": {"#c": counter},
                "ExpressionAttributeValues": {":one": _n(1), ":max": _n(max_per_user)},
            }
        }
        put = {
            "Put": {
                "TableName": self._table,
                "Item": item,
                "ConditionExpression": "attribute_not_exists(pk)",
            }
        }
        for _ in range(3):
            try:
                self._call("transact_write_items", TransactItems=[count, put])
                return
            except ClientError as e:
                if e.response["Error"]["Code"] != "TransactionCanceledException":
                    raise
                reasons = [r.get("Code") for r in e.response.get("CancellationReasons", [])]
                if reasons and reasons[0] == "ConditionalCheckFailed":
                    raise too_many(counter, max_per_user) from e
                # A transaction cancelled for capacity says so per item, not in the top code.
                if _THROTTLED & set(reasons):
                    raise _busy() from e
                if "TransactionConflict" not in reasons:
                    raise
                # Another create for the same user touched the counter at the same moment.
                # Wait a little, or the two will usually collide again straight away.
                time.sleep(random.uniform(0.01, 0.05))  # noqa: S311 - timing jitter, not a secret
        raise ApiError(409, "edit_conflict", "Too many changes at once. Try again")

    def create_model(self, model: ThreatModel, max_per_user: int) -> None:
        item = {
            **self._key(model.owner_id, f"TM#{model.id}"),
            "body": _s(_body(model)),
            "ver": _n(1),
        }
        self._create(model.owner_id, "threat_models", item, max_per_user)

    def load_model(self, owner: str, model_id: UUID) -> tuple[ThreatModel, int] | None:
        item = self._call(
            "get_item", Key=self._key(owner, f"TM#{model_id}"), ConsistentRead=True
        ).get("Item")
        if item is None:
            return None
        return _parse_model(owner, model_id, item["body"]["S"]), int(item["ver"]["N"])

    def save_model(self, model: ThreatModel, version: int) -> None:
        # UpdateItem, not PutItem: a put would also wipe the draft lease attributes.
        try:
            self._call(
                "update_item",
                Key=self._key(model.owner_id, f"TM#{model.id}"),
                UpdateExpression="SET #b = :body, #v = :next",
                ConditionExpression="#v = :ver",
                ExpressionAttributeNames={"#b": "body", "#v": "ver"},
                ExpressionAttributeValues={
                    ":body": _s(_body(model)),
                    ":ver": _n(version),
                    ":next": _n(version + 1),
                },
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise Conflict from e
            raise

    def claim_draft(self, owner: str, model_id: UUID, seconds: int) -> str | None:
        now, lease = self._clock(), uuid.uuid4().hex
        try:
            self._call(
                "update_item",
                Key=self._key(owner, f"TM#{model_id}"),
                UpdateExpression="SET #until = :until, #id = :lease",
                # attribute_exists stops UpdateItem from creating a stray item.
                ConditionExpression="attribute_exists(pk) AND "
                "(attribute_not_exists(#until) OR #until < :now)",
                ExpressionAttributeNames={"#until": "draft_until", "#id": "draft_lease"},
                ExpressionAttributeValues={
                    ":until": _n(now + seconds),
                    ":now": _n(now),
                    ":lease": _s(lease),
                },
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return None
            raise
        return lease

    def release_draft(self, owner: str, model_id: UUID, lease: str) -> None:
        try:
            self._call(
                "update_item",
                Key=self._key(owner, f"TM#{model_id}"),
                UpdateExpression="REMOVE #until, #id",
                # Only our own lease: if ours ran out and someone else took one, theirs stays.
                ConditionExpression="#id = :lease",
                ExpressionAttributeNames={"#until": "draft_until", "#id": "draft_lease"},
                ExpressionAttributeValues={":lease": _s(lease)},
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise

    def create_project(self, owner: str, project: Project, max_per_user: int) -> None:
        item = {**self._key(owner, f"PROJECT#{project.id}"), "body": _s(_body(project))}
        self._create(owner, "projects", item, max_per_user)

    def list_projects(self, owner: str) -> list[Project]:
        projects, start = [], None
        while True:
            extra = {"ExclusiveStartKey": start} if start else {}
            page = self._call(
                "query",
                KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
                ExpressionAttributeValues={":pk": _s(f"USER#{owner}"), ":prefix": _s("PROJECT#")},
                ConsistentRead=True,
                **extra,
            )
            for item in page["Items"]:
                project_id = UUID(item["sk"]["S"].removeprefix("PROJECT#"))
                projects.append(_parse_project(owner, project_id, item["body"]["S"]))
            start = page.get("LastEvaluatedKey")
            if not start:
                return projects

    def get_project(self, owner: str, project_id: UUID) -> Project | None:
        item = self._call(
            "get_item", Key=self._key(owner, f"PROJECT#{project_id}"), ConsistentRead=True
        ).get("Item")
        return None if item is None else _parse_project(owner, project_id, item["body"]["S"])
