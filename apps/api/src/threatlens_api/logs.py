"""One JSON object per log line, so CloudWatch Logs Insights and metric filters can query
fields (status, duration_ms, scan_id) instead of grepping text.

Only what the code passes in `extra` is logged, and the code only passes ids, counts and
error class names: never request bodies, tokens or uploaded files. Values are cut to a few
hundred characters and JSON-escaped, so a value can't forge a second log line.
"""

import hashlib
import json
import logging
import re
import sys
import traceback
from contextvars import ContextVar
from datetime import UTC, datetime

MAX_VALUE = 300
MAX_TRACEBACK = 4_000

# Set by the API's middleware (FastAPI's threadpool copies it into sync routes), and by
# the worker from the scan message, so a scan's lines carry the id of the upload request.
request_id: ContextVar[str | None] = ContextVar("request_id", default=None)
REQUEST_ID = re.compile(r"^[A-Za-z0-9-]{8,64}$")

# Attributes every LogRecord has; anything else on a record came from `extra`.
_STANDARD = set(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {"message", "taskName"}


def user_ref(user_id: str) -> str:
    """Who made a call, without writing the id itself (local ids contain the username)."""
    return hashlib.sha256(user_id.encode()).hexdigest()[:16]


def _frames(exc: BaseException) -> str:
    # Frames and exception classes, never messages: a pydantic ValidationError's message
    # quotes the input it rejected, which can be a user's own text.
    parts, seen = [], set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        parts.append(type(exc).__name__ + "\n" + "".join(traceback.format_tb(exc.__traceback__)))
        exc = exc.__cause__ or exc.__context__
    return "--- raised while handling ---\n".join(reversed(parts))


def _clean(value):
    if value is None or isinstance(value, bool | int | float):
        return value
    text = str(value)
    return text if len(text) <= MAX_VALUE else text[: MAX_VALUE - 1] + "…"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "time": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": _clean(record.getMessage()),
        }
        if (rid := request_id.get()) is not None:
            entry["request_id"] = rid
        for key, value in vars(record).items():
            if key not in _STANDARD and key not in entry:
                entry[key] = _clean(value)
        if record.exc_info and record.exc_info[1] is not None:
            entry["error"] = type(record.exc_info[1]).__name__
            entry["traceback"] = _frames(record.exc_info[1])[-MAX_TRACEBACK:]
        return json.dumps(entry, ensure_ascii=False, default=str)


def configure(log_format: str, level: str = "INFO") -> None:
    """JSON on stdout replaces any handler already there (Lambda's own writes plain text)."""
    if log_format != "json":
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logging.basicConfig(level=level, handlers=[handler], force=True)
    # httpx logs every outgoing call (OSV, EPSS, GitHub) at INFO: thousands of lines a scan.
    logging.getLogger("httpx").setLevel(logging.WARNING)
