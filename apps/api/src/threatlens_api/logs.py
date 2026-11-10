"""One JSON object per log line, so CloudWatch Logs Insights and metric filters can query
fields (status, duration_ms, scan_id) instead of grepping text.

Only what the code passes in `extra` is logged, and the code only passes ids, counts and
error class names: never request bodies, tokens or uploaded files. Values are cut to a few
hundred characters and JSON-escaped, so a value can't forge a second log line.
"""

import json
import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime

MAX_VALUE = 300
MAX_TRACEBACK = 4_000

# Set by the API's middleware; FastAPI's threadpool copies it into sync routes.
request_id: ContextVar[str | None] = ContextVar("request_id", default=None)

# Attributes every LogRecord has; anything else on a record came from `extra`.
_STANDARD = set(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {"message", "taskName"}


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
        if record.exc_info and record.exc_info[0] is not None:
            entry["error"] = record.exc_info[0].__name__
            trace = self.formatException(record.exc_info)
            entry["traceback"] = trace[-MAX_TRACEBACK:]
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
