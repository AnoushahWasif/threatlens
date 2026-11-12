import io
import json
import logging
import sys

import pytest
from test_scans import REQUIREMENTS, fake_pipeline  # noqa: I001

from threatlens_api import logs
from threatlens_api.logs import JsonFormatter
from threatlens_api.settings import Settings


@pytest.fixture
def lines():
    """Everything the threatlens logger writes, as parsed JSON objects."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("threatlens")
    logger.addHandler(handler)
    old_level = logger.level
    logger.setLevel(logging.INFO)

    def read():
        return [json.loads(line) for line in stream.getvalue().splitlines()]

    read.raw = stream
    yield read
    logger.removeHandler(handler)
    logger.setLevel(old_level)


log = logging.getLogger("threatlens")


# --- the formatter ------------------------------------------------------------------------


def test_one_json_object_with_the_extra_fields(lines):
    log.info("scan done", extra={"scan_id": "abc", "findings": 3, "ok": True, "x": None})
    [entry] = lines()
    assert entry["message"] == "scan done" and entry["level"] == "INFO"
    assert entry["logger"] == "threatlens"
    assert (entry["scan_id"], entry["findings"], entry["ok"], entry["x"]) == ("abc", 3, True, None)
    assert entry["time"].endswith("+00:00")
    # Nothing from LogRecord's own attributes leaks in.
    assert not {"args", "msg", "pathname", "lineno", "thread", "taskName"} & entry.keys()


def test_a_value_cannot_forge_a_second_line(lines):
    log.warning("odd", extra={"route": 'x"}\n{"level": "ERROR", "message": "forged'})
    raw = lines.raw.getvalue()
    assert raw.count("\n") == 1
    assert lines()[0]["route"].startswith('x"}\n{')


def test_long_values_are_cut(lines):
    log.info("x" * 1000, extra={"v": "y" * 1000})
    [entry] = lines()
    assert len(entry["message"]) == logs.MAX_VALUE and entry["message"].endswith("…")
    assert len(entry["v"]) == logs.MAX_VALUE


def test_other_values_are_written_as_text(lines):
    log.info("x", extra={"thing": {"a": [1, 2]}, "number": 1.5})
    [entry] = lines()
    assert entry["thing"] == "{'a': [1, 2]}" and entry["number"] == 1.5


def test_exceptions_get_their_class_and_frames_but_no_message(lines):
    from pydantic import BaseModel, ValidationError

    class Project(BaseModel):
        name: int

    def load(text):
        try:
            Project(name=text)
        except ValidationError as e:
            raise RuntimeError(f"couldn't load {text}") from e

    # Built at run time: traceback lines quote the source, which never holds user data.
    try:
        load("my " + "sec" + "ret project")
    except RuntimeError:
        log.exception("failed")
    [entry] = lines()
    assert entry["level"] == "ERROR" and entry["error"] == "RuntimeError"
    trace = entry["traceback"]
    assert "ValidationError" in trace and "RuntimeError" in trace and "in load" in trace
    assert trace.index("ValidationError") < trace.index("RuntimeError")  # cause first
    assert "secret" not in lines.raw.getvalue()


def test_an_error_raised_while_handling_another_keeps_both(lines):
    try:
        try:
            {}["missing"]
        except KeyError:
            raise ValueError("cleanup failed")  # noqa: B904 - the implicit chain under test
    except ValueError:
        log.exception("failed")
    [entry] = lines()
    assert entry["traceback"].index("KeyError") < entry["traceback"].index("ValueError")


def test_a_long_traceback_is_capped(lines):
    error = None
    for i in range(200):
        try:
            raise KeyError(i) from error
        except KeyError as e:
            error = e
    try:
        raise ValueError("last") from error
    except ValueError:
        log.exception("failed")
    [entry] = lines()
    assert len(entry["traceback"]) == logs.MAX_TRACEBACK
    assert entry["traceback"].rstrip().endswith('raise ValueError("last") from error')


def test_an_exception_chain_that_loops_still_logs(lines):
    a, b = ValueError("a"), KeyError("b")
    a.__context__, b.__context__ = b, a
    try:
        raise a
    except ValueError:
        log.exception("failed")
    [entry] = lines()
    assert entry["traceback"].count("ValueError") == 1


def test_the_request_id_is_added_while_it_is_set(lines):
    token = logs.request_id.set("r1")
    log.info("inside")
    logs.request_id.reset(token)
    log.info("outside")
    inside, outside = lines()
    assert inside["request_id"] == "r1" and "request_id" not in outside


def test_text_format_leaves_logging_alone():
    root = logging.getLogger()
    before = root.handlers[:]
    logs.configure("text")
    assert root.handlers == before


def test_json_format_puts_one_json_handler_on_stdout():
    logs.configure("json", "WARNING")
    root = logging.getLogger()
    [handler] = root.handlers
    assert isinstance(handler.formatter, JsonFormatter) and handler.stream is sys.stdout
    assert root.level == logging.WARNING
    assert logging.getLogger("httpx").level == logging.WARNING


def test_prod_needs_json_logs():
    from test_settings import prod

    with pytest.raises(ValueError, match="LOG_FORMAT must be json"):
        prod(log_format="text")


# --- through the app ----------------------------------------------------------------------


def test_one_line_per_request_with_the_route_template(client, lines):
    project = client.post("/projects", json={"name": "p"}).json()["id"]
    resp = client.get(f"/projects/{project}")
    entry = [e for e in lines() if e["message"] == "request"][-1]
    assert entry["method"] == "GET"
    assert entry["route"] == "/projects/{project_id}"
    assert entry["status"] == 200
    assert entry["request_id"] == resp.headers["x-request-id"]
    assert isinstance(entry["duration_ms"], float)


def test_the_request_line_says_who_without_their_id(client, anon, token, lines):
    me = client.get("/projects")
    other = anon.get("/projects", headers={"authorization": f"Bearer {token('bob')}"})
    nobody = anon.get("/projects")
    assert (me.status_code, other.status_code, nobody.status_code) == (200, 200, 401)
    users = [e["user"] for e in lines() if e["message"] == "request"]
    assert len(users[0]) == 16 and users[0] != users[1]
    assert users[2] is None
    assert "bob" not in lines.raw.getvalue()


def test_a_client_request_id_is_logged_beside_ours(client, lines):
    resp = client.get("/health", headers={"X-Request-ID": "abc-12345678"})
    [entry] = [e for e in lines() if e["message"] == "request"]
    assert entry["client_request_id"] == "abc-12345678"
    assert entry["request_id"] == resp.headers["x-request-id"]


@pytest.mark.parametrize(
    "bad", ["x\r\nfake-log-line", "éééééééé", "short", "a" * 65, 'a"}{"level":"x"}']
)
def test_a_rejected_client_request_id_never_reaches_the_logs(client, lines, bad):
    client.get("/health", headers={"X-Request-ID": bad.encode()})
    [entry] = [e for e in lines() if e["message"] == "request"]
    assert "client_request_id" not in entry
    raw = lines.raw.getvalue()
    assert "fake-log-line" not in raw and "ééé" not in raw and "short" not in raw


def test_an_unknown_path_is_logged_cut_short(client, lines):
    client.get("/nope/" + "a" * 500)
    entry = [e for e in lines() if e["message"] == "request"][-1]
    assert entry["status"] == 404 and len(entry["route"]) == 100


def test_no_token_or_body_ever_reaches_the_logs(client, lines):
    token = client.headers["authorization"].removeprefix("Bearer ")
    client.post("/projects", json={"name": "secret project name"})
    client.get("/projects", headers={"authorization": "Bearer not.a.valid-token"})
    raw = lines.raw.getvalue()
    assert raw
    for needle in (token, token[-20:], "secret project name", "not.a.valid-token"):
        assert needle not in raw


def test_logs_from_sync_routes_carry_the_request_id(app, client, lines):
    real_list = app.state.projects.list

    def noisy(owner):
        log.warning("listing projects")
        return real_list(owner)

    app.state.projects.list = noisy
    resp = client.get("/projects")
    inner = [e for e in lines() if e["message"] == "listing projects"]
    assert inner[0]["request_id"] == resp.headers["x-request-id"]


def test_an_unhandled_error_is_logged_once_with_the_request_id(app, client, lines):
    def broken(owner):
        raise RuntimeError("db exploded")

    app.state.projects.list = broken
    resp = client.get("/projects")
    assert resp.status_code == 500
    [error] = [e for e in lines() if e["message"] == "unhandled error"]
    assert error["error"] == "RuntimeError"
    assert error["request_id"] == resp.headers["x-request-id"]
    access = [e for e in lines() if e["message"] == "request"][-1]
    assert access["status"] == 500


def test_the_request_id_does_not_leak_into_the_next_request(app, client, lines):
    client.get("/health")
    log.info("between requests")
    assert "request_id" not in [e for e in lines() if e["message"] == "between requests"][0]


# --- the worker ---------------------------------------------------------------------------


def test_a_finished_scan_logs_its_counts(client, app, lines):
    runner = app.state.local_runner
    runner.worker.pipeline = fake_pipeline()
    project = client.post("/projects", json={"name": "p"}).json()["id"]
    scan = client.post(
        f"/projects/{project}/scans", params={"filename": "requirements.txt"}, content=REQUIREMENTS
    ).json()
    runner.run_pending()
    [done] = [e for e in lines() if e["message"] == "scan done"]
    assert done["scan_id"] == scan["id"]
    # The upload's request id, so a user's report leads from the upload to the scan.
    [upload] = [e for e in lines() if e["message"] == "request" and e["status"] == 202]
    assert done["request_id"] == upload["request_id"]
    assert (done["dependencies"], done["findings"], done["attempt"]) == (2, 2, 1)
    assert isinstance(done["seconds"], float)


def test_a_failed_scan_logs_why(client, app, lines):
    runner = app.state.local_runner
    runner.worker.pipeline = fake_pipeline()
    project = client.post("/projects", json={"name": "p"}).json()["id"]
    scan = client.post(
        f"/projects/{project}/scans", params={"filename": "requirements.txt"}, content=REQUIREMENTS
    ).json()
    app.state.blobs._data.clear()
    runner.run_pending()
    [failed] = [e for e in lines() if e["message"] == "scan failed"]
    assert failed["level"] == "WARNING" and failed["scan_id"] == scan["id"]
    assert "no longer there" in failed["reason"]


def test_the_worker_clears_the_request_id_after_each_message(client, app, lines):
    runner = app.state.local_runner
    runner.worker.pipeline = fake_pipeline()
    project = client.post("/projects", json={"name": "p"}).json()["id"]
    client.post(
        f"/projects/{project}/scans", params={"filename": "requirements.txt"}, content=REQUIREMENTS
    )
    runner.run_pending()
    assert logs.request_id.get() is None


def test_prod_app_writes_json_to_stdout(capsys):
    from test_settings import prod

    from threatlens_api.main import create_app

    create_app(prod())
    logging.getLogger("threatlens").warning("hello", extra={"n": 1})
    entry = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert (entry["message"], entry["n"]) == ("hello", 1)


def test_settings_default_to_text():
    assert Settings(_env_file=None).log_format == "text"
