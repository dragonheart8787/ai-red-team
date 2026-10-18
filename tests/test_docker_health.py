"""One answer to "is Docker lost?", for both services (ACCEPTANCE 5.109).

The table of ``control_plane/docker_health.py`` as cases; the two services' own ``_translate``
shown to give the same answer to every one of them; and the case that was wrong -- a daemon that
dies under a dispatch in flight -- through the scheduler's real tick, ending with exit 5, not 1.
"""

from __future__ import annotations

import pytest
import requests
from docker.errors import APIError, DockerException, NotFound
from sqlalchemy.exc import OperationalError

from control_plane import docker_health as dh
from control_plane.orchestrator import stages
from control_plane.reconciler import emit as reconciler_emit
from control_plane.reconciler import service as reconciler_service
from control_plane.scheduler import service as scheduler_service
from control_plane.scheduler import vocab
from control_plane.scheduler.service import Scheduler
from tests import scheduler_support as sup
from tests.test_scheduler_service import _global_events, _stage, world  # noqa: F401


def api(status: int) -> APIError:
    response = requests.Response()
    response.status_code = status
    return APIError(str(status), response, "explanation")


def not_found() -> NotFound:
    response = requests.Response()
    response.status_code = 404
    return NotFound("No such container", response, "No such container")


def wrapped_socket_error() -> Exception:
    """What the SDK raises when the socket file is gone (the exception of the 5.109 traceback)."""
    try:
        try:
            raise FileNotFoundError(2, "No such file or directory")
        except FileNotFoundError as inner:
            raise requests.exceptions.ConnectionError("Connection aborted.", inner) from inner
    except requests.exceptions.ConnectionError as exc:
        return exc


def chained(outer: Exception, inner: Exception) -> Exception:
    try:
        try:
            raise inner
        except Exception as e:  # noqa: BLE001
            raise outer from e
    except Exception as exc:  # noqa: BLE001
        return exc


def implicit(outer: Exception, inner: Exception) -> Exception:
    """``outer`` raised while handling ``inner`` (no ``from``): only ``__context__`` links them."""
    try:
        try:
            raise inner
        except Exception:  # noqa: BLE001
            raise outer  # noqa: B904
    except Exception as exc:  # noqa: BLE001
        return exc


CASES = [
    ("a container that is not there", not_found(), dh.GONE),
    ("a conflict the daemon answered", api(409), dh.ANSWERED),
    ("a bad request", api(400), dh.ANSWERED),
    ("a server error", api(500), dh.LOST),
    ("a bad gateway", api(502), dh.LOST),
    ("an SDK error with no HTTP answer",
     DockerException("Error while fetching server API version"), dh.LOST),
    ("the connection refused", requests.exceptions.ConnectionError("refused"), dh.LOST),
    ("a read that timed out", requests.exceptions.ReadTimeout("slow"), dh.LOST),
    ("a builtin connection error", ConnectionRefusedError(111, "refused"), dh.LOST),
    ("a broken pipe", BrokenPipeError(32, "pipe"), dh.LOST),
    ("a timeout", TimeoutError("timed out"), dh.LOST),
    ("the socket file gone, as the SDK wraps it", wrapped_socket_error(), dh.LOST),
    ("a Docker error wrapping a host file error",
     chained(DockerException("cannot talk to docker"), FileNotFoundError(2, "x")), dh.LOST),
    ("a bug that wraps a lost daemon (cause)",
     chained(RuntimeError("dispatch failed"), requests.exceptions.ConnectionError("x")), dh.LOST),
    ("a bug that wraps a lost daemon (context)",
     implicit(RuntimeError("dispatch failed"), ConnectionRefusedError(111, "refused")), dh.LOST),
    ("a bug that wraps a vanished container", chained(RuntimeError("x"), not_found()), dh.GONE),
    ("a bug that wraps a daemon's refusal", chained(RuntimeError("x"), api(409)), dh.ANSWERED),
    ("a bug that wraps nothing of Docker's",
     chained(RuntimeError("x"), FileNotFoundError(2, "no such directory")), None),
    ("a bare host file error", FileNotFoundError(2, "no such directory"), None),
    ("a permission error on a host directory", PermissionError(13, "denied"), None),
    ("a bug", RuntimeError("something nobody planned for"), None),
    ("a lost database", OperationalError("SELECT 1", {}, Exception("gone")), None),
]


@pytest.mark.parametrize("what, exc, expected", CASES, ids=[c[0] for c in CASES])
def test_the_classification(what, exc, expected):
    assert dh.classify(exc) == expected, what
    assert dh.is_lost(exc) == (expected == dh.LOST)


@pytest.mark.parametrize("what, exc, expected", CASES, ids=[c[0] for c in CASES])
def test_the_scheduler_and_the_reconciler_give_the_same_answer(what, exc, expected):
    scheduler_lost = scheduler_service._translate(exc).reason == vocab.STOP_DOCKER_LOST
    reconciler_lost = reconciler_service._translate(exc).reason == reconciler_emit.STOP_DOCKER_LOST
    assert scheduler_lost == reconciler_lost == (expected == dh.LOST), what


@pytest.mark.parametrize("exc", [wrapped_socket_error(), requests.exceptions.ConnectionError("x"),
                                 api(503)], ids=["socket", "refused", "503"])
def test_the_scheduler_exits_5_not_1_for_a_daemon_that_is_gone(exc):
    stop = scheduler_service._translate(exc)
    assert (stop.reason, stop.exit_code) == (vocab.STOP_DOCKER_LOST, 5)
    assert vocab.EXIT_DOCKER_LOST == 5


def test_a_daemon_that_dies_under_a_dispatch_in_flight_stops_the_scheduler_with_exit_5(
        world):  # noqa: F811
    """The traceback of 5.109, through the real tick: the container has started, the run is
    recorded ``running``, and the sandbox raises what the SDK raises when the socket is gone."""

    class DiesUnderTheRun:
        calls = 0

        def run(self, **kwargs):
            self.calls += 1
            raise wrapped_socket_error()

    sandbox = DiesUnderTheRun()
    assert Scheduler(sandbox=sandbox).run(interval=0, max_ticks=3) == vocab.EXIT_DOCKER_LOST == 5
    assert sandbox.calls == 1                                  # one attempt, never a second
    stage, detail = _stage(world)
    assert stage == stages.DISPATCHING                # left for the reconciler, as designed
    runs = sup.rows(world["engagement_id"], "SELECT status FROM tool_runs")
    assert [r["status"] for r in runs] == ["running"]
    stopped = _global_events("scheduler.stopped")
    assert stopped and stopped[0]["payload"]["reason_code"] == vocab.STOP_DOCKER_LOST
    assert len(sup.audit(world["engagement_id"], "scheduler.dispatched")) == 1
