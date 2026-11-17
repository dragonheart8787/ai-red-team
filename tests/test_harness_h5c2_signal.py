"""D69 H5c2 (D): a real SIGTERM, sent to a real process, driven by scripted roles.

``scripts/run_harness.py`` is started as a process on the test database. Its Supervisor plans three
tasks; its Worker, on the first task, prints ``WORKER-STARTED`` and waits a few seconds -- the
moment the test sends SIGTERM. The handler only sets a flag (``harness/signals.py``); the loop
finishes the task it is on, reads the flag at its next safe point, completes the tasks it created
and never claimed as ``not_run``, and the process exits 0.

No model, no container, no network: the roles are ``tests/harness_h5c2_roles.py``.
"""

from __future__ import annotations

import os
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.test_harness_h5c1_support import make_world, proposal_rows, task_rows
from tests.test_harness_h5c2_support import enrolled

ROOT = Path(__file__).resolve().parents[1]
TIMEOUT = 40.0


@pytest.fixture
def world(engagement_id, registry):
    return make_world(engagement_id, registry)


def _line(process, deadline) -> str | None:
    """The next line of the process's standard output, or None at the deadline or at its end."""
    while time.monotonic() < deadline:
        ready, _, _ = select.select([process.stdout], [], [], 0.2)
        if ready:
            line = process.stdout.readline()
            return line if line else None
        if process.poll() is not None:
            return None
    return None


def _start(world, **env) -> subprocess.Popen:
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "H5C2_SCOPE_ID": world.scope_id,
                   "H5C2_TASKS": "3", "H5C2_SLOW": "3", **env}
    return subprocess.Popen(
        [sys.executable, "-B", str(ROOT / "scripts" / "run_harness.py"), "run",
         "--role-factory", "tests.harness_h5c2_roles:build", "--objective", "o",
         "--window-limit", "25", "--max-rounds", "5", "--max-model-calls", "100",
         "--no-progress-limit", "5", "--live-task-limit", "200"],
        cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def _wait_for(process, text: str) -> list[str]:
    seen, deadline = [], time.monotonic() + TIMEOUT
    while True:
        line = _line(process, deadline)
        if line is None:
            break
        seen.append(line.rstrip("\n"))
        if text in line:
            break
    return seen


def test_a_real_sigterm_stops_the_process_cleanly_after_the_task_it_is_on(world):
    with enrolled(world.engagement_id):
        process = _start(world)
        try:
            seen = _wait_for(process, "WORKER-STARTED")
            assert seen and seen[-1] == "WORKER-STARTED", seen   # the Worker is in its first call
            process.send_signal(signal.SIGTERM)
            deadline = time.monotonic() + TIMEOUT
            while process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.1)
            stopped = process.poll() is not None
        finally:
            if process.poll() is None:
                process.kill()
            err = process.stderr.read()
            process.stdout.close()
            process.stderr.close()
            process.wait()

    assert stopped, "the process did not stop after SIGTERM"
    assert process.returncode == 0, err
    assert "harness stopped (exit 0): reason=signal_or_once" in err
    rows = task_rows(world.engagement_id)
    summaries = [row[5] for row in rows]
    # the task the signal found in flight went through its own path to the end: a proposal was
    # made and the task completed with the pipeline's answer (a DENY here), not as not_run
    assert [row[1] for row in rows] == ["completed"] * 3
    assert summaries.count("not_run") == 2 and summaries.count("DENY") == 1, summaries
    assert len(proposal_rows(world.engagement_id)) == 1
    assert rows[0][5] == "DENY"                          # the oldest task was claimed first
    # nothing is left for the next run to refuse on
    assert not any(row[1] in ("queued", "claimed", "running") for row in rows)


def test_a_process_that_is_not_signalled_runs_to_its_cap(world):
    with enrolled(world.engagement_id):
        process = _start(world, H5C2_SLOW="0")
        try:
            out, err = process.communicate(timeout=TIMEOUT)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
    assert process.returncode == 13, err
    assert "WORKER-STARTED" not in out
