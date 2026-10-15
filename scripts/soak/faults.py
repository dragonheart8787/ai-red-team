"""The faults a soak injects, and how each is applied (D66).

Six kinds, drawn at random -- from a shuffled bag, so that every kind is drawn once before any is
drawn twice -- every 10 to 20 minutes:

* ``postgres_restart``   ``service postgresql restart`` (every connection dies; locks are released)
* ``docker_restart``     SIGTERM to ``dockerd``, wait for it, start it again (a daemon restart
                         without live-restore: running containers are stopped)
* ``kill9_scheduler``    ``kill -9`` of the scheduler process
* ``kill9_reconciler``   ``kill -9`` of the reconciler process
* ``kill9_control_plane`` ``kill -9`` of the control-plane worker (its tool containers are not
                         touched: they are left for the reconciler, which is the point)
* ``pause_container``    ``docker pause`` of a running tool container of the soak, unpaused
                         20-90 s later
"""

from __future__ import annotations

import os
import random
import signal
import subprocess
import time

from scripts.soak import lib

KINDS = ("postgres_restart", "docker_restart", "kill9_scheduler", "kill9_reconciler",
         "kill9_control_plane", "pause_container")


class Bag:
    """Every kind once, in a random order, then again."""

    def __init__(self, rng: random.Random, kinds: tuple[str, ...] = KINDS):
        self.rng = rng
        self.kinds = kinds
        self.items: list[str] = []

    def draw(self) -> str:
        if not self.items:
            self.items = list(self.kinds)
            self.rng.shuffle(self.items)
        return self.items.pop()


def postgres_restart() -> dict:
    started = time.monotonic()
    done = subprocess.run(["service", "postgresql", "restart"], capture_output=True, text=True,
                          timeout=180)
    return {"ok": done.returncode == 0, "action_s": round(time.monotonic() - started, 1),
            "detail": (done.stdout + done.stderr).strip()[-200:]}


def _dockerd_pids() -> list[int]:
    done = subprocess.run(["pgrep", "-x", "dockerd"], capture_output=True, text=True)
    return [int(p) for p in done.stdout.split()]


def docker_restart() -> dict:
    started = time.monotonic()
    pids = _dockerd_pids()
    for pid in pids:
        os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline and _dockerd_pids():
        time.sleep(1)
    killed_hard = False
    for pid in _dockerd_pids():
        os.kill(pid, signal.SIGKILL)
        killed_hard = True
    time.sleep(2)
    # (the way this machine starts it: detached, its own session, its log kept)
    log = open("/tmp/dockerd.log", "ab")
    subprocess.Popen(["dockerd"], stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                     start_new_session=True)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline and not lib.docker_reachable():
        time.sleep(1)
    return {"ok": lib.docker_reachable(), "action_s": round(time.monotonic() - started, 1),
            "old_pids": pids, "killed_hard": killed_hard}


def pause_container(rng: random.Random, owners: set[str], *, wait_s: float = 300.0) -> dict:
    """Pause one running tool container of the soak (or say there was none to pause)."""
    client = lib.docker_client()
    deadline = time.monotonic() + wait_s
    while True:
        running = [c for c in client.containers.list(filters={"label": lib.OWNER_LABEL,
                                                              "status": "running"})
                   if (c.labels or {}).get(lib.OWNER_LABEL) in owners]
        if running or time.monotonic() > deadline:
            break
        time.sleep(1)
    if not running:
        return {"ok": False, "detail": "no_running_container_to_pause"}
    victim = rng.choice(running)
    hold = rng.uniform(20, 90)
    victim.pause()
    return {"ok": True, "container": victim.short_id, "name": victim.name,
            "run_id": (victim.labels or {}).get(lib.RUN_LABEL), "hold_s": round(hold, 1),
            "paused_at": lib.now()}


def unpause(container_id: str) -> dict:
    try:
        client = lib.docker_client()
        container = client.containers.get(container_id)
        status = container.status
        if status == "paused":
            container.unpause()
            return {"unpaused": True}
        return {"unpaused": False, "status_then": status}
    except Exception as exc:  # noqa: BLE001 -- the container may be gone (killed, removed)
        return {"unpaused": False, "error": f"{type(exc).__name__}: {str(exc)[:120]}"}
