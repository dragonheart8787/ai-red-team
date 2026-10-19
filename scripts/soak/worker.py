"""The control plane of a soak: threads that keep proposing actions through the real pipeline.

    python -m scripts.soak.worker --run-dir DIR [--threads 4] [--mean-gap 6] [--budget 60]

Each request is one ``propose_action`` call with an idempotency key of its own, to one of the
soak's engagements:

* ``allow`` (60 %): in scope, decided ALLOW, dispatched here, in this process, to a real container
  (``DockerSandbox``) -- the path a ``kill -9`` of the control plane interrupts;
* ``human`` (30 %): in scope, the reviewer names sensitive data, so the decision is HUMAN_APPROVAL
  and the pipeline stops; the conductor's approver grants (or denies) it and the scheduler
  dispatches it;
* ``deny`` (10 %): outside the scope object, decided DENY.

Every request is written to ``requests.jsonl`` *before* the call and again when it returns. When
this process is killed and started again, it finds the requests that never returned and, for half
of them (decided by the hash of the key, so the choice is the same on every run), calls
``propose_action`` again with the **same key** -- a client that retries -- and drops the others, a
client that gave up. A retry must resume, not repeat; that is what the soak's checks look at.

A call that fails for a reason that a fault explains (the database or Docker is down) is retried
with the same key, 5 times, with growing waits; any other exception is written down as
``worker.unexpected`` and the conductor treats it as a finding.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import random
import signal
import sys
import threading
import time
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from scripts.soak import lib  # noqa: E402
from scripts.soak import world as world_mod  # noqa: E402

KINDS = (("allow", 0.6), ("human", 0.3), ("deny", 0.1))


def pick_kind(rng: random.Random) -> str:
    roll = rng.random()
    total = 0.0
    for kind, weight in KINDS:
        total += weight
        if roll < total:
            return kind
    return KINDS[-1][0]


def retried_after_a_crash(key: str) -> bool:
    """Half of the requests a killed worker never saw return are asked again; fixed by the key."""
    return int(hashlib.sha256(key.encode()).hexdigest()[:4], 16) % 2 == 0


def transient(exc: BaseException) -> bool:
    """A failure that a fault the soak injects explains: the database or Docker went away."""
    import requests
    from docker.errors import DockerException
    from sqlalchemy.exc import DBAPIError, InterfaceError, OperationalError

    from tool_gateway.sandbox import SandboxUnavailable
    known = (OperationalError, InterfaceError, SandboxUnavailable, DockerException,
             requests.exceptions.ConnectionError, ConnectionError, TimeoutError)
    return isinstance(exc, known) or (isinstance(exc, DBAPIError) and exc.connection_invalidated)


class Worker:
    def __init__(self, run_dir: Path, args):
        self.run_dir = run_dir
        self.args = args
        self.world = world_mod.load(run_dir)
        self.requests = lib.Journal(run_dir / "requests.jsonl")
        self.events = lib.Journal(run_dir / "events.jsonl")
        self.stop = threading.Event()
        self.rng = random.Random(args.seed)

    # -- one request ----------------------------------------------------------------------

    def new_request(self, rng: random.Random) -> dict:
        engagement = rng.choice(self.world["engagements"])
        kind = pick_kind(rng)
        host = engagement["outside"] if kind == "deny" else rng.choice(engagement["hosts"])
        return {"req": f"REQ-{uuid.uuid4().hex[:12]}", "key": f"soak-{uuid.uuid4().hex[:16]}",
                "eid": engagement["id"], "scope_id": engagement["scope_id"], "what": kind,
                "cidr": engagement["cidr"], "ports": str(rng.randrange(1, 65536)),
                "host": host}

    def call(self, req: dict):
        from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
        from control_plane.api.function_api import propose_action
        from control_plane.capability.broker import Budget
        from tests import scheduler_support as sup
        from tests.task_support import task_for
        from tool_gateway.sandbox import DockerSandbox

        reviewer = (HonestFakeReviewer(sensitive_hint=("pii",)) if req["what"] == "human"
                    else HonestFakeReviewer())
        proposal = sup.proposal_for(req["scope_id"], host=req["host"], ports=req["ports"])
        # D68: a request names the task it serves, as a harness's worker would. One task per
        # request, however often it is retried; created inside the retry loop, so a fault
        # that lands on the task's own insert is retried like any other.
        if "task_id" not in req:
            req["task_id"] = task_for(req["eid"], proposal)
        proposal = dataclasses.replace(proposal, task_id=req["task_id"])
        return propose_action(
            engagement_id=req["eid"],
            proposal=proposal,
            reviewer=reviewer, policy=sup.effective_policy(req["eid"]), agent_id="soak-worker",
            sandbox=DockerSandbox() if req["what"] == "allow" else None,
            network_allowlist=[req["cidr"]],
            budget=Budget(max_duration_seconds=self.args.budget), idempotency_key=req["key"])

    def run_request(self, req: dict, *, resumed: bool = False) -> None:
        self.requests.write("started", **req, resumed=resumed)
        waits = (3, 6, 12, 24, 48)
        for attempt in range(len(waits) + 1):
            try:
                outcome = self.call(req)
            except BaseException as exc:  # noqa: BLE001
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                detail = {"req": req["req"], "key": req["key"], "attempt": attempt,
                          "type": type(exc).__name__, "message": str(exc)[:300]}
                if transient(exc) and attempt < len(waits) and not self.stop.is_set():
                    self.events.write("worker.retry", **detail)
                    if self.stop.wait(waits[attempt]):
                        return
                    continue
                self.events.write("worker.gave_up" if transient(exc) else "worker.unexpected",
                                  **detail)
                self.requests.write("done", req=req["req"], ok=False, type=type(exc).__name__)
                return
            self.requests.write("done", req=req["req"], ok=True,
                                decision=getattr(outcome, "decision", None),
                                proposal_id=getattr(outcome, "proposal_id", None),
                                failure=getattr(outcome, "failure", None))
            return

    # -- the loop -------------------------------------------------------------------------

    def unfinished(self) -> list[dict]:
        started: dict[str, dict] = {}
        for record in self.requests.read():
            if record["kind"] == "started":
                started[record["req"]] = record
            elif record["kind"] == "done":
                started.pop(record["req"], None)
        return list(started.values())

    def thread_main(self, index: int, resubmit: list[dict]) -> None:
        rng = random.Random(f"{self.args.seed}-{index}-{time.time_ns()}")
        for req in resubmit:
            if self.stop.is_set():
                return
            self.run_request(req, resumed=True)
        while not self.stop.is_set():
            self.run_request(self.new_request(rng))
            if self.stop.wait(rng.expovariate(1.0 / self.args.mean_gap)):
                return

    def serve(self) -> int:
        leftovers = self.unfinished()
        again = [r for r in leftovers if retried_after_a_crash(r["key"])]
        for record in leftovers:
            if record not in again:
                self.requests.write("done", req=record["req"], ok=False, type="client_gave_up")
        self.events.write("worker.started", pid=_pid(), unfinished=len(leftovers),
                          retried=len(again))
        threads = []
        for index in range(self.args.threads):
            share = [{k: v for k, v in r.items() if k not in ("ts", "at", "kind", "resumed")}
                     for r in again[index::self.args.threads]]
            thread = threading.Thread(target=self.thread_main, args=(index, share), daemon=True)
            thread.start()
            threads.append(thread)
        while not self.stop.is_set():
            self.stop.wait(1.0)
        for thread in threads:
            thread.join(timeout=120)
        self.events.write("worker.stopped", pid=_pid())
        return 0


def _pid() -> int:
    import os
    return os.getpid()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--mean-gap", type=float, default=6.0,
                        help="mean seconds between one thread's requests")
    parser.add_argument("--budget", type=int, default=60, help="max_duration_seconds of a run")
    parser.add_argument("--seed", default="d66")
    args = parser.parse_args(argv)
    lib.load_env()
    worker = Worker(args.run_dir, args)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: worker.stop.set())
    return worker.serve()


if __name__ == "__main__":
    raise SystemExit(main())
