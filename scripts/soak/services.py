"""The three processes of a soak, and the supervisor that restarts them (D66).

The product's own command lines, unchanged: ``scripts/run_scheduler.py``,
``scripts/run_reconciler.py`` (on a pseudo-terminal, the confirmation typed -- there is no
``--yes``) and the soak's control-plane worker. Neither service reconnects or restarts itself
(their own documentation says so and exits
with a code instead); the supervisor here is what an operator's service manager would be, and every
exit it sees is written down with its cause: a ``kill -9`` the injector sent, a code that a fault
the injector applied explains (``4`` the database went away, ``5`` Docker did), or **nothing that
explains it** -- which the conductor treats as a finding.
"""

from __future__ import annotations

import json
import os
import pty
import select
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from scripts.soak import lib

PY = sys.executable
#: exit codes of the services and what they say; a service that exits with one of these *after a
#: fault that explains it* is behaving as documented
EXIT_DB_LOST = 4
EXIT_DOCKER_LOST = 5
EXIT_LOCK_LOST = 6
EXPLAINED_BY = {
    "postgres_restart": {EXIT_DB_LOST, EXIT_LOCK_LOST},
    "docker_restart": {EXIT_DOCKER_LOST},
}
#: how long after a fault an exit is attributed to it
ATTRIBUTION_S = 300


@dataclass
class Service:
    name: str
    argv: list[str]
    env: dict[str, str]
    log: Path
    pty_answer: str | None = None            # the phrase to type back, if any
    pid: int | None = None
    started_at: float = 0.0
    exits: list[dict] = field(default_factory=list)
    starts: int = 0
    killed_by_injector: bool = False
    _master: int | None = None
    _proc: subprocess.Popen | None = None
    _reader: threading.Thread | None = None
    last_pass_at: float = 0.0
    passes: int = 0


class Supervisor:
    def __init__(self, run_dir: Path, journal: lib.Journal, env: dict[str, str],
                 engagements: list[str], evidence_dir: Path, *, interval_reconciler: float,
                 interval_scheduler: float, worker_args: list[str]):
        self.run_dir = run_dir
        self.journal = journal
        self.lock = threading.Lock()
        self.logs = run_dir / "logs"
        self.logs.mkdir(parents=True, exist_ok=True)
        enable = ["kill", "container", "proxy"]
        reconciler_argv = [PY, str(lib.REPO_ROOT / "scripts" / "run_reconciler.py"),
                           "--mode", "state-only", "--interval", str(interval_reconciler),
                           "--evidence-dir", str(evidence_dir)]
        for category in enable:
            reconciler_argv += ["--enable", category]
        for eid in engagements:
            reconciler_argv += ["--engagement", eid]
        self.services: dict[str, Service] = {
            "scheduler": Service("scheduler", [PY, str(lib.REPO_ROOT / "scripts" /
                                                       "run_scheduler.py"),
                                               "--interval", str(interval_scheduler)],
                                 env, self.logs / "scheduler.log"),
            "reconciler": Service("reconciler", reconciler_argv, env, self.logs / "reconciler.log",
                                  pty_answer="enable " + " ".join(sorted(enable))),
            "worker": Service("worker", [PY, "-m", "scripts.soak.worker", "--run-dir",
                                         str(run_dir), *worker_args], env,
                              self.logs / "worker.log"),
        }

    # -- starting ---------------------------------------------------------------------------

    def start(self, name: str, *, reason: str) -> None:
        svc = self.services[name]
        svc.killed_by_injector = False
        if svc.pty_answer is not None:
            self._start_pty(svc)
        else:
            out = open(svc.log, "ab")
            svc._proc = subprocess.Popen(svc.argv, cwd=lib.REPO_ROOT, env=svc.env, stdout=out,
                                         stderr=subprocess.STDOUT, start_new_session=True,
                                         stdin=subprocess.DEVNULL)
            svc.pid = svc._proc.pid
        svc.started_at = lib.now()
        svc.starts += 1
        self.journal.write("service.started", service=name, pid=svc.pid, reason=reason,
                           start_number=svc.starts)

    def _start_pty(self, svc: Service) -> None:
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(str(lib.REPO_ROOT))
            os.execve(PY, svc.argv, svc.env)
        svc.pid, svc._master = pid, fd
        svc._proc = None
        svc._reader = threading.Thread(target=self._read_pty, args=(svc, fd, pid), daemon=True)
        svc._reader.start()

    def _read_pty(self, svc: Service, fd: int, pid: int) -> None:
        """The reconciler's output: kept whole in its log, and every pass noted."""
        sent = False
        shown = b""
        buffer = b""
        with open(svc.log, "ab") as log:
            while True:
                ready, _, _ = select.select([fd], [], [], 1.0)
                if not ready:
                    if svc.pid != pid:
                        return
                    continue
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    return
                if not chunk:
                    return
                log.write(chunk)
                log.flush()
                shown += chunk
                if not sent and b"Type exactly:" in shown and shown.rstrip().endswith(b">"):
                    os.write(fd, (svc.pty_answer + "\n").encode())
                    sent = True
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    self._note_line(svc, line.decode(errors="replace").strip())

    def _note_line(self, svc: Service, line: str) -> None:
        if not line.startswith("{"):
            return
        try:
            record = json.loads(line)
        except ValueError:
            return
        if "summary" in record:
            svc.last_pass_at = lib.now()
            svc.passes += 1
            self.journal.write("reconciler.pass", planned=record.get("summary"),
                               outcomes=record.get("outcomes"), reports=record.get("reports"),
                               limited=record.get("limited"), held_back=record.get("held_back"),
                               truncated=record.get("truncated"))
        elif "kind" in record and "outcome" in record:
            self.journal.write("reconciler.action", action=record.get("kind"),
                               reason=record.get("reason_code"), subject=record.get("subject_id"),
                               engagement=record.get("engagement_id"),
                               outcome=record.get("outcome"), detail=record.get("detail"))

    # -- looking ----------------------------------------------------------------------------

    def exited(self, name: str) -> int | None:
        """The exit code if the service's process is gone (and reaped), else ``None``."""
        svc = self.services[name]
        if svc.pid is None:
            return None
        if svc._proc is not None:
            code = svc._proc.poll()
            return code
        try:
            done, status = os.waitpid(svc.pid, os.WNOHANG)
        except ChildProcessError:
            return -1
        if done == 0:
            return None
        return os.waitstatus_to_exitcode(status)

    def pids(self) -> dict[str, int | None]:
        return {name: svc.pid for name, svc in self.services.items()}

    def all_alive(self) -> bool:
        return all(svc.pid is not None and self.exited_peek(svc) for svc in
                   self.services.values())

    @staticmethod
    def exited_peek(svc: Service) -> bool:
        return lib.alive(svc.pid)

    # -- the injector's kill ------------------------------------------------------------------

    def kill9(self, name: str) -> int | None:
        svc = self.services[name]
        pid = svc.pid
        if pid is None or not lib.alive(pid):
            return None
        svc.killed_by_injector = True
        os.kill(pid, signal.SIGKILL)
        return pid

    def stop_all(self, grace: float = 60.0) -> None:
        for svc in self.services.values():
            if svc.pid and lib.alive(svc.pid):
                try:
                    os.kill(svc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline and any(lib.alive(s.pid) for s in
                                                   self.services.values()):
            time.sleep(1)
        for svc in self.services.values():
            if svc.pid and lib.alive(svc.pid):
                os.kill(svc.pid, signal.SIGKILL)
        for name in self.services:
            self.exited(name)
