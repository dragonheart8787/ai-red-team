"""The soak, D66: the scheduler, the reconciler and a control plane that never stops proposing,
under faults, for hours.

    python -m scripts.soak.conductor --run-dir DIR [--hours 4] [--engagements 3]
                                     [--fault-min 10 --fault-max 20] [--check-every 15]

What runs, all of it the product's own code beside a test harness:

* the **scheduler** (``scripts/run_scheduler.py``) and the **reconciler**
  (``scripts/run_reconciler.py``, ``state-only``, ``kill`` / ``container`` / ``proxy`` enabled,
  the confirmation typed on a pseudo-terminal), restarted by this program when they exit --
  they do not restart themselves;
* the **control-plane worker** (``scripts.soak.worker``): four threads proposing through the real
  pipeline, ALLOW ones dispatched to real containers in-process, HUMAN_APPROVAL ones left for
* the **approver** in this program, which grants (90 %) or denies (10 %) after 2-20 s, and the
  scheduler dispatches them;
* the **injector**, which every 10-20 minutes applies one of six faults (``faults.py``);
* the **sampler** (every minute: memory, descriptors and Postgres connections of every process,
  Docker's and the temp directory's contents) and the **witness** (``docker events``);
* the **checker**, every 15 minutes and at the end (``checks.py``).

**A finding stops the soak.** The first failed check, the first exit of a service that no injected
fault explains, a service that does not come back, a recovery that does not complete: the injector
and the worker stop, the state is written down as it is, and the program exits with status 3.
Nothing is repaired, and no threshold is moved to get past it.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import signal
import subprocess
import sys
import threading
import time
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from scripts.soak import checks, faults, heartbeat, lib, measure, report, services  # noqa: E402
from scripts.soak import world as world_mod  # noqa: E402

#: the reconciler's thresholds for the soak. Everything not named here is ``.env.example``'s (the
#: derived defaults: B = the capability's budget, P = 915 s, Q = 300 s, margin 60 s). Shortened, and
#: only these, so that what a 4-hour run can reach is reached: a proposal received and never decided
#: is abandoned after 5 minutes instead of an hour, a container at rest is removed after 5 minutes
#: instead of a day, a failed action is retried after 2 minutes instead of 30.
RECONCILER_ENV = {
    "RECONCILER_STAGE_GRACE_S": "300",
    "RECONCILER_RETENTION_S": "300",
    "RECONCILER_RETRY_AFTER_FAILURE_S": "120",
    "RECONCILER_BACKOFF_MAX_S": "60",
    "RECONCILER_SUMMARY_PERIOD_S": "600",
}

#: Resource caps, fixed before the run. A breach is a finding (the run stops): a soak that needs
#: more than this is not a soak of something that holds still. Memory is resident set; descriptors
#: and connections are per process; the rest are the host and the run directory.
CAPS = measure.DEFAULT_CAPS

FAULT_ATTRIBUTION_S = services.ATTRIBUTION_S
RECOVERY_TIMEOUT_S = 20 * 60


class Finding(Exception):
    pass


class Conductor:
    def __init__(self, args):
        self.args = args
        self.run_dir: Path = args.run_dir
        self.journal = lib.Journal(self.run_dir / "events.jsonl")
        self.rng = random.Random(args.seed)
        self.stop = threading.Event()          # the traffic and the faults end
        self.shutdown = threading.Event()      # the supervisors, approver, sampler and witness end
        self.halted: str | None = None
        self.findings: list[dict] = []
        self.samples: list[dict] = []
        self.check_results: list[dict] = []
        self.faults_done: list[dict] = []
        self.world: dict = {}
        self.eids: list[str] = []
        self.sup: services.Supervisor | None = None
        self.last_fault: dict | None = None
        self.evidence_dir = self.run_dir / "evidence"
        self.started = lib.now()
        self.lock = threading.Lock()
        self.pending_seen: dict[str, float] = {}
        self._events_offset = 0
        self.hourly_points: list[dict] = []
        self.caps = self._load_caps()
        self.schema_before: dict[str, str] = {}

    def _load_caps(self) -> dict:
        """The default caps, or the ones measured on this machine (``scripts/soak/measure.py``)."""
        self.caps_document = None
        path = getattr(self.args, "caps_file", None)
        if not path:
            return measure.DEFAULT_CAPS
        self.caps_document = json.loads(Path(path).read_text())
        return self.caps_document["caps"]

    # -- findings ---------------------------------------------------------------------------

    def finding(self, kind: str, detail: str, **extra) -> None:
        record = {"kind": kind, "detail": detail, **extra}
        with self.lock:
            self.findings.append(record)
        self.journal.write("FINDING", finding=kind, detail=detail, **extra)
        if self.args.halt_on_finding and not self.halted:
            self.halted = f"{kind}: {detail}"
            self.stop.set()

    # -- setup ------------------------------------------------------------------------------

    def setup(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.evidence_dir, 0o700)
        if self.args.reuse_world:
            self.world = world_mod.load(self.run_dir)
        else:
            self.world = world_mod.setup(self.run_dir, self.args.engagements)
        self.eids = [e["id"] for e in self.world["engagements"]]
        lib.load_env()
        env = {**os.environ, **RECONCILER_ENV, "PYTHONUNBUFFERED": "1"}
        for line in (REPO_ROOT / ".env.example").read_text().splitlines():
            key, _, value = line.partition("=")
            if key.startswith("RECONCILER_") and value.strip().isdigit():
                env.setdefault(key, value.strip())
        env.update(RECONCILER_ENV)
        self.sup = services.Supervisor(
            self.run_dir, self.journal, env, self.eids, self.evidence_dir,
            interval_reconciler=self.args.reconciler_interval,
            interval_scheduler=self.args.scheduler_interval,
            scheduler_script=self.args.scheduler_script,
            worker_args=["--threads", str(self.args.threads), "--mean-gap",
                         str(self.args.mean_gap), "--budget", str(self.args.budget),
                         "--seed", str(self.args.seed)])
        self.schema_before = checks.schema_now()
        self.journal.write("soak.setup", engagements=self.eids, seed=self.args.seed,
                           hours=self.args.hours, reconciler_env=RECONCILER_ENV,
                           pid=os.getpid(), host=heartbeat.host_identity(),
                           caps=self.caps, caps_source=(self.caps_document or {}).get(
                               "source", "defaults of the development machine"),
                           measured=(self.caps_document or {}).get("measured"),
                           schema_facts=len(self.schema_before),
                           smoke=bool(getattr(self.args, "smoke", False)))

    # -- the witness ------------------------------------------------------------------------

    def witness(self) -> None:
        """``docker events`` for containers, one JSON line each, restarted when the daemon is."""
        path = self.run_dir / "docker_events.jsonl"
        out = lib.Journal(path)
        while not self.shutdown.is_set():
            try:
                proc = subprocess.Popen(
                    ["docker", "events", "--filter", "type=container", "--format",
                     "{{json .}}"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            except OSError:
                time.sleep(3)
                continue
            out.write("witness.connected")
            try:
                for line in proc.stdout:
                    if self.shutdown.is_set():
                        break
                    try:
                        event = json.loads(line)
                    except ValueError:
                        continue
                    attrs = (event.get("Actor") or {}).get("Attributes") or {}
                    if lib.OWNER_LABEL not in attrs and lib.RUN_LABEL not in attrs:
                        continue
                    out.write("docker", action=event.get("Action", "").split(":")[0],
                              id=(event.get("Actor") or {}).get("ID", "")[:12],
                              run_id=attrs.get(lib.RUN_LABEL), owner=attrs.get(lib.OWNER_LABEL),
                              proxy=lib.PROXY_LABEL in attrs, name=attrs.get("name"),
                              exit_code=attrs.get("exitCode"))
            finally:
                proc.kill()
                proc.wait()
            out.write("witness.disconnected")
            time.sleep(2)

    # -- the approver -----------------------------------------------------------------------

    def approver(self) -> None:
        from control_plane.api.approvals import ApprovalError, deny_approval, list_pending_approvals
        from tests import scheduler_support as sup
        from tests.helpers import committing_scope

        rng = random.Random(f"{self.args.seed}-approver")
        decided: set[str] = set()
        while not self.shutdown.is_set():
            for eid in self.eids:
                try:
                    with committing_scope(eid) as conn:
                        pending = list_pending_approvals(conn, engagement_id=eid, limit=50)
                    for row in pending:
                        pid = row["proposal_id"]
                        if pid in decided:
                            continue
                        first = self.pending_seen.setdefault(pid, lib.now())
                        wait = (zlib.crc32(pid.encode()) % 1800) / 100.0 + 2.0     # 2-20 s
                        if lib.now() - first < wait:
                            continue
                        try:
                            if rng.random() < 0.9:
                                sup.approve(eid, pid, approver="soak-approver")
                                self.journal.write("approver.granted", proposal=pid)
                            else:
                                with committing_scope(eid) as conn:
                                    deny_approval(conn, engagement_id=eid, proposal_id=pid,
                                                  denier="soak-approver", reason="soak")
                                self.journal.write("approver.denied", proposal=pid)
                        except ApprovalError as exc:
                            self.journal.write("approver.refused", proposal=pid,
                                               message=str(exc)[:200])
                        decided.add(pid)
                except Exception as exc:  # noqa: BLE001 -- the database may be down; try again
                    self.journal.write("approver.error", type=type(exc).__name__,
                                       message=str(exc)[:200])
            self.shutdown.wait(3.0)

    # -- supervising ------------------------------------------------------------------------

    def healthy(self) -> bool:
        return lib.db_reachable() and lib.docker_reachable()

    def wait_healthy(self, limit: float = 300.0) -> bool:
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline and not self.shutdown.is_set():
            if self.healthy():
                return True
            time.sleep(2)
        return self.healthy()

    def supervise(self) -> None:
        """Notice exits; say why; start the service again once its dependencies are back."""
        recent: dict[str, list[float]] = {}
        while not self.shutdown.is_set():
            for name, svc in self.sup.services.items():
                code = self.sup.exited(name)
                if code is None:
                    continue
                cause = self.cause_of(name, svc, code)
                svc.exits.append({"ts": lib.now(), "code": code, "cause": cause,
                                  "uptime_s": round(lib.now() - svc.started_at, 1)})
                self.journal.write("service.exited", service=name, code=code, cause=cause,
                                   uptime_s=round(lib.now() - svc.started_at, 1))
                svc.pid = None
                if cause == "unexplained":
                    self.finding("unexplained_exit", f"{name} exited with {code} and no injected "
                                 f"fault explains it", service=name, code=code)
                    continue
                if cause == "conductor_stop" or self.halted:
                    continue
                times = [t for t in recent.get(name, []) if lib.now() - t < 120]
                times.append(lib.now())
                recent[name] = times
                if len(times) >= 4:
                    self.finding("crash_loop", f"{name} exited {len(times)} times in 2 minutes",
                                 service=name)
                    continue
                if not self.wait_healthy():
                    self.finding("dependencies_down", f"database or Docker not back after 5 "
                                 f"minutes; {name} not restarted")
                    continue
                time.sleep(3)
                self.sup.start(name, reason=f"after_{cause}")
            self.scan_worker_events()
            self.shutdown.wait(1.0)

    def scan_worker_events(self) -> None:
        """A worker exception that is not a database or Docker failure is a finding."""
        path = self.journal.path
        try:
            with open(path, "rb") as handle:
                handle.seek(self._events_offset)
                chunk = handle.read()
        except OSError:
            return
        complete = chunk[:chunk.rfind(b"\n") + 1]
        self._events_offset += len(complete)
        for line in complete.splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if record.get("kind") == "worker.unexpected":
                self.finding("worker_unexpected", f"{record.get('type')}: "
                             f"{record.get('message')}", request=record.get("req"))

    def cause_of(self, name: str, svc: services.Service, code: int) -> str:
        if svc.killed_by_injector:
            return "injected_kill9"
        fault = self.last_fault
        if fault and lib.now() - fault["ended"] < FAULT_ATTRIBUTION_S and code in \
                services.EXPLAINED_BY.get(fault["kind"], set()) and name != "worker":
            return f"explained_by_{fault['kind']}"
        if self.stop.is_set() and code in (0, -signal.SIGTERM, 143):
            return "conductor_stop"
        return "unexplained"

    # -- the injector -----------------------------------------------------------------------

    def injector(self) -> None:
        bag = faults.Bag(self.rng, tuple(self.args.faults) if self.args.faults else faults.KINDS)
        first = self.args.first_fault_s
        wait = first if first is not None else self.rng.uniform(self.args.fault_min,
                                                               self.args.fault_max) * 60
        while not self.stop.wait(wait):
            kind = bag.draw()
            self.apply_fault(kind)
            wait = self.rng.uniform(self.args.fault_min, self.args.fault_max) * 60

    def apply_fault(self, kind: str) -> None:
        began = lib.now()
        record = {"kind": kind, "began": began, "began_at": lib.stamp(began), "ended": began}
        self.last_fault = record                 # (a fault is in force from its first moment: the
        self.journal.write("fault.begin", fault=kind)    # services notice a daemon that is going)
        extra: dict = {}
        try:
            if kind == "postgres_restart":
                extra = faults.postgres_restart()
            elif kind == "docker_restart":
                extra = faults.docker_restart()
            elif kind == "kill9_scheduler":
                extra = {"pid": self.sup.kill9("scheduler")}
            elif kind == "kill9_reconciler":
                extra = {"pid": self.sup.kill9("reconciler")}
            elif kind == "kill9_control_plane":
                extra = {"pid": self.sup.kill9("worker")}
            elif kind == "pause_container":
                extra = faults.pause_container(self.rng, set(self.eids))
        except Exception as exc:  # noqa: BLE001
            extra = {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:200]}"}
            self.finding("fault_failed", f"{kind} could not be applied: {extra['error']}")
        record.update(extra)
        record["ended"] = lib.now()
        self.faults_done.append(record)
        self.journal.write("fault.applied", fault=kind, **extra)
        threading.Thread(target=self.track_recovery, args=(record,), daemon=True).start()

    def track_recovery(self, record: dict) -> None:
        t0 = record["began"]
        if record["kind"] == "pause_container" and record.get("ok"):
            self.shutdown.wait(record["hold_s"])
            record["unpause"] = faults.unpause(record["container"])
            self.journal.write("fault.unpaused", **record["unpause"], container=record["container"])
        marks: dict[str, float | None] = {"services_up": None, "reconciler_pass": None,
                                          "allow_recorded": None, "scheduler_dispatched": None}
        after = {name: svc.passes for name, svc in self.sup.services.items()}
        deadline = time.monotonic() + RECOVERY_TIMEOUT_S
        while time.monotonic() < deadline and not self.shutdown.is_set():
            now = lib.now()
            try:
                if marks["services_up"] is None and self.sup.all_alive() and self.healthy():
                    marks["services_up"] = now - t0
                if marks["reconciler_pass"] is None and \
                        self.sup.services["reconciler"].passes > after["reconciler"] and \
                        self.sup.services["reconciler"].last_pass_at > t0:
                    marks["reconciler_pass"] = now - t0
                arr = checks._quote(self.eids)
                if marks["allow_recorded"] is None:
                    rows = lib.psql(
                        "SELECT count(*) FROM action_proposals WHERE engagement_id = ANY(" + arr +
                        f") AND decision = 'ALLOW' AND pipeline_stage = 'recorded' AND "
                        f"stage_detail = 'succeeded' AND stage_updated_at > to_timestamp({t0}) "
                        f"AND created_at > to_timestamp({record['ended']})")
                    if int(rows[0][0]) > 0:
                        marks["allow_recorded"] = now - t0
                if marks["scheduler_dispatched"] is None:
                    rows = lib.psql(
                        "SELECT count(*) FROM action_proposals p WHERE p.engagement_id = ANY(" +
                        arr + ") AND p.decision = 'HUMAN_APPROVAL' AND p.pipeline_stage = "
                        "'recorded' AND p.stage_updated_at > to_timestamp(" + str(record["ended"]) +
                        ")")
                    if int(rows[0][0]) > 0:
                        marks["scheduler_dispatched"] = now - t0
            except Exception:  # noqa: BLE001 -- the database may still be coming back
                pass
            if all(v is not None for v in marks.values()):
                break
            self.shutdown.wait(3.0)
        record["recovery_s"] = {k: (round(v, 1) if v is not None else None)
                                for k, v in marks.items()}
        done = all(v is not None for v in marks.values())
        record["recovered_s"] = round(max(v for v in marks.values() if v is not None), 1) \
            if done else None
        self.journal.write("fault.recovery", fault=record["kind"], **record["recovery_s"],
                           recovered_s=record["recovered_s"])
        if not done and not self.shutdown.is_set():
            self.finding("no_recovery", f"after {record['kind']}: {record['recovery_s']}",
                         fault=record["kind"])

    # -- sampling ---------------------------------------------------------------------------

    def sample_once(self) -> dict:
        sample: dict = {"ts": lib.now()}
        procs = {}
        for name, pid in self.sup.pids().items():
            stats = lib.proc_stats(pid) if pid else None
            procs[name] = {**stats, "pid": pid} if stats else None
        mine = lib.proc_stats(os.getpid())
        procs["conductor"] = {**mine, "pid": os.getpid()} if mine else None
        sample["procs"] = procs
        try:
            sample["pg"] = lib.pg_connections()
        except Exception:  # noqa: BLE001
            sample["pg"] = None
        try:
            client = lib.docker_client()
            try:
                sample["docker"] = lib.docker_counts(client, "/tmp", self.evidence_dir)
            finally:
                client.close()
        except Exception:  # noqa: BLE001
            sample["docker"] = None
        try:
            rows = lib.psql("SELECT pipeline_stage, count(*) FROM action_proposals WHERE "
                            "engagement_id = ANY(" + checks._quote(self.eids) + ") GROUP BY 1")
            sample["stages"] = {r[0]: int(r[1]) for r in rows}
        except Exception:  # noqa: BLE001
            sample["stages"] = None
        return sample

    def sampler(self) -> None:
        while not self.shutdown.is_set():
            sample = self.sample_once()
            self.samples.append(sample)
            self.journal.write("sample", **{k: v for k, v in sample.items() if k != "ts"})
            for breach in self.caps_breached(sample):
                self.finding("resource_cap", breach)
            self.shutdown.wait(self.args.sample_s)

    def caps_breached(self, sample: dict) -> list[str]:
        out = []
        for name, stats in (sample.get("procs") or {}).items():
            if not stats:
                continue
            cap = self.caps["rss_mb"].get(name)
            if cap is not None and stats["rss_kb"] / 1024 > cap:
                out.append(f"{name} resident memory {stats['rss_kb'] / 1024:.0f} MB > {cap} MB")
            if stats["fds"] > self.caps["fds"]:
                out.append(f"{name} holds {stats['fds']} descriptors > {self.caps['fds']}")
            if stats["pg_connections"] > self.caps["pg_connections_per_process"]:
                out.append(f"{name} holds {stats['pg_connections']} connections to Postgres "
                           f"> {self.caps['pg_connections_per_process']}")
        pg = sample.get("pg")
        if pg and pg["total"] > self.caps["pg_backends_total"]:
            out.append(f"{pg['total']} backends in the database > {self.caps['pg_backends_total']}")
        dk = sample.get("docker")
        if dk:
            total = sum(dk["tools"].values()) + sum(dk["proxies"].values())
            if total > self.caps["containers_total"]:
                out.append(f"{total} containers of the soak > {self.caps['containers_total']}")
            if dk["networks"] > self.caps["networks"]:
                out.append(f"{dk['networks']} sandbox networks > {self.caps['networks']}")
        size = lib.dir_size_mb(self.run_dir)
        if size > self.caps["run_dir_mb"]:
            out.append(f"the run directory is {size} MB > {self.caps['run_dir_mb']} MB")
        events_mb = self.journal.path.stat().st_size / 1048576
        if events_mb > self.caps["events_file_mb"]:
            out.append(f"events.jsonl is {events_mb:.0f} MB > {self.caps['events_file_mb']} MB")
        free = lib.disk_free_mb("/")
        if free < self.caps["disk_free_mb_min"]:
            out.append(f"{free} MB free on / < {self.caps['disk_free_mb_min']} MB")
        return out

    def hourly(self, number: int) -> None:
        """The hourly sample point: everything the trends are read from, once an hour, in one
        record (``hourly.jsonl``; the report's table is made from it)."""
        point = {"hour": number, "at": lib.stamp(), "sample": self.sample_once()}
        try:
            point["db"] = lib.db_sizes()
        except Exception as exc:  # noqa: BLE001
            point["db"] = {"error": f"{type(exc).__name__}: {str(exc)[:120]}"}
        point["host"] = {"dockerd": lib.rss_of_named("dockerd"),
                         "containerd": lib.rss_of_named("containerd"),
                         "postgres": lib.rss_of_named("postgres"),
                         "run_dir_mb": lib.dir_size_mb(self.run_dir),
                         "disk_free_mb": lib.disk_free_mb("/")}
        point["faults_so_far"] = {k: sum(1 for f in self.faults_done if f["kind"] == k)
                                  for k in faults.KINDS}
        point["findings"] = len(self.findings)
        self.hourly_points.append(point)
        lib.Journal(self.run_dir / "hourly.jsonl").write("hourly", **point)
        self.journal.write("hourly", hour=number)

    # -- checking ---------------------------------------------------------------------------

    def run_checks(self, label: str) -> list[checks.Result]:
        window = self.args.check_every * 60
        results: list[checks.Result] = []
        if not self.wait_healthy(180):
            self.finding("dependencies_down", f"the {label} check could not run: the database or "
                         "Docker is not reachable")
            return results
        steps = [
            lambda: checks.coherence(self.eids),
            lambda: checks.capability_on_abandoned(self.eids),
            lambda: checks.run_twice_in_the_database(self.eids),
            lambda: checks.run_twice_in_docker(self.run_dir / "docker_events.jsonl", self.eids),
            lambda: checks.audit_matches_state(self.eids, list(self.faults_done)),
            lambda: checks.residue_does_not_grow(self.samples, window),
            lambda: checks.no_connection_leak(self.samples, window),
            lambda: checks.unresolved_intents(self.eids),
            lambda: checks.schema_unchanged(self.schema_before),
        ]
        for step in steps:
            for attempt in range(3):
                try:
                    results.append(step())
                    break
                except Exception as exc:  # noqa: BLE001
                    if attempt == 2:
                        results.append(checks.Result(
                            "check could not run", False,
                            f"{type(exc).__name__}: {str(exc)[:300]}"))
                    else:
                        time.sleep(10)
        for result in results:
            self.journal.write("check", label=label, **result.as_dict())
            self.check_results.append({"label": label, "at": lib.stamp(), **result.as_dict()})
            if checks.is_finding(result, smoke=bool(getattr(self.args, "smoke", False))):
                self.finding("invariant", f"{result.name}: {result.detail}", label=label)
            elif not result.ok:
                self.journal.write("smoke.not_enforced", check=result.name, detail=result.detail,
                                   label=label)
        return results

    # -- the run ----------------------------------------------------------------------------

    def beat(self) -> None:
        """The heartbeat file, every ``heartbeat.PERIOD_S`` seconds, until the very end."""
        while True:
            phase = ("draining" if self.stop.is_set() else "running")
            try:
                heartbeat.write(self.run_dir, phase=phase, started_at=self.started,
                                last_sample_at=(self.samples[-1]["ts"] if self.samples else None),
                                faults_done=len(self.faults_done), findings=len(self.findings))
            except OSError:
                pass                                     # a full disk is the caps' to report
            if self.shutdown.wait(heartbeat.PERIOD_S):
                return

    def run(self) -> int:
        self.setup()
        threading.Thread(target=self.beat, daemon=True, name="beat").start()
        threading.Thread(target=self.witness, daemon=True, name="witness").start()
        time.sleep(2)
        # the reconciler first (the convention of its documentation), then the scheduler, then the
        # control plane
        for name in ("reconciler", "scheduler", "worker"):
            self.sup.start(name, reason="soak_start")
            time.sleep(3)
        for target in (self.supervise, self.approver, self.sampler):
            threading.Thread(target=target, daemon=True, name=target.__name__).start()
        injector = threading.Thread(target=self.injector, daemon=True, name="injector")
        injector.start()
        end = self.started + self.args.hours * 3600
        next_check = self.started + self.args.check_every * 60
        next_hour, hour = self.started + 3600, 1
        self.hourly(0)
        while not self.stop.is_set() and lib.now() < end:
            if lib.now() >= next_hour:
                self.hourly(hour)
                next_hour += 3600
                hour += 1
            if lib.now() >= next_check:
                self.run_checks(f"t+{int((lib.now() - self.started) / 60)}min")
                next_check += self.args.check_every * 60
            self.stop.wait(5.0)
        return self.finish()

    def finish(self) -> int:
        halted = self.halted
        self.journal.write("soak.stopping", halted=halted, findings=len(self.findings))
        # no more faults, no more proposals; the scheduler and the reconciler go on until the
        # work that is in flight is over (or, on a finding, until the state has been written down)
        self.stop.set()
        worker = self.sup.services["worker"]
        if worker.pid and lib.alive(worker.pid):
            os.kill(worker.pid, signal.SIGTERM)
        self.drained = False
        if not halted:
            self.drain()
        final = self.final_checks("final" if not halted else "final-after-finding")
        if not halted:
            self.completeness_findings()
        self.hourly(len(self.hourly_points))                   # the last point: after the drain
        self.shutdown.set()
        self.sup.stop_all()
        tear = {}
        try:
            tear = world_mod.teardown(self.run_dir)
        except Exception as exc:  # noqa: BLE001
            tear = {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
        self.journal.write("soak.teardown", **tear)
        heartbeat.write(self.run_dir, phase="ended", started_at=self.started,
                        faults_done=len(self.faults_done), findings=len(self.findings))
        report.write(self, final, tear)
        return 3 if self.findings else 0

    def completeness_findings(self) -> None:
        """A check that never ran, or never judged anything, has verified nothing: a finding. So is
        a fault kind that never took effect in a run long enough to have drawn all six."""
        for line in checks.never_ran(self.check_results, expect_drain=True):
            self.finding("check_never_ran", line)
        arr = checks._quote(self.eids)
        rows = lib.psql(
            "SELECT count(*) FILTER (WHERE decision = 'ALLOW' AND pipeline_stage = 'recorded'), "
            "count(*) FILTER (WHERE decision = 'HUMAN_APPROVAL' AND pipeline_stage = 'recorded') "
            "FROM action_proposals WHERE engagement_id = ANY(" + arr + ")")
        for line in checks.workload_exercised(int(rows[0][0]), int(rows[0][1])):
            self.finding("workload_not_exercised", line)
        done = [f for f in self.faults_done]
        # a smoke run (0.2 h or more) exists to inject all six; a run too short to draw them is
        # not asked to
        smoke_long_enough = bool(getattr(self.args, "smoke", False)) and self.args.hours >= 0.2
        if (len(done) >= len(faults.KINDS) or smoke_long_enough) and not self.args.faults:
            for kind in faults.KINDS:
                if not any(f["kind"] == kind and f.get("ok", True) is not False for f in done):
                    self.finding("fault_kind_never_effective",
                                 f"{kind} was never injected and effective in {len(done)} faults")

    def drain(self) -> None:
        """Let the scheduler and the reconciler finish what is in flight: every proposal terminal
        (the approver still decides the ones waiting for a human) and no container of the soak
        left. Bounded; what is left at the bound is what the final check reports."""
        limit = time.monotonic() + self.args.drain_minutes * 60
        arr = checks._quote(self.eids)
        settled = False
        while time.monotonic() < limit and not self.halted:
            try:
                open_ = int(lib.psql(
                    "SELECT count(*) FROM action_proposals WHERE engagement_id = ANY(" + arr +
                    ") AND pipeline_stage NOT IN ('recorded', 'closed', 'abandoned')")[0][0])
                runs = int(lib.psql(
                    "SELECT count(*) FROM tool_runs WHERE engagement_id = ANY(" + arr + ") AND "
                    "status IN ('queued', 'dispatching', 'running')")[0][0])
                client = lib.docker_client()
                try:
                    docker = lib.docker_counts(client, "/tmp", self.evidence_dir)
                finally:
                    client.close()
                left = (sum(docker["tools"].values()) + sum(docker["proxies"].values()))
                self.journal.write("drain", open_proposals=open_, open_runs=runs,
                                   containers=left)
                if open_ == 0 and runs == 0 and left == 0:
                    settled = True
                    break
            except Exception as exc:  # noqa: BLE001
                self.journal.write("drain.error", message=str(exc)[:200])
            time.sleep(20)
        self.journal.write("drain.end", settled=settled)
        self.drained = settled

    def final_checks(self, label: str) -> list[checks.Result]:
        results = self.run_checks(label)
        if label == "final":
            # after the drain: nothing of the soak is left in Docker, the temp directory holds no
            # credential or TLS file, and every proposal is in a terminal stage
            arr = checks._quote(self.eids)
            try:
                client = lib.docker_client()
                try:
                    docker = lib.docker_counts(client, "/tmp", self.evidence_dir)
                finally:
                    client.close()
                stages = lib.psql("SELECT pipeline_stage, count(*) FROM action_proposals WHERE "
                                  "engagement_id = ANY(" + arr + ") GROUP BY 1")
                open_ = {s: int(n) for s, n in stages
                         if s not in ("recorded", "closed", "abandoned")}
                bad = (sum(docker["tools"].values()) or sum(docker["proxies"].values())
                       or docker["files"] or open_ or not getattr(self, "drained", False))
                result = checks.Result(
                    "after the drain nothing of the soak is left", not bad,
                    f"docker {json.dumps(docker)}; proposals not terminal {open_}; "
                    f"settled {getattr(self, 'drained', False)}")
            except Exception as exc:  # noqa: BLE001
                result = checks.Result("after the drain nothing of the soak is left", False,
                                       f"{type(exc).__name__}: {str(exc)[:200]}")
            self.journal.write("check", label=label, **result.as_dict())
            self.check_results.append({"label": label, "at": lib.stamp(), **result.as_dict()})
            results.append(result)
            if not result.ok:
                self.finding("invariant", f"{result.name}: {result.detail}", label=label)
        return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--hours", type=float, default=4.0)
    parser.add_argument("--engagements", type=int, default=3)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--mean-gap", type=float, default=6.0)
    parser.add_argument("--budget", type=int, default=60)
    parser.add_argument("--fault-min", type=float, default=10.0, help="minutes")
    parser.add_argument("--fault-max", type=float, default=20.0, help="minutes")
    parser.add_argument("--first-fault-s", type=float, default=None,
                        help="seconds until the first fault (default: drawn like the others)")
    parser.add_argument("--check-every", type=float, default=15.0, help="minutes")
    parser.add_argument("--sample-s", type=float, default=60.0)
    parser.add_argument("--reconciler-interval", type=float, default=20.0)
    parser.add_argument("--scheduler-interval", type=float, default=5.0)
    parser.add_argument("--drain-minutes", type=float, default=45.0)
    parser.add_argument("--faults", nargs="*", choices=faults.KINDS,
                        help="only these kinds (a diagnostic run; the real soak draws all six)")
    parser.add_argument("--scheduler-script", type=Path,
                        help="a different script for the scheduler (a diagnostic wrapper)")
    parser.add_argument("--caps-file", type=Path,
                        help="caps measured on this machine (scripts/soak/measure.py)")
    parser.add_argument("--smoke", action="store_true",
                        help="a try of the workflow, not a soak: faults about a minute apart, "
                             "checks every two minutes, a short drain")
    parser.add_argument("--seed", default="d66")
    parser.add_argument("--reuse-world", action="store_true")
    parser.add_argument("--halt-on-finding", action="store_true", default=True)
    args = parser.parse_args(argv)
    if args.smoke:
        args.fault_min, args.fault_max, args.first_fault_s = 0.7, 1.0, 30.0
        args.check_every, args.sample_s, args.drain_minutes = 2.0, 15.0, 35.0
    conductor = Conductor(args)
    signal.signal(signal.SIGTERM, lambda *_: conductor.stop.set())
    signal.signal(signal.SIGINT, lambda *_: conductor.stop.set())
    return conductor.run()


if __name__ == "__main__":
    raise SystemExit(main())
