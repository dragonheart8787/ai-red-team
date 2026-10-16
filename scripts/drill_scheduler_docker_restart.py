"""A drill: the Docker daemon is restarted under a dispatch in flight, ten times in a row (5.109).

    python scripts/drill_scheduler_docker_restart.py run --dir DIR [--rounds 10]     # ~25 minutes
    python scripts/drill_scheduler_docker_restart.py reconcile --dir DIR [--limit-min 40]
    python scripts/drill_scheduler_docker_restart.py clean --dir DIR

The product's own scheduler (``scripts/run_scheduler.py``, a process of its own) dispatches an
approved proposal to a real container; as soon as that container is running, the daemon is
stopped (SIGTERM to ``dockerd``, wait for it to exit) and started again, the way the soak does it.
Each round records, from Docker's events and the database, and the drill asserts:

* the scheduler stops **with exit 5** (``docker_lost``);
* what became of the in-flight run: the container's state and exit code after the daemon is back,
  the proposal's stage, the run's status -- and the container's restart policy (a daemon that
  restarts containers would bring the run back by itself);
* **I7**: after the daemon is back, from round 6 on the dead container is started again by hand
  (``docker start``: a container that comes back to life), then a new scheduler is started and
  left for 40 seconds: the proposal must have **one** dispatch audit record, the engagement
  **one** run row for it, and Docker must report the creation of **one** container for it --
  never a second.

The rows of the in-flight proposals are left as they are (``dispatching`` / ``running``): they are
the reconciler's to resolve, and the drill's last act is to say so; nothing is edited.
"""

from __future__ import annotations

import argparse
import json
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(HERE))

import drill_reconciler_docker as base  # noqa: E402
import drill_reconciler_live_owner as live  # noqa: E402

SCHEDULER = str(REPO_ROOT / "scripts" / "run_scheduler.py")


def say(*parts):
    print(*parts, flush=True)


def start_scheduler(out: Path, tag: str):
    log = open(out / f"scheduler-{tag}.log", "ab")
    return subprocess.Popen([sys.executable, SCHEDULER, "--interval", "2"], cwd=str(REPO_ROOT),
                            stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                            start_new_session=True)


def running_container(client, eid, since):
    for c in client.containers.list(filters={"label": f"{base.OWNER_LABEL}={eid}",
                                             "status": "running"}):
        if live.started_at(c) >= since - 1:
            return c
    return None


def run(args) -> int:
    from sqlalchemy import text

    from control_plane.config import load_dotenv
    from control_plane.state.db import engagement_scope
    from scripts.soak import faults
    from tests import scheduler_support as sup
    from tests.helpers import EngagementManager, ensure_test_baseline, make_engagement

    load_dotenv()
    out = Path(args.dir)
    out.mkdir(parents=True, exist_ok=True)
    client = base.docker_client()
    if client.containers.list(all=True, filters={"label": base.RUN_LABEL}):
        raise SystemExit("refusing to start: containers of the sandbox exist already")
    tag = uuid.uuid4().hex[:6]
    eid = f"ENG-RESTART-{tag}"
    published = ensure_test_baseline()
    make_engagement(eid)
    sup.publish_engagement_policy(eid)
    cidr = live.fresh_cidr(client, 140).split("/")[0].rsplit(".", 1)[0] + ".0/24"
    scope = sup.register_scope(EngagementManager(eid), type="cidr", value=cidr)
    sup.enroll(eid)
    net = cidr.rsplit(".", 1)[0]
    events_file = out / "docker-events.jsonl"
    events_file.write_text("")

    def start_witness():
        """``docker events`` ends when the daemon does: one is started at the top of each round."""
        return subprocess.Popen(["docker", "events", "--format", "{{json .}}", "--filter",
                                 "type=container"], stdout=open(events_file, "a"),
                                stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)

    witness = start_witness()
    state = {"eid": eid, "cidr": cidr, "rounds": []}
    problems: list[str] = []
    say(f"engagement {eid}, scope {cidr}; {args.rounds} rounds")
    try:
        for n in range(1, args.rounds + 1):
            row: dict = {"round": n}
            witness.terminate()
            witness = start_witness()
            time.sleep(1)
            host = f"{net}.{20 + n}"
            proposal = sup.approved_proposal(eid, scope, host=host, ports=str(20000 + n))
            row["proposal"] = proposal
            began = time.time()
            sched = start_scheduler(out, f"{n}a")
            container = base.wait_for(
                lambda client=client, began=began: running_container(client, eid, began), 90,
                "the dispatched container")
            row["container"] = container.id
            row["restart_policy"] = container.attrs["HostConfig"]["RestartPolicy"]
            row["alive_s_before_restart"] = round(time.time() - live.started_at(container), 1)
            t0 = time.time()
            fault = faults.docker_restart()
            row["docker_restart"] = {"ok": fault["ok"], "action_s": fault["action_s"]}
            try:
                code = sched.wait(timeout=120)
            except subprocess.TimeoutExpired:
                sched.kill()
                code = "timeout"
            row["scheduler_exit"] = code
            row["scheduler_exit_after_s"] = round(time.time() - t0, 1)
            if code != 5:
                problems.append(f"round {n}: the scheduler exited {code}, not 5")
            base.wait_for(lambda: base.docker_client().ping() or True, 60, "the daemon")
            client = base.docker_client()
            c = client.containers.get(container.id)
            row["container_after"] = {"status": c.status,
                                      "exit_code": c.attrs["State"]["ExitCode"],
                                      "restarted_by_daemon": c.attrs["State"].get("Running")}
            if c.status == "running":
                problems.append(f"round {n}: the daemon brought the container back by itself")
            if n > args.rounds // 2:                         # a container that comes back to life
                c.start()
                time.sleep(1)
                c.reload()
                row["revived_by_hand"] = {"status_after": c.status}
            sched2 = start_scheduler(out, f"{n}b")
            time.sleep(40)
            sched2.send_signal(signal.SIGTERM)
            try:
                row["second_scheduler_exit"] = sched2.wait(timeout=60)
            except subprocess.TimeoutExpired:
                sched2.kill()
                row["second_scheduler_exit"] = "killed"
            with engagement_scope(eid) as conn:
                stage = conn.execute(text(
                    "SELECT pipeline_stage, coalesce(stage_detail, ''), dispatch_state "
                    "FROM action_proposals WHERE proposal_id = :p"), {"p": proposal}).one()
                runs = conn.execute(text(
                    "SELECT run_id, status FROM tool_runs WHERE proposal_id = :p"),
                    {"p": proposal}).all()
                dispatched = conn.execute(text(
                    "SELECT count(*) FROM audit_log WHERE event_type = 'scheduler.dispatched' "
                    "AND subject_id = :p"), {"p": proposal}).scalar_one()
            run_ids = [r[0] for r in runs]
            row["containers_with_the_runs_label_now"] = len(base.docker_client().containers.list(
                all=True, filters={"label": f"{base.RUN_LABEL}={run_ids[0]}"})) if run_ids else 0
            created = [json.loads(line) for line in events_file.read_text().splitlines()
                       if line.strip()]
            created = [e for e in created if e.get("Action") == "create"
                       and (e.get("Actor", {}).get("Attributes", {}) or {}).get(
                           "cyberorch.run_id") in run_ids]
            row.update(stage=list(stage), runs=[list(r) for r in runs], dispatch_records=dispatched,
                       containers_created_for_the_run=len(created))
            say(json.dumps(row, default=str))
            if (len(runs), dispatched, len(created), row["containers_with_the_runs_label_now"]) \
                    != (1, 1, 1, 1):
                problems.append(f"round {n}: runs {len(runs)}, dispatch records {dispatched}, "
                                f"containers created {len(created)}, containers now "
                                f"{row['containers_with_the_runs_label_now']}: not (1, 1, 1, 1)")
            if stage[0] != "dispatching" or runs[0][1] != "running":
                problems.append(f"round {n}: the in-flight run ended {tuple(stage)} / {runs}")
            state["rounds"].append(row)
            base.save(out, state)
            # (the revived container is left to the reconciler's kill at B + margin; it is removed
            # at the end by `clean`)
    finally:
        witness.terminate()
        sup.withdraw(eid)
        if published is not None:
            from tests.helpers import deactivate_global_layer
            deactivate_global_layer(published, actor="drill")
    exits = [r["scheduler_exit"] for r in state["rounds"]]
    say(f"scheduler exits: {exits}")
    say("RESULT:", "OK" if not problems else problems)
    (out / "rounds.json").write_text(json.dumps(state, indent=1, default=str))
    return 0 if not problems else 6


def reconcile(args) -> int:
    """What becomes of the in-flight runs the drill left: the product's reconciler, the soak's
    switches (kill, container) and thresholds, on the drill's engagement only, until every proposal
    has left ``dispatching`` or ``--limit-min`` is up. Every pass and action is written down."""
    import os

    from sqlalchemy import text

    from control_plane.config import load_dotenv
    from control_plane.state.db import engagement_scope
    from scripts.soak.conductor import RECONCILER_ENV

    load_dotenv()
    out = Path(args.dir)
    state = json.loads((out / "state.json").read_text())
    eid = state["eid"]
    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    for line in (REPO_ROOT / ".env.example").read_text().splitlines():   # (the soak does the same)
        key, _, value = line.partition("=")
        if key.startswith("RECONCILER_") and value.strip().isdigit():
            env.setdefault(key, value.strip())
    env.update(RECONCILER_ENV)
    evidence = out / "evidence"
    evidence.mkdir(exist_ok=True, mode=0o700)
    flags = ["--mode", "state-only", "--interval", "20", "--engagement", eid, "--enable", "kill",
             "--enable", "container", "--evidence-dir", str(evidence)]
    loop = live.Loop(flags, env, "enable container kill\n")
    began = time.time()
    seen_stage: dict = {}
    timeline: list[dict] = []

    def stages():
        with engagement_scope(eid) as conn:
            return conn.execute(text(
                "SELECT p.proposal_id, p.pipeline_stage, coalesce(p.stage_detail, ''), "
                "r.status, r.run_id FROM action_proposals p LEFT JOIN tool_runs r "
                "ON r.proposal_id = p.proposal_id ORDER BY p.proposal_id")).all()

    try:
        while time.time() - began < args.limit_min * 60:
            time.sleep(15)
            rows = stages()
            now = round(time.time() - began)
            for pid, stage, detail, status, run_id in rows:
                key = (stage, detail, status)
                if seen_stage.get(pid) != key:
                    seen_stage[pid] = key
                    timeline.append({"t_s": now, "proposal": pid, "stage": stage,
                                     "detail": detail, "run_status": status, "run": run_id})
                    say(json.dumps(timeline[-1]))
            if rows and all(r[1] != "dispatching" for r in rows):
                break
    finally:
        code = loop.stop()
    actions = [r for _, r in loop.records() if "kind" in r and "outcome" in r]
    client = base.docker_client()
    left = client.containers.list(all=True, filters={"label": f"{base.OWNER_LABEL}={eid}"})
    result = {"eid": eid, "reconciler_exit": code, "minutes": round((time.time() - began) / 60, 1),
              "timeline": timeline, "actions": actions,
              "containers_left": [[c.short_id, c.status] for c in left]}
    (out / "reconcile.json").write_text(json.dumps(result, indent=1, default=str))
    say("reconciler exit", code, "; containers left", result["containers_left"])
    return 0


def clean(args) -> int:
    state = json.loads((Path(args.dir) / "state.json").read_text())
    client = base.docker_client()
    for c in client.containers.list(all=True, filters={
            "label": f"{base.OWNER_LABEL}={state['eid']}"}):
        c.remove(force=True)
        say("removed", c.short_id)
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "reconcile", "clean"):
        p = sub.add_parser(name)
        p.add_argument("--dir", required=True)
        if name == "run":
            p.add_argument("--rounds", type=int, default=10)
        if name == "reconcile":
            p.add_argument("--limit-min", type=int, default=40)
    args = parser.parse_args(argv)
    return {"run": run, "reconcile": reconcile, "clean": clean}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
