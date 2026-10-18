"""A drill of the whole chain, with nobody editing a state (completion 5, item 3).

    python scripts/drill_reconciler_full_chain.py run   --dir DIR      # ~30 minutes, unattended
    python scripts/drill_reconciler_full_chain.py clean --dir DIR

The earlier drills each took one step: the first made the rows by hand, the second set a run to
``unknown_outcome`` with an ``UPDATE`` because the reconciler's own mark "takes about a quarter of
an hour that the drill did not wait for". This one waits. **Nothing in this file writes a row after
the setup**: every stage, run status and audit record below is the product's.

* A real control-plane process runs ``propose_action`` through the whole pipeline (decision,
  capability, ``dispatching``, a ``running`` run row) with the product's own ``DockerSandbox``; only
  the container's command is ``sleep 3600`` and it has no in-container deadline, so it outlives its
  budget (``B`` = 30 s). The process is then killed with ``SIGKILL``.
* The product's own command line (``scripts/run_reconciler.py``, ``state-only``, every 30 s,
  ``--enable kill --enable container --evidence-dir``, the phrase typed on a pseudo-terminal) is
  left to run, with the thresholds of ``.env.example`` but one: **the retention is 1,500 s**,
  longer than the quarter of an hour before ``unknown_outcome`` (``B + P + Q`` = 30 + 915 + 300 =
  1,245 s after the stage was written), so that the order the design promises can be seen.

What has to happen, each by the reconciler and in this order, and what the drill checks about it:

====  =====================================================  ==================================
1     the container is killed once ``B`` + the margin (60 s)    Docker's own ``kill`` event, with
      have passed since its start                               the time; the control plane is dead
2     the proposal is moved ``dispatching -> recorded /         ``stage_updated_at`` + 1,245 s,
      unknown_outcome`` and its run to ``unknown_outcome``      not earlier; one audit event
3     nothing is removed before the retention is over           the corpse is still there, and no
                                                                ``remove_container`` result, until
                                                                finish + 1,500 s
4     the inspect output and the logs are written to            two files under
      ``<dir>/<engagement>/<container id>.*``, mode 0600, and  ``evidence/<engagement>/``; their
      their SHA-256 are in the audit trail                      hashes equal the audit's
5     the container is removed                                  Docker's ``destroy`` event, after
                                                                the ``evidence_saved`` record
====  =====================================================  ==================================

Then the proposal must be ``recorded / unknown_outcome``, its run ``unknown_outcome``, and
``assert_coherent`` must hold.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
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

BUDGET_S = 30
RETENTION_S = 1500
INTERVAL_S = 30


def say(*parts):
    print(*parts, flush=True)


# --------------------------------------------------------------------------- the control plane

def child(args) -> int:
    """The control plane: the real pipeline, the real sandbox, a container that sleeps."""
    from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
    from control_plane.api.function_api import propose_action
    from control_plane.capability.broker import Budget
    from tests import scheduler_support as sup
    from tool_gateway.sandbox import DockerSandbox

    class Sleeping(DockerSandbox):
        """The product's sandbox; the tool's command is replaced and no deadline is put in it, so
        that the container is still there when the budget and the margin have passed."""

        def run(self, **kwargs):
            kwargs["command"] = ["sleep", "3600"]
            kwargs["deadline_helper"] = None
            return super().run(**kwargs)

    propose_action(
        engagement_id=args.eid, proposal=sup.proposal_for(args.scope, host=args.host),
        reviewer=HonestFakeReviewer(), policy=sup.effective_policy(args.eid),
        agent_id="drill", sandbox=Sleeping(), network_allowlist=[args.cidr],
        budget=Budget(max_duration_seconds=BUDGET_S),
        idempotency_key=f"drill-{uuid.uuid4().hex[:10]}")
    return 0


# --------------------------------------------------------------------------- the drill

def psql(statement: str) -> list[list[str]]:
    done = subprocess.run(
        ["su", "postgres", "-c", f"psql -d cyberorch -At -F '|' -c \"{statement}\""],
        capture_output=True, text=True, check=True)
    return [line.split("|") for line in done.stdout.splitlines() if line]


def epoch(container, key: str) -> float | None:
    from datetime import datetime
    stamp = container.attrs["State"].get(key)
    if not stamp or stamp.startswith("0001"):
        return None
    return datetime.fromisoformat(stamp[:26].rstrip("Z") + "+00:00").timestamp()


def run(args) -> int:
    holder: dict = {}
    try:
        return _run(args, holder)
    finally:
        if "loop" in holder:
            holder["loop"].stop()
        if "witness" in holder:
            holder["witness"].terminate()
        if "published" in holder and holder["published"] is not None:
            from tests.helpers import deactivate_global_layer
            deactivate_global_layer(holder["published"], actor="drill")


def _run(args, holder) -> int:
    from control_plane.config import load_dotenv
    from control_plane.reconciler.config import load
    from tests import scheduler_support as sup
    from tests.helpers import EngagementManager, ensure_test_baseline, make_engagement

    load_dotenv()
    out = Path(args.dir)
    out.mkdir(parents=True, exist_ok=True)
    vault = out / "evidence"
    vault.mkdir(mode=0o700, exist_ok=True)
    os.chmod(vault, 0o700)
    client = base.docker_client()
    if client.containers.list(all=True, filters={"label": base.RUN_LABEL}):
        raise SystemExit("refusing to start: containers of the sandbox exist already")
    env = base.drill_env()
    env["RECONCILER_RETENTION_S"] = str(RETENTION_S)
    th = load(env)
    unknown_after = th.unknown_after_s(BUDGET_S)
    kill_after = th.kill_after_s(BUDGET_S)
    say(f"B = {BUDGET_S} s; the kill is due {kill_after} s after the start; unknown_outcome "
        f"{unknown_after} s after the stage was written; retention {RETENTION_S} s")

    tag = uuid.uuid4().hex[:6]
    eid = f"ENG-CHAIN-{tag}"
    holder["published"] = ensure_test_baseline()
    make_engagement(eid)
    sup.publish_engagement_policy(eid)
    cidr = live.fresh_cidr(client, 120)
    scope = sup.register_scope(EngagementManager(eid), type="cidr", value=cidr)
    net, last = cidr.split("/")[0].rsplit(".", 1)
    host = f"{net}.{int(last) + 3}"          # (+1 is the gateway of the network the sandbox makes)
    state = {"tag": tag, "eid": eid, "cidr": cidr, "scope": scope, "host": host, "dir": str(out)}
    base.save(out, state)

    witness = subprocess.Popen(
        ["docker", "events", "--format", "{{json .}}", "--filter", "type=container"],
        stdout=open(out / "docker-events.jsonl", "w"), stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL)
    holder["witness"] = witness
    time.sleep(1)

    proc = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "child", "--eid", eid, "--scope", scope,
         "--host", host, "--cidr", cidr], stdout=subprocess.PIPE,
        stderr=open(out / "child.err", "w"),
        stdin=subprocess.DEVNULL, cwd=str(REPO_ROOT))
    container = base.wait_for(lambda: next(iter(client.containers.list(
        filters={"label": f"{base.OWNER_LABEL}={eid}"})), None), 90, "the tool container")
    cid = container.id
    started = epoch(container, "StartedAt")
    # the control plane is killed in the middle of its run: the pipeline's rows are committed, the
    # container is running, and nobody is waiting for it
    stage_row = psql(
        "SELECT p.proposal_id, p.pipeline_stage, extract(epoch FROM p.stage_updated_at), "
        "r.run_id, r.status FROM action_proposals p JOIN tool_runs r USING (proposal_id) "
        f"WHERE p.engagement_id = '{eid}'")[0]
    proposal, stage, run_id, run_status = (stage_row[0], stage_row[1], stage_row[3], stage_row[4])
    stage_at = float(stage_row[2])
    assert (stage, run_status) == ("dispatching", "running"), stage_row
    os.kill(proc.pid, signal.SIGKILL)
    proc.wait()
    killed_cp_at = time.time()
    say(f"the control plane (pid {proc.pid}) is dead; proposal {proposal} is {stage}, run {run_id} "
        f"is {run_status}; the container {cid[:12]} started {killed_cp_at - started:.1f} s ago")
    state.update(proposal=proposal, run=run_id, container=cid, started=started,
                 stage_updated_at=stage_at, control_plane_killed_at=killed_cp_at)
    base.save(out, state)

    flags = ["--mode", "state-only", "--interval", str(INTERVAL_S), "--enable", "kill",
             "--enable", "container", "--evidence-dir", str(vault), "--engagement", eid]
    loop = live.Loop(flags, env, "enable container kill\n")
    holder["loop"] = loop
    state["reconciler_started_at"] = time.time()
    horizon = started + kill_after + (unknown_after - kill_after) + RETENTION_S + 300
    seen = {}
    while time.time() < horizon:
        time.sleep(5)
        now = time.time()
        try:
            c = client.containers.get(cid)
            status = c.status
        except Exception:                                       # noqa: BLE001
            status = "gone"
        stage_now = psql(f"SELECT pipeline_stage, coalesce(stage_detail, ''), (SELECT status FROM "
                         f"tool_runs WHERE run_id = '{run_id}') FROM action_proposals WHERE "
                         f"proposal_id = '{proposal}'")[0]
        row = (status, tuple(stage_now))
        if seen.get("last") != row:
            seen["last"] = row
            say(f"+{now - started:7.1f}s  container {status:<8} "
                f"proposal {stage_now[0]}/{stage_now[1]} run {stage_now[2]}")
            seen.setdefault("history", []).append((now, status, tuple(stage_now)))
        if status == "gone":
            time.sleep(INTERVAL_S + 5)                          # one more pass after the removal
            break
    code = loop.stop()
    witness.terminate()
    time.sleep(1)
    (out / "loop-output.txt").write_text(
        "\n".join(f"{t - started:8.1f}  {line}" for t, line in loop.lines))
    say(f"the reconciler stopped (exit {code}) after {len(loop.passes())} passes")
    problems = check(client, state, out, vault, loop, code, kill_after, unknown_after,
                     seen.get("history", []))
    say("RESULT:", "OK" if not problems else problems)
    return 0 if not problems else 6


def check(client, state, out, vault, loop, code, kill_after, unknown_after, history):
    from sqlalchemy import text

    from control_plane.reconciler import emit
    from control_plane.state.db import engagement_scope
    from tests.test_pipeline_stages import assert_coherent, snapshot

    problems: list[str] = []
    eid, cid, started = state["eid"], state["container"], state["started"]
    stage_at = state["stage_updated_at"]
    events = []
    for line in (out / "docker-events.jsonl").read_text().splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if (e.get("id") or e.get("Actor", {}).get("ID")) == cid and e.get("Action") in (
                "create", "start", "kill", "die", "destroy"):
            events.append((e["timeNano"] / 1e9, e["Action"],
                           (e.get("Actor", {}).get("Attributes") or {}).get("signal", "")))
    events.sort()
    say("Docker's own record of the container (seconds after its start):")
    for t, action, sig in events:
        say(f"  +{t - started:8.1f}  {action}{(' signal ' + sig) if sig else ''}")
    kills = [t for t, a, _ in events if a == "kill"]
    destroys = [t for t, a, _ in events if a == "destroy"]
    dies = [t for t, a, _ in events if a == "die"]
    if len(kills) != 1:
        problems.append(f"expected one kill, Docker reported {len(kills)}")
    elif kills[0] - started < kill_after:
        problems.append(f"killed {kills[0] - started:.1f} s after the start, before {kill_after} s")
    if state["control_plane_killed_at"] >= (kills[0] if kills else 0):
        problems.append("the container was killed before the control plane was dead")
    if len(destroys) != 1:
        problems.append(f"expected one destroy, Docker reported {len(destroys)}")

    with engagement_scope(eid) as conn:
        rows = conn.execute(text(
            "SELECT audit_id, ts, event_type, subject_id, payload FROM audit_log WHERE "
            "actor = 'reconciler' ORDER BY audit_id")).all()
        final = conn.execute(text(
            "SELECT pipeline_stage, stage_detail, dispatch_state FROM action_proposals "
            "WHERE proposal_id = :p"), {"p": state["proposal"]}).one()
        run_final = conn.execute(text("SELECT status FROM tool_runs WHERE run_id = :r"),
                                 {"r": state["run"]}).scalar_one()
    audit = [(a, ts.timestamp(), et, sid, payload) for a, ts, et, sid, payload in rows]
    (out / "audit.json").write_text(json.dumps(
        [{"audit_id": a, "t": round(t - started, 1), "event": et, "subject": sid, "payload": p}
         for a, t, et, sid, p in audit], indent=1, default=str))
    say("the reconciler's audit events:")
    for _a, t, et, sid, payload in audit:
        say(f"  +{t - started:8.1f}  {et.removeprefix('reconciler.'):<24} {sid}  "
            f"{(payload or {}).get('reason_code', '')}")
    names = [et.removeprefix("reconciler.") for _, _, et, _, _ in audit
             if et not in ("reconciler.started", "reconciler.stopped",
                           "reconciler.failure_summary")]
    want = ["action_intended", "container_killed", "dispatch_unknown_outcome", "action_intended",
            "evidence_saved", "container_removed"]
    if names != want:
        problems.append(f"the audit events were {names}, expected {want}")
    by = {et: (t, p) for _, t, et, _, p in audit}
    unknown_at = by.get(emit.DISPATCH_UNKNOWN_OUTCOME, (None, None))[0]
    if unknown_at is not None:
        gap = unknown_at - stage_at
        say(f"unknown_outcome was written {gap:.1f} s after the stage (due: {unknown_after} s; "
            f"passes every ~{INTERVAL_S + 2} s)")
        if gap < unknown_after or gap > unknown_after + 2 * (INTERVAL_S + 5):
            problems.append(f"unknown_outcome came {gap:.1f} s after the stage, due at "
                            f"{unknown_after}")
    finished = max(dies) if dies else None
    removed_at = destroys[0] if destroys else None
    if finished and removed_at and removed_at - finished < RETENTION_S:
        problems.append(f"the container was removed {removed_at - finished:.1f} s after it "
                        f"finished, inside the retention of {RETENTION_S} s")
    if unknown_at is not None and removed_at is not None:
        say(f"unknown at +{unknown_at - started:.1f}s; removed at +{removed_at - started:.1f}s "
            f"({removed_at - finished:.1f} s after it finished; retention {RETENTION_S} s)")
        if removed_at < unknown_at:
            problems.append("removed before unknown_outcome")
    saved = by.get(emit.EVIDENCE_SAVED)
    removed_event = by.get(emit.CONTAINER_REMOVED)
    if saved and removed_event and not saved[0] <= removed_event[0]:
        problems.append("evidence_saved is not before container_removed")
    # the files and their hashes
    eng_dir = vault / eid
    files = sorted(p.name for p in eng_dir.glob("*")) if eng_dir.exists() else []
    say("evidence files:", files)
    if saved:
        payload = saved[1]
        for kind, suffix in (("inspect_sha256", ".inspect.json"), ("logs_sha256", ".logs")):
            path = eng_dir / f"{cid}{suffix}"
            if not path.exists():
                problems.append(f"{path.name} does not exist")
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            mode = oct(path.stat().st_mode & 0o777)
            say(f"  {path.name}: {path.stat().st_size} bytes, mode {mode}, sha256 "
                f"{digest[:16]}... audit says {payload.get(kind, '')[:16]}...")
            if digest != payload.get(kind):
                problems.append(f"{path.name}: its sha256 is not the audit's")
            if mode != "0o600":
                problems.append(f"{path.name} has mode {mode}")
        if oct(eng_dir.stat().st_mode & 0o777) != "0o700":
            problems.append("the engagement's evidence directory is not 0700")
        if len(json.dumps(payload)) > 2000:
            problems.append("the audit payload is large: it should hold ids and hashes only")
    else:
        problems.append("no evidence_saved event")
    say(f"final: proposal {tuple(final)}, run {run_final}")
    if tuple(final)[:2] != ("recorded", "unknown_outcome") or run_final != "unknown_outcome":
        problems.append(f"final state {tuple(final)} / run {run_final}")
    snap = snapshot(eid)
    try:
        assert_coherent(snap)
        say("assert_coherent: holds")
    except AssertionError as exc:
        problems.append(f"assert_coherent: {exc}")
    failed = [r for _, r in loop.records() if r.get("outcome") == "failed"]
    if failed:
        problems.append(f"{len(failed)} failed results: {failed[:3]}")
    if code != 0:
        problems.append(f"the reconciler exited {code}")
    # nothing in this file writes a row after the setup: say what the drill itself did
    say("the drill wrote: the engagement, its policy layer and scope object (setup, through the "
        "product's functions); no other row")
    (out / "history.json").write_text(json.dumps(
        [{"t": round(t - started, 1), "container": s, "stage": list(st)} for t, s, st in history],
        indent=1))
    return problems


def clean(args) -> int:
    out = Path(args.dir)
    state = json.loads((out / "state.json").read_text())
    client = base.docker_client()
    for container in client.containers.list(all=True, filters={
            "label": f"{base.OWNER_LABEL}={state['eid']}"}):
        container.remove(force=True)
        say("removed", container.short_id)
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "clean"):
        p = sub.add_parser(name)
        p.add_argument("--dir", required=True)
    c = sub.add_parser("child")
    c.add_argument("--eid", required=True)
    c.add_argument("--scope", required=True)
    c.add_argument("--host", required=True)
    c.add_argument("--cidr", required=True)
    args = parser.parse_args(argv)
    from control_plane.config import load_dotenv
    load_dotenv()
    return {"run": run, "clean": clean, "child": child}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
