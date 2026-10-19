"""A drill of the late result, on a real container (completion 5, item 4; ACCEPTANCE 5.74).

    python scripts/drill_reconciler_late_result.py run   --dir DIR      # ~25 minutes, unattended
    python scripts/drill_reconciler_late_result.py clean --dir DIR

5.74 was found with a fake container held open by a hook. This is the same race with a real one:

* a real control-plane process runs ``propose_action`` through the whole pipeline with the product's
  own ``DockerSandbox`` and a real ``nmap`` run (budget ``B`` = 30 s). It is stopped with
  ``SIGSTOP`` as soon as the tool container exists: the container goes on and ends by itself, and
  nobody is waiting for it;
* the product's own command line (``state-only``, **no switch enabled**, every 15 s) finds the
  proposal still ``dispatching`` and, ``B + P + Q`` = 30 + 915 + 300 = 1,245 s after the stage was
  written, declares it ``unknown_outcome`` (the product refuses shorter ``P`` and ``Q``); the
  retention is 1,800 s, so that the container's output is still there when its owner comes back;
* **70 seconds after the reconciler wrote the unknown outcome** the control plane is continued
  (``SIGCONT``). It finishes its run and records its result.

What has to be true afterwards, and is checked: the late result **replaced** the unknown outcome in
one transaction (the proposal is ``recorded`` with the detail equal to its dispatch state, the
run has the real status, there is one evidence row), there is an audit event ``run.late_result``
that names the run and the proposal, there is still exactly one run for the proposal and exactly
one container Docker ever created for it, the reconciler's own ``dispatch_unknown_outcome`` record
is still in the trail, and ``assert_coherent`` holds (it holds that a ``recorded`` proposal's
detail equals its dispatch state, the rule that would have flagged E17).
"""

from __future__ import annotations

import argparse
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
RETENTION_S = 1800
INTERVAL_S = 15
LATE_BY_S = 70


def say(*parts):
    print(*parts, flush=True)


def child(args) -> int:
    from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
    from control_plane.api.function_api import propose_action
    from control_plane.capability.broker import Budget
    from tests import scheduler_support as sup
    from tests.task_support import attach_task
    from tool_gateway.sandbox import DockerSandbox

    outcome = propose_action(
        engagement_id=args.eid,
        proposal=attach_task(args.eid, sup.proposal_for(args.scope, host=args.host)),
        reviewer=HonestFakeReviewer(), policy=sup.effective_policy(args.eid),
        agent_id="drill", sandbox=DockerSandbox(), network_allowlist=[args.cidr],
        budget=Budget(max_duration_seconds=BUDGET_S),
        idempotency_key=f"drill-{uuid.uuid4().hex[:10]}")
    print(json.dumps({"decision": outcome.decision, "failure": outcome.failure,
                      "run_id": outcome.run_id}), flush=True)
    return 0


def psql(statement: str) -> list[list[str]]:
    done = subprocess.run(
        ["su", "postgres", "-c", f"psql -d cyberorch -At -F '|' -c \"{statement}\""],
        capture_output=True, text=True, check=True)
    return [line.split("|") for line in done.stdout.splitlines() if line]


def run(args) -> int:
    holder: dict = {}
    try:
        return _run(args, holder)
    finally:
        if "child" in holder and holder["child"].poll() is None:
            try:
                os.kill(holder["child"].pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
        if "loop" in holder:
            holder["loop"].stop()
        if "witness" in holder:
            holder["witness"].terminate()
        if holder.get("published") is not None:
            from tests.helpers import deactivate_global_layer
            deactivate_global_layer(holder["published"], actor="drill")


def _run(args, holder) -> int:
    from control_plane.config import load_dotenv
    from control_plane.reconciler import emit
    from control_plane.reconciler.config import load
    from tests import scheduler_support as sup
    from tests.helpers import EngagementManager, ensure_test_baseline, make_engagement

    load_dotenv()
    out = Path(args.dir)
    out.mkdir(parents=True, exist_ok=True)
    client = base.docker_client()
    if client.containers.list(all=True, filters={"label": base.RUN_LABEL}):
        raise SystemExit("refusing to start: containers of the sandbox exist already")
    env = base.drill_env()
    env["RECONCILER_RETENTION_S"] = str(RETENTION_S)
    th = load(env)
    unknown_after = th.unknown_after_s(BUDGET_S)
    say(f"B = {BUDGET_S} s: unknown_outcome {unknown_after} s after the stage was written; the "
        f"owner continues {LATE_BY_S} s after that; retention {RETENTION_S} s; no switch enabled")

    tag = uuid.uuid4().hex[:6]
    eid = f"ENG-LATE-{tag}"
    holder["published"] = ensure_test_baseline()
    make_engagement(eid)
    sup.publish_engagement_policy(eid)
    cidr = live.fresh_cidr(client, 130)
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
         "--host", host, "--cidr", cidr], stdout=open(out / "child.out", "w"),
        stderr=open(out / "child.err", "w"),
        stdin=subprocess.DEVNULL, cwd=str(REPO_ROOT))
    holder["child"] = proc
    container = base.wait_for(lambda: next(iter(client.containers.list(
        filters={"label": f"{base.OWNER_LABEL}={eid}"})), None), 90, "the tool container")
    cid = container.id
    os.kill(proc.pid, signal.SIGSTOP)
    stopped_at = time.time()
    row = psql("SELECT p.proposal_id, p.pipeline_stage, extract(epoch FROM p.stage_updated_at), "
               "r.run_id, r.status FROM action_proposals p JOIN tool_runs r USING (proposal_id) "
               f"WHERE p.engagement_id = '{eid}'")[0]
    proposal, stage_at, run_id = row[0], float(row[2]), row[3]
    assert (row[1], row[4]) == ("dispatching", "running"), row
    state.update(proposal=proposal, run=run_id, container=cid, stage_updated_at=stage_at,
                 child_pid=proc.pid, stopped_at=stopped_at)
    base.save(out, state)
    say(f"the control plane (pid {proc.pid}) is stopped; proposal {proposal} is {row[1]}, run "
        f"{run_id} is {row[4]}; the container {cid[:12]} runs on its own")

    loop = live.Loop(["--mode", "state-only", "--interval", str(INTERVAL_S), "--engagement", eid],
                     env, "")
    holder["loop"] = loop
    horizon = stage_at + unknown_after + LATE_BY_S + 240
    unknown_seen = None
    continued_at = None
    while time.time() < horizon:
        time.sleep(2)
        stage = psql(f"SELECT pipeline_stage, coalesce(stage_detail, '') FROM action_proposals "
                     f"WHERE proposal_id = '{proposal}'")[0]
        if unknown_seen is None and tuple(stage) == ("recorded", "unknown_outcome"):
            unknown_row = psql(
                "SELECT extract(epoch FROM ts) FROM audit_log WHERE event_type = "
                f"'{emit.DISPATCH_UNKNOWN_OUTCOME}' AND subject_id = '{proposal}'")
            unknown_seen = float(unknown_row[0][0]) if unknown_row else time.time()
            say(f"the reconciler declared it unknown {unknown_seen - stage_at:.1f} s after the "
                f"stage was written")
        if unknown_seen is not None and continued_at is None and \
                time.time() >= unknown_seen + LATE_BY_S:
            os.kill(proc.pid, signal.SIGCONT)
            continued_at = time.time()
            say(f"the control plane continues {continued_at - unknown_seen:.1f} s after the "
                "unknown outcome was written")
        if continued_at is not None and proc.poll() is not None:
            break
    if continued_at is not None:
        time.sleep(INTERVAL_S + 5)                        # a few more passes beside the result
    code = loop.stop()
    witness.terminate()
    time.sleep(1)
    (out / "loop-output.txt").write_text("\n".join(f"{t - stage_at:8.1f}  {line}"
                                                   for t, line in loop.lines))
    say(f"the reconciler stopped (exit {code}) after {len(loop.passes())} passes")
    state.update(unknown_at=unknown_seen, continued_at=continued_at)
    base.save(out, state)
    problems = check(state, out, loop, code, proc)
    say("RESULT:", "OK" if not problems else problems)
    return 0 if not problems else 6


def check(state, out, loop, code, proc):
    from sqlalchemy import text

    from control_plane.reconciler import emit
    from control_plane.state.db import engagement_scope
    from tests.test_pipeline_stages import assert_coherent, snapshot

    problems: list[str] = []
    eid, proposal, run_id = state["eid"], state["proposal"], state["run"]
    if state.get("unknown_at") is None:
        return ["the reconciler never declared the run unknown"]
    if state.get("continued_at") is None:
        return ["the control plane was never continued"]
    late = state["continued_at"] - state["unknown_at"]
    say(f"the owner came back {late:.1f} s after the unknown outcome")
    if proc.returncode not in (0, None):
        problems.append(f"the control plane exited {proc.returncode}")
    say("the control plane said:", (out / "child.out").read_text().strip() or "(nothing)",
        "| stderr:", ((out / "child.err").read_text().strip() or "(nothing)")[-300:])

    created = []
    for line in (out / "docker-events.jsonl").read_text().splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        attrs = (e.get("Actor") or {}).get("Attributes") or {}
        if attrs.get(base.OWNER_LABEL) == eid and e.get("Action") == "create":
            created.append((e["timeNano"] / 1e9, (e.get("Actor") or {}).get("ID", "")[:12]))
    say(f"containers Docker created for this engagement: {[c for _, c in created]}")
    if len(created) != 1:
        problems.append(f"{len(created)} containers were created, expected one")

    with engagement_scope(eid) as conn:
        final = conn.execute(text(
            "SELECT pipeline_stage, stage_detail, dispatch_state FROM action_proposals "
            "WHERE proposal_id = :p"), {"p": proposal}).one()
        runs = conn.execute(text("SELECT run_id, status, exit_code FROM tool_runs "
                                 "WHERE proposal_id = :p"), {"p": proposal}).all()
        evidence = conn.execute(text("SELECT count(*) FROM evidence WHERE run_id = :r"),
                                {"r": run_id}).scalar_one()
        audit = conn.execute(text(
            "SELECT audit_id, extract(epoch FROM ts), event_type, subject_id, actor, payload "
            "FROM audit_log WHERE engagement_id = :e AND (subject_id = :p OR subject_id = :r) "
            "ORDER BY audit_id"), {"e": eid, "p": proposal, "r": run_id}).all()
    say("audit events of the proposal and its run:")
    for a, t, et, _sid, actor, payload in audit:
        flag = " (late_result)" if (payload or {}).get("late_result") else ""
        say(f"  {a}  +{float(t) - state['stage_updated_at']:7.1f}s  {et:<34} {actor:<12}{flag}")
    (out / "audit.json").write_text(json.dumps(
        [{"audit_id": a, "t": round(float(t) - state["stage_updated_at"], 1), "event": et,
          "subject": sid, "actor": actor, "payload": p} for a, t, et, sid, actor, p in audit],
        indent=1, default=str))
    events = [et for _, _, et, _, _, _ in audit]
    say(f"final: proposal {tuple(final)}; runs {[tuple(r) for r in runs]}; "
        f"evidence rows {evidence}")
    if len(runs) != 1:
        problems.append(f"{len(runs)} runs for the proposal")
    if events.count("run.late_result") != 1:
        problems.append(f"run.late_result recorded {events.count('run.late_result')} times")
    else:
        late_event = next(p for _, _, et, _, _, p in audit if et == "run.late_result")
        if late_event.get("run_id") != run_id or late_event.get("proposal_id") != proposal:
            problems.append(f"run.late_result does not name the run and proposal: {late_event}")
    if events.count(emit.DISPATCH_UNKNOWN_OUTCOME) != 1:
        problems.append("the reconciler's own unknown_outcome record is not in the trail once")
    if tuple(final)[0] != "recorded" or final[1] != final[2]:
        problems.append(f"the proposal ends {tuple(final)}: stage detail and dispatch state differ")
    if final[1] == "unknown_outcome":
        problems.append("the late result did not replace the unknown outcome")
    if runs and runs[0][1] == "unknown_outcome":
        problems.append("the run is still unknown_outcome")
    if evidence != 1:
        problems.append(f"{evidence} evidence rows for the run")
    try:
        assert_coherent(snapshot(eid))
        say("assert_coherent: holds")
    except AssertionError as exc:
        problems.append(f"assert_coherent: {exc}")
    failed = [r for _, r in loop.records() if r.get("outcome") == "failed"]
    if failed:
        problems.append(f"{len(failed)} failed results: {failed[:3]}")
    if code != 0:
        problems.append(f"the reconciler exited {code}")
    return problems


def clean(args) -> int:
    out = Path(args.dir)
    state = json.loads((out / "state.json").read_text())
    client = base.docker_client()
    for container in client.containers.list(all=True, filters={
            "label": f"{base.OWNER_LABEL}={state['eid']}"}):
        container.remove(force=True)
        say("removed", container.short_id)
    pid = state.get("child_pid")
    if pid:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
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
