"""A drill of the reconciler's three enabled switches on a real Docker daemon (completion 3, #5).

    python scripts/drill_reconciler_docker.py seed  --dir DRILL_DIR [--tidy]
    python scripts/drill_reconciler_docker.py play  --dir DRILL_DIR       # ~27 minutes, unattended
    python scripts/drill_reconciler_docker.py clean --dir DRILL_DIR

``seed`` makes, on the host's own Docker and the development database, the things the reconciler is
meant to act on and the things it is meant to leave alone; ``play`` runs the real command line
(``scripts/run_reconciler.py``, on a pseudo-terminal, the confirmation typed) at fixed moments and
checks, after each, that Docker holds exactly what was expected; ``clean`` removes what the drill
made. The command line is the product's own: the drill adds no code path to it, and nothing in
this file kills or removes a container the drill did not make.

Before any pass that is allowed to act, the same command line is run as a **dry run** and its plan
is compared with what the drill expects at that moment, object by object. A Docker action on
anything the drill did not make, or any difference, stops the drill *before* the real pass.

Every budget is 30 s, the retention is 180 s (``RECONCILER_RETENTION_S``; the other thresholds are
``.env.example``'s), so the bounds are short:

====  ====================================================================  ========================
S1    a tool container still running past its budget + margin, with no      killed when 30 + 60 s
      in-container deadline (the helper is the first line; this is the     have passed; its corpse
      backstop)                                                             removed once its run has
                                                                            been declared unknown
S2    a real sandbox run with its egress proxy; the control plane is        the proxy removed when
      killed with SIGKILL in the middle                                     its bound (30 + 60 + 915
                                                                            s) passes; the tool
                                                                            container, which its own
                                                                            deadline stopped, once
                                                                            the run is declared
                                                                            unknown
S3    an exited container, its run finished, past retention                 removed
N1    unlabeled containers (exited, running); one with only the owner       never touched; the last
      label; one with only the run label                                    one is reported
N3    a running tool container well inside a long budget                    never touched
N4    an exited container inside its retention (twice: one before the       never touched (the first
      removal of S3, one before the last pass)                              is removed later, when
                                                                            its retention is over)
N5    a proxy of a run still in flight, inside its bound                    never touched
N6    the control plane is alive -- stopped with SIGSTOP, not dead -- and   never touched by the
      the deadline has just passed                                          reconciler; killed and
                                                                            removed by its own
                                                                            control plane
N2    a container that took the name of one that was removed                never touched
====  ====================================================================  ========================
"""

from __future__ import annotations

import argparse
import json
import os
import pty
import select
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

RUN_LABEL = "cyberorch.run_id"
OWNER_LABEL = "cyberorch.owner"
PROXY_LABEL = "cyberorch.egress_proxy"
BUDGET_S = 30
RETENTION_S = 180
IMAGE = "busybox:latest"
CLI = str(REPO_ROOT / "scripts" / "run_reconciler.py")
ALL3 = ("kill", "container", "proxy")

#: (name, seconds after the seeds, switches)
PHASES = [
    ("A", 45, ALL3), ("B", 80, ALL3), ("C", 195, ()), ("D", 205, ("kill",)),
    ("E", 235, ("container", "proxy")), ("F", 1050, ALL3), ("G", 1280, ALL3), ("H", 1315, ALL3),
]
#: the control plane of N6 is let go this long after the seeds (after phase B, before S1 and N6 are
#: due for the reconciler at 90 s or so)
RESUME_N6_AT = 86
#: before this phase, make this (a negative that has to be fresh for it)
BEFORE = {"E": "N4", "F": "N5", "H": "N4B"}
#: what each phase's plan must hold for drill objects, {(role, kind): outcome}; anything else about
#: a drill object, and every Docker action on an object that is not the drill's, stops the drill
EXPECT = {
    "A": {}, "B": {},
    "C": {("S1", "kill_container"): "skipped_deletions_off",
          ("S3", "remove_container"): "skipped_deletions_off"},
    "D": {("S1", "kill_container"): "done", ("S3", "remove_container"): "skipped_deletions_off"},
    "E": {("S3", "remove_container"): "done"},
    "F": {("S2P", "remove_proxy"): "done", ("N4", "remove_container"): "done"},
    "G": {("S1", "mark_unknown_outcome"): "done", ("S2", "mark_unknown_outcome"): "done"},
    "H": {("S1", "remove_container"): "done", ("S2T", "remove_container"): "done"},
}
#: Docker's state of each container once the phase is over ("gone" for a removed one); a set is "any
#: of these"
AFTER = {
    "A": {"S2T": {"running", "exited"}}, "B": {"S2T": "exited"}, "C": {"N6": "gone"},
    "D": {"S1": "exited"}, "E": {"S3": "gone"}, "F": {"S2P": "gone", "N4": "gone"},
    "G": {}, "H": {"S1": "gone", "S2T": "gone"},
}
START = {"S1": "running", "S2P": "running", "S2T": {"running", "exited"}, "S3": "exited",
         "N1E": "exited", "N1R": "running", "N1O": "running", "N1B": "running", "N3": "running",
         "N6": "running"}
FRESH = {"N4": "exited", "N5": "running", "N4B": "exited"}
#: containers that must never be killed, removed or changed by the reconciler
NEGATIVES = ("N1E", "N1R", "N1O", "N1B", "N3", "N5", "N4B", "N2NEW")
#: the containers Docker must report destroyed, and killed, by the end -- and no other
DESTROYED = {"S3", "S2P", "N6", "N4", "S1", "S2T", "N2OLD"}
#: N6 by its own control plane, S1 by the reconciler, and the running proxy S2P by the reconciler's
#: forced removal (Docker's `remove(force=True)` of a running container is a kill and a destroy)
KILLED = {"S1", "N6", "S2P"}


def say(*parts):
    print(*parts, flush=True)


def docker_client():
    import docker
    return docker.from_env()


def drill_env() -> dict[str, str]:
    from control_plane.config import load_dotenv
    load_dotenv()
    env = dict(os.environ)
    for line in (REPO_ROOT / ".env.example").read_text().splitlines():
        key, _, value = line.partition("=")
        if key.startswith("RECONCILER_") and value.strip().isdigit():
            env.setdefault(key, value.strip())
    env["RECONCILER_RETENTION_S"] = str(RETENTION_S)
    return env


def save(out: Path, state: dict) -> None:
    (out / "state.json").write_text(json.dumps(state, indent=1))


# --------------------------------------------------------------------------- database rows

def make_rows(eid, *, stage, run_status, budget_s, detail=None, dispatch_state="running"):
    """A proposal at ``stage`` made just now, its capability and its run: ``(proposal, run)``."""
    from sqlalchemy import text

    from control_plane.state.db import engagement_scope
    from tests.reconciler_support import _capability, _run

    pid = f"PROP-{uuid.uuid4().hex[:10]}"
    with engagement_scope(eid) as conn:
        conn.execute(text("""
            INSERT INTO action_proposals (proposal_id, engagement_id, agent_id,
                request_idempotency_key, action, target, "authorization", discovery, decision,
                pipeline_stage, stage_detail, dispatch_state, stage_updated_at)
            VALUES (:p, :e, 'drill', :k, 'network.scan', '{}', '{}', '{}', 'ALLOW', :s, :d, :ds,
                    now())"""), {"p": pid, "e": eid, "k": f"k-{pid}", "s": stage, "d": detail,
                                 "ds": dispatch_state})
    cid = _capability(eid, pid, json.dumps({"max_duration_seconds": budget_s}))
    return pid, _run(eid, pid, cid, run_status)


def close_everything_stuck() -> int:
    """The test session's own hygiene, applied to the development database's debris: every stuck
    proposal and in-flight run is moved to a terminal state (never deleted)."""
    from sqlalchemy import create_engine, text

    from control_plane.reconciler import observe
    from control_plane.state.db import reconciler_reader_scope
    from tests import residue

    with reconciler_reader_scope() as conn:
        rows, _ = observe.read_stuck(conn, max_pages=40)
    engine = create_engine(os.environ["MIGRATION_DATABASE_URL"], future=True)
    closed = 0
    for eid in sorted({r.engagement_id for r in rows}):
        with engine.begin() as conn:
            conn.execute(text("SELECT set_config('cyberorch.engagement_id', :e, true)"), {"e": eid})
            closed += conn.execute(text(residue.CLOSE_PROPOSALS),
                                   {"stuck": list(residue.STUCK)}).rowcount
            conn.execute(text(residue.CLOSE_RUNS), {"in_flight": list(residue.IN_FLIGHT)})
    return closed


def free_cidr(client, first: int) -> str:
    taken = []
    for network in client.networks.list():
        for conf in (network.attrs.get("IPAM", {}) or {}).get("Config") or []:
            taken.append(conf.get("Subnet", ""))
    for n in range(50, 250):
        for m in range(0, 256, 8):
            cidr = f"10.{first}.{n}.{m}/29"
            if not any(cidr.rsplit(".", 1)[0] in t for t in taken):
                return cidr
    raise SystemExit("no free range")


def find(client, run, *, proxy):
    for c in client.containers.list(all=True, filters={"label": f"{RUN_LABEL}={run}"}):
        if (PROXY_LABEL in (c.labels or {})) == proxy:
            return c
    return None


def wait_for(check, seconds, what):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        found = check()
        if found:
            return found
        time.sleep(0.3)
    raise SystemExit(f"timed out waiting for {what}")


# --------------------------------------------------------------------------- the seeds

def seed(args) -> int:
    from tests.helpers import deactivate_global_layer, ensure_test_baseline, make_engagement

    out = Path(args.dir)
    out.mkdir(parents=True, exist_ok=True)
    client = docker_client()
    from control_plane.config import load_dotenv
    load_dotenv()
    ours = (client.containers.list(all=True, filters={"label": RUN_LABEL})
            + client.containers.list(all=True, filters={"label": PROXY_LABEL}))
    if ours:
        raise SystemExit(f"refusing to start: {len(ours)} container(s) of the sandbox exist "
                         "already -- the drill needs to know every one is its own")
    if args.tidy:
        say(f"tidied: {close_everything_stuck()} stuck proposal(s) of the development database "
            "moved to a terminal stage")
    tag = uuid.uuid4().hex[:6]
    state = {"tag": tag, "dir": str(out), "containers": {}, "rows": {}, "engagements": {},
             "children": {}, "cidrs": []}
    published = ensure_test_baseline()
    try:
        for role in ("S1", "S2", "S3", "N3", "N5", "N6", "N4", "N4B", "N2"):
            eid = f"ENG-DRILL-{tag}-{role}"
            make_engagement(eid)
            state["engagements"][role] = eid
    finally:
        if published is not None:
            deactivate_global_layer(published, actor="drill")
    eid = state["engagements"]

    def box(name, command, *, labels, exited=False):
        c = client.containers.run(IMAGE, command, detach=True, name=f"drill-{tag}-{name}",
                                  labels=labels)
        if exited:
            c.wait(timeout=20)
        c.reload()
        return c

    # Docker's own record from now on: the witness nobody of ours writes
    witness = subprocess.Popen(
        ["docker", "events", "--format", "{{json .}}", "--filter", "type=container"],
        stdout=open(out / "docker-events.jsonl", "w"), stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL)
    state["witness_pid"] = witness.pid
    state["t0"] = time.time()

    _, run = make_rows(eid["S3"], stage="recorded", run_status="succeeded", budget_s=BUDGET_S,
                       detail="succeeded", dispatch_state="succeeded")
    state["containers"]["S3"] = box("s3", ["true"], exited=True,
                                    labels={RUN_LABEL: run, OWNER_LABEL: eid["S3"]}).id
    state["rows"]["S3_run"] = run
    prop, run = make_rows(eid["S1"], stage="dispatching", run_status="running", budget_s=BUDGET_S)
    state["containers"]["S1"] = box("s1", ["sleep", "3600"],
                                    labels={RUN_LABEL: run, OWNER_LABEL: eid["S1"]}).id
    state["rows"].update(S1_run=run, S1_prop=prop)
    state["containers"]["N1E"] = box("n1e", ["true"], labels={}, exited=True).id
    state["containers"]["N1R"] = box("n1r", ["sleep", "3600"], labels={}).id
    state["containers"]["N1O"] = box("n1o", ["sleep", "3600"], labels={OWNER_LABEL: eid["N3"]}).id
    state["containers"]["N1B"] = box("n1b", ["sleep", "3600"],
                                     labels={RUN_LABEL: "RUN-no-owner"}).id
    _, run = make_rows(eid["N3"], stage="dispatching", run_status="running", budget_s=3000)
    state["containers"]["N3"] = box("n3", ["sleep", "3600"],
                                    labels={RUN_LABEL: run, OWNER_LABEL: eid["N3"]}).id
    state["rows"]["N3_run"] = run

    # S2: a real run with its proxy; the control plane is killed in the middle
    prop, run = make_rows(eid["S2"], stage="dispatching", run_status="running", budget_s=BUDGET_S)
    state["rows"].update(S2_run=run, S2_prop=prop)
    tool_side, target_side = free_cidr(client, 97), free_cidr(client, 98)
    child = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "child-proxy", "--run", run,
         "--owner", eid["S2"], "--tool-side", tool_side, "--target-side", target_side],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, text=True,
        cwd=str(REPO_ROOT))
    wait_for(lambda: find(client, run, proxy=True) and find(client, run, proxy=False), 90,
             "the proxy and the tool container of S2")
    os.kill(child.pid, signal.SIGKILL)
    child.wait()
    state["containers"]["S2P"] = find(client, run, proxy=True).id
    state["containers"]["S2T"] = find(client, run, proxy=False).id
    state["children"]["S2"] = "killed -9"

    # N6: the control plane is alive -- stopped, not dead -- and the deadline passes
    prop, run = make_rows(eid["N6"], stage="dispatching", run_status="running", budget_s=BUDGET_S)
    state["rows"].update(N6_run=run, N6_prop=prop)
    cidr = free_cidr(client, 99)
    child = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "child-live", "--run", run,
         "--owner", eid["N6"], "--proposal", prop, "--cidr", cidr],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, text=True,
        cwd=str(REPO_ROOT))
    wait_for(lambda: find(client, run, proxy=False), 60, "the tool container of N6")
    os.kill(child.pid, signal.SIGSTOP)
    state["containers"]["N6"] = find(client, run, proxy=False).id
    state["children"]["N6"] = child.pid
    state["n6_stopped_at"] = time.time()
    state["cidrs"] = [tool_side, target_side, cidr]
    save(out, state)
    say(f"seeded {len(state['containers'])} containers and {len(state['rows'])} rows; tag {tag}")
    for role, cid in state["containers"].items():
        say(f"  {role:<5} {cid[:12]}  {client.containers.get(cid).status}")
    return 0


# --------------------------------------------------------------------------- the children

def child_proxy(args) -> int:
    """A control plane in the middle of a run with an egress proxy: it is about to be killed."""
    from tool_gateway.sandbox import DockerSandbox
    box = DockerSandbox()
    box.start_egress_proxy(
        grant={"capability_id": "CAP-DRILL", "host": "10.250.250.9", "port": 80,
               "methods": ["GET"], "max_requests": 1},
        tool_side=[args.tool_side], target_side=[args.target_side], run_id=args.run,
        engagement_id=args.owner)
    box.run(command=["sleep", "3600"], network_allowlist=[args.tool_side],
            max_duration_seconds=BUDGET_S, run_id=args.run, engagement_id=args.owner)
    return 0


def child_live(args) -> int:
    """A control plane that is alive: when its wait times out it kills its own container and
    records the run. It is stopped (SIGSTOP) by the drill until after the deadline. No in-container
    deadline, so the container is still there when the host's clock passes the budget."""
    from sqlalchemy import text

    from control_plane.state.db import engagement_scope
    from tool_gateway.sandbox import DockerSandbox
    result = DockerSandbox().run(
        command=["sleep", "3600"], network_allowlist=[args.cidr], max_duration_seconds=BUDGET_S,
        run_id=args.run, engagement_id=args.owner, deadline_helper=None)
    with engagement_scope(args.owner) as conn:
        conn.execute(text("UPDATE tool_runs SET status = 'failed', exit_code = -1 "
                          "WHERE run_id = :r"), {"r": args.run})
        conn.execute(text("UPDATE action_proposals SET pipeline_stage = 'recorded', "
                          "stage_detail = 'failed', dispatch_state = 'failed', "
                          "stage_updated_at = now() WHERE proposal_id = :p"), {"p": args.proposal})
    print(json.dumps({"timed_out": bool(result.timed_out)}), flush=True)
    return 0


# --------------------------------------------------------------------------- playing it

def run_cli(args, env, *, answer=None):
    """The command line, on a pseudo-terminal (so that a phrase can be typed). (status, output)."""
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(str(REPO_ROOT))
        os.execve(sys.executable, [sys.executable, CLI, *args], env)
    shown = b""
    sent = answer is None
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.5)
        if ready:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            shown += chunk
            if not sent and b"Type exactly:" in shown and shown.rstrip().endswith(b">"):
                os.write(fd, answer.encode())
                sent = True
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), shown.decode(errors="replace").replace("\r\n", "\n")


def parse(text):
    return [json.loads(ln) for ln in text.splitlines() if ln.startswith("{")]


DOCKER_KINDS = ("kill_container", "remove_container", "remove_proxy", "remove_network",
                "unlink_file")


def judge(lines, phase, state, *, executed):
    """The command's lines against ``EXPECT``: the problems found, and what was seen."""
    role_of_container = {v: k for k, v in state["containers"].items()}
    role_of_proposal = {state["rows"]["S1_prop"]: "S1", state["rows"]["S2_prop"]: "S2"}
    drill = set(state["engagements"].values())
    seen, problems = {}, []
    for line in lines:
        if "kind" not in line:
            continue
        kind, subject = line["kind"], line["subject_id"]
        outcome = line["outcome"] if executed else "planned"
        if kind in DOCKER_KINDS:
            role = role_of_container.get(subject)
            if role is None:
                problems.append(f"{kind} on an object that is not the drill's: {subject[:16]}")
            else:
                seen[(role, kind)] = outcome
        elif line.get("engagement_id") in drill:
            role = role_of_proposal.get(subject)
            if role is None:
                problems.append(f"a proposal action on a drill engagement, not planned: {line}")
            else:
                seen[(role, kind)] = outcome
    expected = {k: (v if executed else "planned") for k, v in EXPECT[phase].items()}
    for key in sorted(set(seen) | set(expected)):
        if seen.get(key) != expected.get(key):
            problems.append(f"{key}: expected {expected.get(key)}, found {seen.get(key)}")
    return problems, seen


def docker_states(client, state):
    now = {}
    for role, cid in state["containers"].items():
        try:
            c = client.containers.get(cid)
            now[role] = {"status": c.status, "id": c.id}
        except Exception:                                    # noqa: BLE001 - gone is a state
            now[role] = {"status": "gone", "id": cid}
    return now


def matches(got, want):
    return got in want if isinstance(want, set) else got == want


def play(args) -> int:
    out = Path(args.dir)
    state = json.loads((out / "state.json").read_text())
    client = docker_client()
    env = drill_env()
    expected_now = dict(START)
    for name, at, switches in PHASES:
        if name in BEFORE and BEFORE[name] not in state["containers"]:
            make_fresh(client, state, out, BEFORE[name])
            expected_now[BEFORE[name]] = FRESH[BEFORE[name]]
        wait = state["t0"] + at - time.time()
        if wait > 0:
            say(f"[{name}] waiting {wait:.0f} s")
            time.sleep(wait)
        elapsed = time.time() - state["t0"]
        before = docker_states(client, state)
        status, shown = run_cli(["--mode", "dry-run", "--once"], env)
        plan_lines = parse(shown)
        (out / f"phase-{name}-plan.jsonl").write_text("\n".join(json.dumps(x) for x in plan_lines))
        problems, _ = judge(plan_lines, name, state, executed=False)
        if problems or status != 0:
            say(f"[{name}] STOP before acting at t+{elapsed:.0f}s: {problems or status}")
            return 3
        words = [w for s in switches for w in ("--enable", s)]
        phrase = ("enable " + " ".join(sorted(switches)) + "\n") if switches else None
        status, shown = run_cli(["--mode", "state-only", "--once", *words], env, answer=phrase)
        lines = parse(shown)
        (out / f"phase-{name}-run.jsonl").write_text("\n".join(json.dumps(x) for x in lines))
        problems, seen = judge(lines, name, state, executed=True)
        after = docker_states(client, state)
        expected_now.update(AFTER[name])
        for role, want in expected_now.items():
            if not matches(after[role]["status"], want):
                problems.append(f"{role}: Docker says {after[role]['status']}, expected {want}")
            if after[role]["status"] != "gone" and after[role]["id"] != state["containers"][role]:
                problems.append(f"{role}: the id changed")
        changed = sorted(r for r in after if after[r]["status"] != before[r]["status"])
        verdict = "OK" if not problems and status == 0 else problems or f"exit {status}"
        say(f"[{name}] t+{elapsed:.0f}s switches={list(switches) or 'none'} exit={status} "
            f"outcomes={ {f'{k[0]}:{k[1]}': v for k, v in seen.items()} } "
            f"changed={changed or '-'} {verdict}")
        if problems or status != 0:
            return 4
        if name == "B" and resume_n6(client, state):
            return 4
    return name_race(client, state, env, out) or final_checks(client, state, out)


def resume_n6(client, state) -> int:
    """Let the stopped control plane of N6 go, after its deadline and before the reconciler's: its
    wait times out, it kills its own container, records the run and removes the container, as a
    live control plane does. (Its wait is a read timeout that starts over when it continues: the
    container is gone some 30 s after, not at once.)"""
    from docker.errors import NotFound

    wait = state["t0"] + RESUME_N6_AT - time.time()
    if wait > 0:
        time.sleep(wait)
    os.kill(state["children"]["N6"], signal.SIGCONT)
    say(f"[N6] the control plane continues (stopped {time.time() - state['n6_stopped_at']:.0f} s)")
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            client.containers.get(state["containers"]["N6"])
        except NotFound:
            say(f"[N6] its container is gone: its own control plane stopped and removed it "
                f"({time.time() - state['t0']:.0f} s after the seeds)")
            return 0
        time.sleep(0.5)
    say("[N6] its control plane did not remove its container")
    return 1


def finish(args) -> int:
    """The last two steps of ``play`` for a drill that stopped before them (the phases are over)."""
    out = Path(args.dir)
    state = json.loads((out / "state.json").read_text())
    client = docker_client()
    return name_race(client, state, drill_env(), out) or final_checks(client, state, out)


def make_fresh(client, state, out, role):
    """A negative that has to be fresh for the phase after it."""
    eid = state["engagements"][role]
    if role in ("N4", "N4B"):
        _, run = make_rows(eid, stage="recorded", run_status="succeeded", budget_s=BUDGET_S,
                           detail="succeeded", dispatch_state="succeeded")
        c = client.containers.run(IMAGE, ["true"], detach=True,
                                  name=f"drill-{state['tag']}-{role.lower()}",
                                  labels={RUN_LABEL: run, OWNER_LABEL: eid})
        c.wait(timeout=20)
    else:                                                  # N5: a proxy of a run still in flight
        _, run = make_rows(eid, stage="dispatching", run_status="running", budget_s=3000)
        c = client.containers.run(IMAGE, ["sleep", "3600"], detach=True,
                                  name=f"drill-{state['tag']}-n5",
                                  labels={RUN_LABEL: run, OWNER_LABEL: eid, PROXY_LABEL: "1"})
    state["containers"][role] = c.id
    state["rows"][f"{role}_run"] = run
    save(out, state)


def name_race(client, state, env, out):
    """The container the plan names is replaced, between the plan and the act, by a different one
    with the same name. The act goes by full id: the newcomer is not touched."""
    import tempfile

    from control_plane.reconciler import act, flags, outcome
    from control_plane.reconciler.config import load
    from control_plane.reconciler.observe import observe
    from control_plane.reconciler.plan import plan
    from control_plane.state.db import reconciler_reader_scope

    eid = state["engagements"]["N2"]
    name = f"drill-{state['tag']}-n2"
    here = tempfile.mkdtemp(prefix="drill-empty-")          # no file of ours in it: nothing to see
    try:                                          # (a resumed drill finds it already made)
        old = client.containers.get(name)
        started_at = time.time() - 1
    except Exception:                                       # noqa: BLE001 - not there: make it
        _, run = make_rows(eid, stage="recorded", run_status="succeeded", budget_s=BUDGET_S,
                           detail="succeeded", dispatch_state="succeeded")
        old = client.containers.run(IMAGE, ["true"], detach=True, name=name,
                                    labels={RUN_LABEL: run, OWNER_LABEL: eid})
        old.wait(timeout=20)
        started_at = time.time()
    state["containers"]["N2OLD"] = old.id
    th = load(env)
    left = started_at + RETENTION_S + 3 - time.time()
    say(f"[N2] waiting {max(left, 0):.0f} s for the retention ({RETENTION_S} s) of {name}")
    time.sleep(max(left, 0))
    with reconciler_reader_scope() as conn:
        obs = observe(conn, client, directory=here, expected_uid=os.getuid(),
                      clock_us=lambda: time.time_ns() // 1000, max_pages=1)
    wanted = [a for a in plan(obs, th).actions if a.subject_id == old.id]
    if [(a.kind, a.reason_code) for a in wanted] != [("remove_container", "run_finished")]:
        say(f"[N2] the plan is not what was expected: {wanted}")
        return 5
    old.remove(force=True)                                  # someone else removes it ...
    newcomer = client.containers.run(IMAGE, ["sleep", "3600"], detach=True, name=name)   # ... and a
    state["containers"]["N2NEW"] = newcomer.id              #       new one takes the name
    results = act.carry_out(wanted, act.settings_for("state-only", [flags.CONTAINER]),
                            th=th, client=client, directory=here, expected_uid=os.getuid())
    newcomer.reload()
    ok = (results[0].outcome == outcome.GONE and newcomer.status == "running"
          and newcomer.id != old.id)
    say(f"[N2] the plan named {old.id[:12]}; the act said {results[0].outcome}; the newcomer "
        f"{newcomer.id[:12]} is {newcomer.status} ({'OK' if ok else 'FAILED'})")
    save(out, state)
    return 0 if ok else 5


def final_checks(client, state, out):
    """Docker's own record of what happened, against the audit trail's, against the expectation."""
    from sqlalchemy import text

    from control_plane.state.db import engagement_scope

    try:
        os.kill(state["witness_pid"], signal.SIGTERM)
    except ProcessLookupError:                  # already stopped (a resumed drill)
        pass
    time.sleep(1)
    role_of = {v: k for k, v in state["containers"].items()}
    destroyed, killed = set(), set()
    for line in (out / "docker-events.jsonl").read_text().splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        cid = e.get("id") or e.get("Actor", {}).get("ID")
        label = role_of.get(cid, f"(not the drill's) {str(cid)[:12]}")
        if e.get("Action") == "destroy":
            destroyed.add(label)
        if e.get("Action") == "kill":
            killed.add(label)
    say("Docker's own events: killed", sorted(killed), "destroyed", sorted(destroyed))
    audit = {}
    for role, eid in state["engagements"].items():
        with engagement_scope(eid) as conn:
            audit[role] = [(t, s) for t, s in conn.execute(text(
                "SELECT event_type, subject_id FROM audit_log WHERE actor = 'reconciler' "
                "ORDER BY audit_id"))]
    (out / "audit.json").write_text(json.dumps(audit, indent=1))
    for role, items in sorted(audit.items()):
        if items:
            say(f"  audit {role}: {[i[0].removeprefix('reconciler.') for i in items]}")
    survivors = []
    for role in NEGATIVES:
        cid = state["containers"].get(role)
        if cid is not None:
            c = client.containers.get(cid)
            survivors.append((role, c.status))
    say("survivors:", survivors)
    problems = []
    if destroyed != DESTROYED:
        problems.append(f"destroyed {sorted(destroyed)}, expected {sorted(DESTROYED)}")
    if not killed <= KILLED | {"(none)"} or "S1" not in killed:
        problems.append(f"killed {sorted(killed)}, expected {sorted(KILLED)}")
    for role in NEGATIVES:
        if role in destroyed | killed:
            problems.append(f"{role} was destroyed or killed")
    # an intent with no result, and a result with no intent
    events = [t for items in audit.values() for t, _ in items]
    intended = sum(t == "reconciler.action_intended" for t in events)
    results = sum(t in ("reconciler.container_killed", "reconciler.container_removed",
                        "reconciler.proxy_removed") for t in events)
    say(f"audit: {intended} intents, {results} verified results")
    if intended != results:
        problems.append("an intent without a verified result, or the reverse")
    say("RESULT:", "OK" if not problems else problems)
    return 0 if not problems else 6


# --------------------------------------------------------------------------- cleaning up

def clean(args) -> int:
    import hashlib

    out = Path(args.dir)
    state = json.loads((out / "state.json").read_text())
    client = docker_client()
    for role, cid in state["containers"].items():
        try:
            client.containers.get(cid).remove(force=True)
            say(f"removed {role}")
        except Exception:                                    # noqa: BLE001
            pass
    for cidr in state.get("cidrs", []):
        name = "cyberorch-allow-" + hashlib.sha256(cidr.encode()).hexdigest()[:12]
        try:
            client.networks.get(name).remove()
            say(f"removed network {name}")
        except Exception:                                    # noqa: BLE001
            pass
    say(f"closed {close_everything_stuck()} stuck proposal(s) the drill's engagements left")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="step", required=True)
    for name in ("seed", "play", "finish", "clean"):
        one = sub.add_parser(name)
        one.add_argument("--dir", required=True)
        if name == "seed":
            one.add_argument("--tidy", action="store_true",
                             help="first move every stuck test row of the development database to "
                                  "a terminal stage, as the test session's end does")
    one = sub.add_parser("child-proxy")
    for flag in ("--run", "--owner", "--tool-side", "--target-side"):
        one.add_argument(flag, required=True)
    one = sub.add_parser("child-live")
    for flag in ("--run", "--owner", "--proposal", "--cidr"):
        one.add_argument(flag, required=True)
    args = parser.parse_args(argv)
    from control_plane.config import load_dotenv
    load_dotenv()
    return {"seed": seed, "play": play, "finish": finish, "clean": clean,
            "child-proxy": child_proxy, "child-live": child_live}[args.step](args)


if __name__ == "__main__":
    raise SystemExit(main())
