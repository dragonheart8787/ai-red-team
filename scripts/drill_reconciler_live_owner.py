"""A drill of the reconciler beside control planes that are alive (completion 4, item 1).

    python scripts/drill_reconciler_live_owner.py run   --dir DIR      # ~4 minutes, unattended
    python scripts/drill_reconciler_live_owner.py clean --dir DIR

The first drill (``drill_reconciler_docker.py``) showed the reconciler removing what a dead control
plane left and leaving alone a container whose live owner was late *at two moments*. It did not
show a pass in the interval that matters: the reconciler running **every 5 seconds** through
``[B, B + margin + 10 s]`` while the owner is alive, and the owner killing first. This one does.

One reconciler, the product's own command line in loop mode (``--interval 3``: three seconds of
waiting after each pass, and a pass takes about two, so one pass every five seconds; confirmed on a
pseudo-terminal), with only ``kill`` enabled and the pass limited to the drill's own engagements
(``--engagement``). Three tool containers of 30-second budgets (``B = 30``), each owned by a real
sandbox run in a control-plane process of its own, with no in-container deadline:

====  ==========================================================  ==============================
L1    the owner is alive and healthy                                 killed by its owner at about B
L2    the owner is alive and **late**: stopped (SIGSTOP) at the      killed by its owner after it
      start, continued 40 s later -- ten seconds after the deadline  continues, inside the margin;
                                                                     the reconciler's passes run
                                                                     while it is overdue
F     the owner is alive and **frozen** (SIGSTOP) for good           killed by the reconciler at
                                                                     the first pass at or after
                                                                     ``B + margin`` (90 s)
====  ==========================================================  ==============================

What is shown, and by whom: Docker's own event stream (``docker events``) for every kill and
removal; the process state of each owner (read from ``/proc``, once a second) at the moment of its
container's kill, so that "the owner killed it" is "a process that was running", and "the reconciler
killed it" is "the owner was stopped"; every reconciler pass with the moment it was seen; and the
audit trail, in which the reconciler's events are the *only* ones that are the reconciler's.

Then, for F's corpse -- whose run is declared ``unknown_outcome`` by hand, as the reconciler would
do after ``B + P + Q`` (a quarter of an hour that the drill does not wait for) -- the retention
(45 s here) and the evidence archive of ACCEPTANCE 5.97: a dry run and a real pass **before** the
retention is over change nothing; one **after** it removes the container, after its inspect output
and logs were written to files whose SHA-256 are in the audit trail.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pty
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(HERE))

import drill_reconciler_docker as base  # noqa: E402

BUDGET_S = 30
INTERVAL_S = 3             # the wait between passes; a pass takes about 2 s, so one every ~5 s
RETENTION_S = 45
LATE_BY_S = 40              # L2's owner is stopped this long: past its deadline, inside the margin
ROLES = ("L1", "L2", "F")


def say(*parts):
    print(*parts, flush=True)


# --------------------------------------------------------------------------- the reconciler loop

class Loop:
    """The product's command line in loop mode, on a pseudo-terminal, every line stamped with the
    moment it was seen."""

    def __init__(self, args, env, answer):
        self.lines: list[tuple[float, str]] = []
        self.code: int | None = None
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.chdir(str(REPO_ROOT))
            os.execve(sys.executable, [sys.executable, base.CLI, *args], env)
        self.answer, self.answered = answer, False
        self.buffer = ""
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        while True:
            try:
                chunk = os.read(self.fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            self.buffer += chunk.decode(errors="replace").replace("\r\n", "\n")
            asked = "Type exactly:" in self.buffer and self.buffer.rstrip().endswith(">")
            if not self.answered and asked:
                os.write(self.fd, self.answer.encode())
                self.answered = True
                self.buffer = ""
                continue
            while "\n" in self.buffer:
                line, self.buffer = self.buffer.split("\n", 1)
                self.lines.append((time.time(), line))

    def records(self):
        out = []
        for seen, line in list(self.lines):
            if line.startswith("{"):
                try:
                    out.append((seen, json.loads(line)))
                except ValueError:
                    pass
        return out

    def passes(self):
        return [(t, r) for t, r in self.records() if "summary" in r]

    def stop(self) -> int:
        if self.code is None:
            try:
                os.kill(self.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            _, status = os.waitpid(self.pid, 0)
            self.thread.join(timeout=5)
            self.code = os.waitstatus_to_exitcode(status)
        return self.code


def process_state(pid: int) -> str:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("State:"):
                return line.split(None, 1)[1].strip()
    except OSError:
        return "gone"
    return "unknown"


def fresh_cidr(client, first: int) -> str:
    """A /29 nobody has used: the sandbox names a network by its range and keeps it for the
    engagement that made it, so a range left by an earlier drill would refuse this one."""
    import random
    taken = {conf.get("Subnet", "") for network in client.networks.list()
             for conf in (network.attrs.get("IPAM", {}) or {}).get("Config") or []}
    for _ in range(200):
        cidr = f"10.{first}.{random.randrange(50, 250)}.{random.randrange(0, 256, 8)}/29"
        if not any(cidr.rsplit(".", 1)[0] in t for t in taken):
            return cidr
    raise SystemExit("no free range")


def started_at(container) -> float:
    from datetime import datetime
    stamp = container.attrs["State"]["StartedAt"]
    return datetime.fromisoformat(stamp[:26].rstrip("Z") + "+00:00").timestamp()


# --------------------------------------------------------------------------- the drill

def run(args) -> int:
    """The drill, and then -- whatever happened -- what it made is taken away again."""
    holder: dict = {}
    try:
        return _run(args, holder)
    finally:
        for key in ("loop",):
            if key in holder:
                holder[key].stop()
        if "witness" in holder:
            holder["witness"].terminate()
        if "out" in holder:
            _clean_up(Path(holder["out"]))


def _run(args, holder) -> int:
    from sqlalchemy import text

    from control_plane.reconciler.config import load
    from control_plane.state.db import engagement_scope
    from tests.helpers import deactivate_global_layer, ensure_test_baseline, make_engagement

    out = Path(args.dir)
    out.mkdir(parents=True, exist_ok=True)
    holder["out"] = str(out)
    vault = out / "evidence"
    vault.mkdir(mode=0o700, exist_ok=True)
    os.chmod(vault, 0o700)
    client = base.docker_client()
    from control_plane.config import load_dotenv
    load_dotenv()
    ours = (client.containers.list(all=True, filters={"label": base.RUN_LABEL})
            + client.containers.list(all=True, filters={"label": base.PROXY_LABEL}))
    if ours:
        raise SystemExit(f"refusing to start: {len(ours)} container(s) of the sandbox exist "
                         "already")
    env = base.drill_env()
    env["RECONCILER_RETENTION_S"] = str(RETENTION_S)
    th = load(env)
    margin = th.kill_margin_s
    bound = BUDGET_S + margin
    say(f"B = {BUDGET_S} s, margin = {margin} s, the reconciler's bound for a container is "
        f"B + margin = {bound} s after its start; a wait of {INTERVAL_S} s after each pass; "
        f"retention {RETENTION_S} s")

    tag = uuid.uuid4().hex[:6]
    state = {"tag": tag, "dir": str(out), "engagements": {}, "containers": {}, "rows": {},
             "children": {}, "cidrs": []}
    published = ensure_test_baseline()
    try:
        for role in ROLES:
            eid = f"ENG-LIVE-{tag}-{role}"
            make_engagement(eid)
            state["engagements"][role] = eid
    finally:
        if published is not None:
            deactivate_global_layer(published, actor="drill")
    eids = state["engagements"]
    for role in ROLES:
        prop, run_id = base.make_rows(eids[role], stage="dispatching", run_status="running",
                                      budget_s=BUDGET_S)
        state["rows"][role] = {"proposal": prop, "run": run_id}
    base.save(out, state)

    witness = subprocess.Popen(
        ["docker", "events", "--format", "{{json .}}", "--filter", "type=container"],
        stdout=open(out / "docker-events.jsonl", "w"), stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL)
    holder["witness"] = witness
    time.sleep(1)

    flags = ["--mode", "state-only", "--interval", str(INTERVAL_S), "--enable", "kill"]
    for role in ROLES:
        flags += ["--engagement", eids[role]]
    loop = Loop(flags, env, "enable kill\n")
    holder["loop"] = loop
    deadline = time.monotonic() + 60
    while len(loop.passes()) < 2 and time.monotonic() < deadline:
        time.sleep(0.5)
    if len(loop.passes()) < 2:
        say("the reconciler did not start passing")
        loop.stop()
        witness.terminate()
        return 3
    say(f"the reconciler is passing ({len(loop.passes())} passes so far)")

    # the owners: three real control-plane processes, each in the middle of a sandbox run
    children, cidrs = {}, {}
    for number, role in enumerate(ROLES):
        cidr = fresh_cidr(client, 100 + number)
        cidrs[role] = cidr
        child = subprocess.Popen(
            [sys.executable, str(HERE / "drill_reconciler_docker.py"), "child-live",
             "--run", state["rows"][role]["run"], "--owner", eids[role],
             "--proposal", state["rows"][role]["proposal"], "--cidr", cidr,
             "--noisy"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, text=True,
            cwd=str(REPO_ROOT))
        children[role] = child
        state["children"][role] = child.pid
        state["cidrs"].append(cidr)
        base.save(out, state)                      # (so that an early stop can still be cleaned)
        container = base.wait_for(
            lambda role=role: base.find(client, state["rows"][role]["run"], proxy=False), 60,
            f"the tool container of {role}")
        state["containers"][role] = container.id
        if role in ("L2", "F"):
            os.kill(child.pid, signal.SIGSTOP)
    base.save(out, state)
    starts = {role: started_at(client.containers.get(state["containers"][role])) for role in ROLES}
    t0 = min(starts.values())
    say("containers started at " + ", ".join(f"{r} +{starts[r] - t0:.1f}s" for r in ROLES))

    # watch: once a second, each container's state and each owner's process state
    watch = []
    resumed = False
    resumed_at = None
    horizon = max(starts.values()) + bound + 30
    while time.time() < horizon:
        now = time.time()
        row = {"t": now}
        for role in ROLES:
            try:
                row[role] = client.containers.get(state["containers"][role]).status
            except Exception:                                        # noqa: BLE001 - gone
                row[role] = "gone"
            row[role + "_owner"] = process_state(children[role].pid)
        watch.append(row)
        if not resumed and now >= starts["L2"] + LATE_BY_S:
            os.kill(children["L2"].pid, signal.SIGCONT)
            resumed, resumed_at = True, now
            say(f"the late owner (L2) continues at +{now - t0:.1f}s, after {LATE_BY_S} s stopped; "
                f"its deadline passed at +{starts['L2'] + BUDGET_S - t0:.1f}s")
        if row["F"] != "running" and now > starts["F"] + bound:
            time.sleep(INTERVAL_S + 2)      # a few more passes after the kill
            break
        time.sleep(1)
    code = loop.stop()
    say(f"the reconciler stopped (exit {code}) after {len(loop.passes())} passes")
    (out / "watch.jsonl").write_text("\n".join(json.dumps(r) for r in watch))
    (out / "loop-output.txt").write_text(
        "\n".join(f"{t - t0:8.1f}  {line}" for t, line in loop.lines))

    # --- F's corpse: the retention and the evidence ---------------------------------------
    f_id = state["containers"]["F"]
    f_run, f_eid = state["rows"]["F"]["run"], eids["F"]
    corpse = None
    try:
        corpse = client.containers.get(f_id)
    except Exception:                                                 # noqa: BLE001
        pass
    problems = []
    retention = {}
    if corpse is not None and corpse.status != "running":
        with engagement_scope(f_eid) as conn:
            conn.execute(text("UPDATE tool_runs SET status = 'unknown_outcome', "
                              "finished_at = coalesce(finished_at, now()) WHERE run_id = :r"),
                         {"r": f_run})
        finished = base_finished(corpse)
        retention["finished_at"] = finished
        flags_f = ["--engagement", f_eid]
        status, shown = base.run_cli(["--mode", "dry-run", "--once", *flags_f], env)
        early = [x for x in base.parse(shown) if x.get("kind") == "remove_container"]
        # (the dry run above ran inside the retention if the kill was recent enough; say when)
        retention["dry_run_before_retention_s_after_finish"] = round(time.time() - finished, 1)
        retention["dry_run_before_retention_plan"] = early
        if early and time.time() - finished < RETENTION_S:
            problems.append("a removal was planned inside the retention")
        words = ["--enable", "container", "--evidence-dir", str(vault)]
        status, shown = base.run_cli(["--mode", "state-only", "--once", *flags_f, *words], env,
                                     answer="enable container\n")
        inside = [x for x in base.parse(shown) if x.get("kind") == "remove_container"]
        retention["real_pass_before_retention_s_after_finish"] = round(time.time() - finished, 1)
        if time.time() - finished < RETENTION_S and inside:
            problems.append("a removal was carried out inside the retention")
        if status != 0:
            problems.append(f"the pass before the retention exited {status}")
        left = finished + RETENTION_S + 2 - time.time()
        say(f"waiting {max(left, 0):.0f} s for the retention of F's corpse")
        time.sleep(max(left, 0))
        status, shown = base.run_cli(["--mode", "dry-run", "--once", *flags_f], env)
        plan_after = [x for x in base.parse(shown) if x.get("kind") == "remove_container"]
        retention["dry_run_after_retention_plan"] = plan_after
        (out / "retention-plan.jsonl").write_text(
            "\n".join(json.dumps(x) for x in base.parse(shown)))
        status, shown = base.run_cli(["--mode", "state-only", "--once", *flags_f, *words], env,
                                     answer="enable container\n")
        (out / "retention-run.jsonl").write_text(
            "\n".join(json.dumps(x) for x in base.parse(shown)))
        done = [x for x in base.parse(shown) if x.get("kind") == "remove_container"]
        retention["real_pass_after_retention"] = done
        if [(x["reason_code"], x["outcome"]) for x in done] != [("run_unknown_outcome", "done")]:
            problems.append(f"the removal after the retention was {done}")
        retention["real_pass_exit"] = status
    else:
        problems.append("F's container was not left to be judged")

    witness.terminate()
    time.sleep(1)
    problems += check(client, state, out, starts, watch, loop, bound, vault, retention, f_id, t0,
                      resumed_at)
    (out / "retention.json").write_text(json.dumps(retention, indent=1, default=str))
    say("RESULT:", "OK" if not problems else problems)
    return 0 if not problems else 6


def base_finished(container) -> float:
    from datetime import datetime
    stamp = container.attrs["State"]["FinishedAt"]
    return datetime.fromisoformat(stamp[:26].rstrip("Z") + "+00:00").timestamp()


def docker_events(out: Path, roles_of: dict[str, str]):
    rows = []
    for line in (out / "docker-events.jsonl").read_text().splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        cid = e.get("id") or e.get("Actor", {}).get("ID")
        if cid in roles_of and e.get("Action") in ("create", "start", "kill", "die", "destroy"):
            rows.append((e["timeNano"] / 1e9, roles_of[cid], e["Action"],
                         (e.get("Actor", {}).get("Attributes") or {}).get("signal", "")))
    return sorted(rows)


def check(client, state, out, starts, watch, loop, bound, vault, retention, f_id, t0,
          resumed_at):
    from sqlalchemy import text

    from control_plane.state.db import engagement_scope

    problems: list[str] = []
    roles_of = {v: k for k, v in state["containers"].items()}
    events = docker_events(out, roles_of)
    kills = {role: [t for t, r, a, _ in events if r == role and a == "kill"] for role in ROLES}
    say("Docker's own record (seconds after the first container started):")
    for t, role, action, sig in events:
        say(f"  +{t - t0:7.1f}  {role:<3} {action}{(' signal ' + sig) if sig else ''}")
    # audit: the reconciler's events by engagement
    audit = {}
    for role, eid in state["engagements"].items():
        with engagement_scope(eid) as conn:
            rows = conn.execute(text(
                "SELECT ts, event_type, payload FROM audit_log WHERE actor = 'reconciler' "
                "ORDER BY audit_id")).all()
            audit[role] = [(float(ts.timestamp()), et, payload) for ts, et, payload in rows]
    (out / "audit.json").write_text(json.dumps(
        {r: [{"t": t - t0, "event": e, "payload": p} for t, e, p in v] for r, v in audit.items()},
        indent=1))
    for role in ROLES:
        say(f"  audit {role}: {[e.removeprefix('reconciler.') for _, e, _ in audit[role]]}")
    passes = [t for t, _ in loop.passes()]
    low, high = starts["L1"] + BUDGET_S, starts["L1"] + bound + 10
    # the passes that cover [B, B + margin + 10 s]: those inside it and the one on each side
    before = [t for t in passes if t < low][-1:]
    after = [t for t in passes if t > high][:1]
    inside = [t for t in passes if low <= t <= high]
    covering = before + inside + after
    gaps = [b - a for a, b in zip(covering, covering[1:], strict=False)]
    say(f"passes: {len(passes)} in all; {len(inside)} inside [B, B + margin + 10 s] = "
        f"[+{BUDGET_S}, +{bound + 10}] s of the containers' start (a wait of {INTERVAL_S} s "
        f"after each pass, plus the pass itself); the longest gap in that interval is "
        f"{max(gaps):.1f} s")
    if not before or not after:
        problems.append("the passes do not reach both ends of the window")
    elif max(gaps) > 6.5:           # "every five seconds": a wait, and a pass of about two
        problems.append(f"a gap between passes of {max(gaps):.1f} s in the window")
    # the owners
    def owner_state_at(role, when):
        before = [r for r in watch if r["t"] <= when]
        return before[-1][role + "_owner"] if before else "?"

    for role in ("L1", "L2"):
        if len(kills[role]) != 1:
            problems.append(f"{role}: {len(kills[role])} kill events")
            continue
        k = kills[role][0]
        state_then = owner_state_at(role, k)
        continued = f" (continued at +{resumed_at - t0:.1f}s)" if role == "L2" else ""
        say(f"  {role}: killed at +{k - starts[role]:.1f}s of its life by a process that was "
            f"'{state_then}'{continued}; the reconciler's bound was +{bound}s")
        if k - starts[role] >= bound:
            problems.append(f"{role}: killed after the reconciler's bound")
        if k - starts[role] < BUDGET_S - 2:
            problems.append(f"{role}: killed before its budget")
        if role == "L1" and state_then.startswith("T"):
            problems.append("L1: the owner was stopped when the container was killed")
        if role == "L2" and k < resumed_at - 0.1:
            problems.append("L2: the container was killed before its owner continued")
        if audit[role]:
            problems.append(f"{role}: the reconciler wrote {len(audit[role])} audit event(s)")
    late = kills["L2"][0] - (starts["L2"] + BUDGET_S) if kills["L2"] else None
    if late is not None:
        overdue = [t for t in passes if starts["L2"] + BUDGET_S < t < kills["L2"][0]]
        say(f"  L2 was past its deadline for {late:.1f} s (inside the {bound - BUDGET_S} s margin) "
            f"when its owner killed it; {len(overdue)} reconciler pass(es) ran while it was "
            "overdue and none acted")
        if late <= 5:
            problems.append("L2 was not late enough to be seen overdue")
        if not overdue:
            problems.append("no pass ran while L2 was overdue")
    # F
    if len(kills["F"]) != 1:
        problems.append(f"F: {len(kills['F'])} kill events")
    else:
        k = kills["F"][0]
        state_then = owner_state_at("F", k)
        say(f"  F: killed at +{k - starts['F']:.1f}s of its life, its owner '{state_then}'; the "
            f"reconciler's bound is +{bound}s")
        if k - starts["F"] < bound:
            problems.append("F: killed before the reconciler's bound")
        if k - starts["F"] > bound + INTERVAL_S + 6:
            problems.append("F: killed long after the bound")
        if not state_then.startswith("T"):
            problems.append("F: the owner was not stopped")
        names = [e for _, e, _ in audit["F"]]
        if names[:2] != ["reconciler.action_intended", "reconciler.container_killed"]:
            problems.append(f"F: audit {names}")
    # no pass ever planned a kill before the bound, for anything
    for _, r in loop.records():
        if r.get("kind") == "kill_container":
            if r["subject_id"] != f_id:
                problems.append("a kill planned for something that is not F")
    first_plan = [t for t, r in loop.passes()
                  if any(k.startswith("kill_container") for k in r["summary"])]
    if first_plan:
        say(f"  the first pass that planned a kill: +{first_plan[0] - starts['F']:.1f}s of F's "
            "life")
        if first_plan[0] - starts["F"] < bound:
            problems.append("a kill was planned before the bound")
    # the corpse
    done = retention.get("real_pass_after_retention") or []
    if done:
        evidence = [e for e in audit["F"] if e[1] == "reconciler.evidence_saved"]
        order = [e.removeprefix("reconciler.") for _, e, _ in audit["F"]]
        say(f"  F's trail: {order}")
        if order != ["action_intended", "container_killed", "action_intended", "evidence_saved",
                    "container_removed"]:
            problems.append(f"F: audit order {order}")
        if len(evidence) == 1:
            payload = evidence[0][2]
            inspect_path = vault / state["engagements"]["F"] / (f_id + ".inspect.json")
            logs_path = vault / state["engagements"]["F"] / (f_id + ".logs")
            for key, path in (("inspect_sha256", inspect_path), ("logs_sha256", logs_path)):
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                say(f"  {key} in the trail {payload[key][:16]}...  "
                    f"sha256 of {path.name[:14]}... {digest[:16]}...")
                if digest != payload[key]:
                    problems.append(f"{key} does not match the file")
            if str(vault) in json.dumps(payload):
                problems.append("a path is in the audit trail")
            if oct(os.stat(inspect_path).st_mode & 0o777) != "0o600":
                problems.append("the inspect file is not 0600")
            kept_files = sorted(p.name[:14] + p.suffix for p in inspect_path.parent.iterdir())
            say(f"  files: {kept_files}")
        else:
            problems.append("no single evidence_saved event for F")
        try:
            client.containers.get(f_id)
            problems.append("F's corpse is still there")
        except Exception:                                            # noqa: BLE001
            pass
    for role in ("L1", "L2"):
        for _, e, _ in audit[role]:
            problems.append(f"{role}: audit event {e}")
    return problems


def _clean_up(out: Path) -> None:
    """Take away what the drill made: its owners, its containers, its networks, its stuck rows."""
    import hashlib as _h

    try:
        state = json.loads((out / "state.json").read_text())
    except OSError:
        return
    client = base.docker_client()
    for pid in state.get("children", {}).values():
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    for role, cid in state.get("containers", {}).items():
        try:
            client.containers.get(cid).remove(force=True)
            say(f"removed {role}")
        except Exception:                                            # noqa: BLE001
            pass
    for cidr in state.get("cidrs", []):
        name = "cyberorch-allow-" + _h.sha256(cidr.encode()).hexdigest()[:12]
        deadline = time.monotonic() + 15           # (an owner's own removal may still be running)
        while time.monotonic() < deadline:
            try:
                client.networks.get(name).remove()
                say(f"removed network {name}")
                break
            except Exception:                                        # noqa: BLE001
                time.sleep(1)
    say(f"closed {base.close_everything_stuck()} stuck proposal(s) the drill's engagements left")


def clean(args) -> int:
    _clean_up(Path(args.dir))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="step", required=True)
    for name in ("run", "clean"):
        sub.add_parser(name).add_argument("--dir", required=True)
    args = parser.parse_args(argv)
    from control_plane.config import load_dotenv
    load_dotenv()
    return {"run": run, "clean": clean}[args.step](args)


if __name__ == "__main__":
    raise SystemExit(main())
