"""D69 H7: the laboratory end to end, driven the way the operator runbook says to.

Every step is a **process**: the operator CLIs (``scripts/manage_harness_enrolment.py``,
``scripts/run_harness.py``, ``scripts/run_reconciler.py``) run as subprocesses on the test database
with the scripted roles of ``tests/harness_h7_roles.py`` and no sandbox that can run anything. What
the tests read back is read as ``cyberorch_app`` in a read-only transaction. Each test says which
section of ``docs/D69_HARNESS_OPERATOR_RUNBOOK.md`` it checks (``runbook 2.3`` ...), and where the
runbook's own text is the input (the banner's field list, the recovery snippet) the test reads it
from the runbook file, so a runbook that is edited is the one that is tested.

The tests end their own enrolments (withdraw, then delete the rows as the table's owner: the app
role has no DELETE). The one thing they leave to the repository's own mechanism is the stuck
proposal a reviewer fault leaves at ``received`` (``conftest._each_test_finishes_what_it_started``),
as H5c1's H5-3 test and H5c2's residue tests already do.

S9 is the one place time is moved: the reconciler's grace is at least 300 s (``config.minimums``),
so the proposal's ``stage_updated_at`` is set back as the owner, the way
``tests/reconciler_support.py`` does, and the first dry run (inside the grace) is on the real, fresh
proposal.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api.function_api import propose_action
from control_plane.orchestrator.engagement import engage_kill_switch
from control_plane.policy.layers import load_effective_policy
from control_plane.reconciler.config import KEYS as RECONCILER_KEYS
from control_plane.state.db import engagement_scope
from tests.test_harness_h5c1_support import FakeSandbox, make_world, task_rows

ROOT = Path(__file__).resolve().parents[1]
RUNBOOK = ROOT / "docs" / "D69_HARNESS_OPERATOR_RUNBOOK.md"
ENROL = ROOT / "scripts" / "manage_harness_enrolment.py"
RUN = ROOT / "scripts" / "run_harness.py"
RECONCILER = ROOT / "scripts" / "run_reconciler.py"
TIMEOUT = 120
ACTOR = "h7-operator"
EPOCH = "1970-01-02 00:00:00+00"


# -- running the commands as the runbook writes them -----------------------------------------------


def _env(**extra) -> dict:
    return {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", **extra}


def _call(script: Path, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    """A script as a process: no terminal on standard input, as in a pipe or a cron job."""
    return subprocess.run(
        [sys.executable, "-B", str(script), *args], cwd=ROOT, env=env or _env(),
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=TIMEOUT)


def _register(engagement_id: str, *, yes: bool = True, purpose: str = "harness_lab"):
    args = ["register", "--engagement", engagement_id, "--purpose", purpose, "--actor", ACTOR]
    return _call(ENROL, *args, *(["--yes"] if yes else []))


def _withdraw(engagement_id: str, *, yes: bool = True):
    args = ["withdraw", "--engagement", engagement_id, "--actor", ACTOR]
    return _call(ENROL, *args, *(["--yes"] if yes else []))


def _list_lines() -> list[str]:
    done = _call(ENROL, "list")
    assert done.returncode == 0, done.stderr
    return done.stdout.splitlines()


def _live_engagements() -> list[str]:
    """The engagement of each ``[live]`` line of ``list``, in the order it prints them."""
    return [line.split()[1] for line in _list_lines() if line.endswith("[live]")]


def _run_loop(worlds, *, rounds: int = 1, once: bool = True, no_progress: int = 5,
              fault: bool = False, tasks: int = 3) -> subprocess.CompletedProcess:
    env = _env(H7_SCOPES=",".join(f"{w.engagement_id}={w.scope_id}" for w in worlds),
               H7_TASKS=str(tasks), **({"H7_FAULT": "reviewer"} if fault else {}))
    args = ["run", "--role-factory", "tests.harness_h7_roles:build", "--objective", "o",
            "--window-limit", "25", "--max-rounds", str(rounds), "--max-model-calls", "100",
            "--no-progress-limit", str(no_progress), "--live-task-limit", "200"]
    return _call(RUN, *args, *(["--once"] if once else []), env=env)


def _residue() -> subprocess.CompletedProcess:
    return _call(RUN, "residue", "--live-task-limit", "10")


def _residue_tasks(done: subprocess.CompletedProcess) -> dict[str, list[str]]:
    """task ids by status, from the lines of the listing."""
    found: dict[str, list[str]] = {}
    for line in done.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) > 2 and parts[2].startswith("status="):
            found.setdefault(parts[2].removeprefix("status="), []).append(parts[1])
    return found


@contextlib.contextmanager
def _ended(*engagement_ids: str):
    """Whatever happens: withdraw these engagements and remove the test's rows (as the owner)."""
    try:
        yield
    finally:
        for engagement_id in engagement_ids:
            _withdraw(engagement_id)
        engine = create_engine(os.environ["MIGRATION_DATABASE_URL"], future=True)
        try:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE harness_enrolment NO FORCE ROW LEVEL SECURITY"))
                conn.execute(text("DELETE FROM harness_enrolment WHERE engagement_id = ANY(:ids)"),
                             {"ids": list(engagement_ids)})
                conn.execute(text("ALTER TABLE harness_enrolment FORCE ROW LEVEL SECURITY"))
        finally:
            engine.dispose()


# -- reading the database ------------------------------------------------------------------------


def _read(engagement_id: str, sql: str, **params) -> list[dict]:
    with engagement_scope(engagement_id) as conn:
        conn.execute(text("SET TRANSACTION READ ONLY"))
        return [dict(r) for r in conn.execute(text(sql), params).mappings()]


def _proposal_of_task(engagement_id: str, task_id: str) -> dict:
    """The proposal the loop made for a task (its key is ``h5:<task_id>:1``): where it stands, and
    whether anything that follows a decision exists. Read only."""
    key = f"h5:{task_id}:1"
    (row,) = _read(
        engagement_id,
        "SELECT p.proposal_id, p.pipeline_stage, p.decision, p.stage_detail, p.task_id, "
        "(SELECT count(*) FROM capabilities c WHERE c.proposal_id = p.proposal_id) AS capabilities,"
        " (SELECT count(*) FROM tool_runs r WHERE r.proposal_id = p.proposal_id) AS runs "
        "FROM action_proposals p WHERE p.request_idempotency_key = :k", k=key)
    return row


def _audit(engagement_id: str, subject_id: str) -> list[dict]:
    return _read(engagement_id,
                 "SELECT event_type, actor, payload FROM audit_log "
                 "WHERE event_type = 'task.completed' AND subject_id = :s ORDER BY ts, audit_id",
                 s=subject_id)


# -- the runbook's own text ----------------------------------------------------------------------


def _runbook_section(start: str, end: str) -> str:
    text_ = RUNBOOK.read_text()
    return text_[text_.index(start):text_.index(end)]


def _banner_fields_in_the_runbook() -> list[str]:
    section = _runbook_section("### 3.3 ", "### 3.4 ")
    return re.findall(r"^\| `([a-z_]+)` \|", section, flags=re.MULTILINE)


def _recovery_snippet(engagement_id: str, task_id: str) -> str:
    """The Python block of runbook 6.4 step 5, with the three placeholders filled."""
    section = _runbook_section("### 6.4 ", "## 7. ")
    block = re.search(r"```python\n(.*?)```", section, flags=re.DOTALL).group(1)
    block = "\n".join(
        line[3:] if line.startswith("   ") else line for line in block.splitlines())
    for placeholder, value in (
            ('"ENG-…"', repr(engagement_id)), ('task_id="…"', f"task_id={task_id!r}"),
            ('"<your name>"', repr(ACTOR))):
        assert placeholder in block, placeholder
        block = block.replace(placeholder, value)
    return block


def _recover(engagement_id: str, task_id: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-B", "-c", _recovery_snippet(engagement_id, task_id)],
                          cwd=ROOT, env=_env(), stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=TIMEOUT)


# -- fixtures ------------------------------------------------------------------------------------


@pytest.fixture
def world(engagement_id, registry):
    return make_world(engagement_id, registry)


@pytest.fixture
def world2(engagement_factory):
    eid, registry = engagement_factory()
    return make_world(eid, registry)


def _after_a_fault(world):
    """Enrol, run with the reviewer raising: the state the runbook's section 6 is about."""
    assert _register(world.engagement_id).returncode == 0
    done = _run_loop([world], fault=True)
    assert done.returncode == 12, done.stderr
    return done


# == S1 registration (runbook 2.3) ==


def test_s1_register_asks_for_a_person_or_yes_and_refuses_what_it_should(engagement_id):
    nowhere = "ENG-H7-NOPE-0123456789ab"
    with _ended(engagement_id):
        # runbook 2.3: "with no terminal it refuses (exit 2)" -- and nothing is written
        asked = _register(engagement_id, yes=False)
        assert asked.returncode == 2
        assert "no terminal to confirm on" in asked.stderr
        assert engagement_id not in "\n".join(_list_lines())

        # runbook 2.3: with --yes it is done (exit 0)
        done = _register(engagement_id)
        assert done.returncode == 0, done.stderr
        assert f"registered {engagement_id} (harness_lab)" in done.stdout

        # runbook 2.1: list shows it, with the purpose, the actor as typed and [live]
        (line,) = [ln for ln in _list_lines() if f" {engagement_id} " in ln]
        assert "purpose=harness_lab" in line and f"registered by {ACTOR}" in line
        assert line.endswith("[live]")

        # runbook 2.3: refusals -- already registered, no such engagement
        twice = _register(engagement_id)
        assert twice.returncode == 1 and "refused: already registered" in twice.stderr
        absent = _register(nowhere)
        assert absent.returncode == 1 and "refused: no such engagement" in absent.stderr
        assert nowhere not in "\n".join(_list_lines())

        # runbook 2.3: a purpose other than harness_lab. The CLI refuses it itself, before the
        # database (the database's own "purpose refused" is only the fallback behind it)
        other = _register(engagement_id, purpose="production")
        assert other.returncode == 1
        assert "refused: --purpose is one of harness_lab" in other.stderr
        assert "purpose refused" not in other.stderr


# == S2 withdrawal (runbook 2.4) ==


def test_s2_withdraw_ends_the_registration_and_a_second_withdrawal_is_refused(engagement_id):
    with _ended(engagement_id):
        assert _register(engagement_id).returncode == 0

        done = _withdraw(engagement_id)
        assert done.returncode == 0 and f"withdrawn {engagement_id}" in done.stdout
        (line,) = [ln for ln in _list_lines() if f" {engagement_id} " in ln]
        assert f"[withdrawn by {ACTOR} at " in line and not line.endswith("[live]")
        assert engagement_id not in _live_engagements()

        again = _withdraw(engagement_id)
        assert again.returncode == 1 and "refused: not currently registered" in again.stderr

        # without --yes and with no terminal it is not done (runbook 2.4: it asks for WITHDRAW)
        assert _register(engagement_id).returncode == 0
        asked = _withdraw(engagement_id, yes=False)
        assert asked.returncode == 2 and engagement_id in _live_engagements()


# == S3 a normal run (runbook 3.1 to 3.3 and 4) ==


def test_s3_a_run_once_ends_with_0_and_prints_the_banner_the_runbook_describes(world, world2):
    with _ended(world.engagement_id, world2.engagement_id):
        assert _register(world.engagement_id).returncode == 0
        assert _register(world2.engagement_id).returncode == 0
        expected = _live_engagements()
        assert expected == [world.engagement_id, world2.engagement_id]       # runbook 2.1

        done = _run_loop([world, world2])

        assert done.returncode == 0, done.stderr                              # runbook 4, code 0
        lines = done.stdout.splitlines()
        # runbook 3.3: eleven fields, one line each, in the runbook's order
        fields = _banner_fields_in_the_runbook()
        assert len(fields) == 11
        assert [ln.split(":", 1)[0] for ln in lines] == fields
        # runbook 2.1 / 3.3: the banner's engagements are the live rows of `list`, in that order
        banner = dict(ln.split(": ", 1) for ln in lines)
        assert banner["engagements"] == ", ".join(expected)
        assert banner["lock_key"] == "0x0D69_5C4E_D000_0001"
        # runbook 3.2 step 9: the last line of standard error
        assert done.stderr.splitlines()[-1].startswith("harness stopped (exit 0): ")
        assert "reason=signal_or_once" in done.stderr.splitlines()[-1]
        # runbook 4, code 0: "run residue to confirm it is empty"
        left = _residue()
        assert left.returncode == 0 and left.stdout.splitlines()[0] == "0 live task(s)"
        for world_ in (world, world2):                  # and the plans really were carried out
            assert {row[1] for row in task_rows(world_.engagement_id)} == {"completed"}


# == S4 a fault (runbook 4 code 12, 6.1, 6.2) ==


def test_s4_a_fault_in_the_reviewer_ends_with_12_and_leaves_what_the_runbook_says(world):
    with _ended(world.engagement_id):
        done = _after_a_fault(world)

        # runbook 4, code 12: nothing is cleaned up; the line says why it stopped
        assert "reason=fault_outside_the_list" in done.stderr.splitlines()[-1]
        assert "injected" not in done.stderr and "RuntimeError" not in done.stdout
        # runbook 6.1: one claimed task and the rest queued, listed as tasks
        left = _residue()
        assert left.returncode == 0 and left.stdout.splitlines()[0] == "3 live task(s)"
        found = _residue_tasks(left)
        assert sorted(found) == ["claimed", "queued"]
        assert len(found["claimed"]) == 1 and len(found["queued"]) == 2
        # runbook 6.2 (a): the proposal of the claimed task is at `received`, with no decision, and
        # nothing that follows a decision exists -- observed, not inferred
        observed = _proposal_of_task(world.engagement_id, found["claimed"][0])
        print("OBSERVED S4 proposal of the claimed task:", observed)
        assert observed["pipeline_stage"] == "received"
        assert observed["decision"] is None and observed["stage_detail"] is None
        assert observed["capabilities"] == 0 and observed["runs"] == 0
        # runbook 6.2 (c): the listing is tasks only -- it names no proposal
        assert observed["proposal_id"] not in left.stdout
        # and the queued tasks have no proposal at all (the loop never reached them)
        for task_id in found["queued"]:
            assert _read(world.engagement_id,
                         "SELECT 1 FROM action_proposals WHERE request_idempotency_key = :k",
                         k=f"h5:{task_id}:1") == []


# == S5 the next start is refused (runbook 4 code 10 (b)) ==


def test_s5_the_next_start_is_refused_with_10_and_no_refused_line(world):
    with _ended(world.engagement_id):
        _after_a_fault(world)
        before = task_rows(world.engagement_id)

        done = _run_loop([world])

        assert done.returncode == 10, done.stderr
        stderr = done.stderr.splitlines()
        # runbook 4, code 10 (b): no `refused:` line, the final line says startup_check_refused
        assert not [ln for ln in stderr if ln.startswith("refused:")]
        assert stderr[-1].startswith("harness stopped (exit 10): ")
        assert "reason=startup_check_refused" in stderr[-1]
        assert task_rows(world.engagement_id) == before       # nothing was planned or claimed


# == S6 hand recovery (runbook 6.4) ==


def test_s6_the_recovery_snippet_completes_the_leftovers_and_the_next_start_passes(world):
    with _ended(world.engagement_id):
        _after_a_fault(world)
        found = _residue_tasks(_residue())
        leftovers = found["claimed"] + found["queued"]

        for task_id in leftovers:                      # runbook 6.4 step 5, word for word
            done = _recover(world.engagement_id, task_id)
            assert done.returncode == 0, done.stderr

        rows = task_rows(world.engagement_id)
        assert sorted((r[1], r[5]) for r in rows) == [("completed", "not_run")] * 3
        for task_id in leftovers:                      # runbook 6.4: the audit record carries it
            (record,) = _audit(world.engagement_id, task_id)
            assert record["actor"] == ACTOR
            assert "not_run" in str(record["payload"])
        # runbook 6.4 step 6: residue is empty, and the next start's check passes
        left = _residue()
        assert left.stdout.splitlines()[0] == "0 live task(s)"
        restart = _run_loop([world])
        assert restart.returncode == 0, restart.stderr


def test_s6b_the_snippet_overwrites_a_completed_task_and_a_mistyped_id_still_writes_an_audit(
        world):
    """Runbook 6.4 step 3 warns that ``complete_task`` has no precondition and does not check that
    a row matched. Here that is run: the first claim was a [D], this makes it an observation."""
    with _ended(world.engagement_id):
        assert _register(world.engagement_id).returncode == 0
        assert _run_loop([world]).returncode == 0     # three tasks, each completed by the pipeline
        before = task_rows(world.engagement_id)
        summaries = sorted(r[5] for r in before)
        assert summaries == ["DENY"] * 3
        completed_id = before[0][0]
        assert len(_audit(world.engagement_id, completed_id)) == 1

        done = _recover(world.engagement_id, completed_id)  # a task that is already completed
        assert done.returncode == 0, done.stderr
        after = {r[0]: r for r in task_rows(world.engagement_id)}
        print("OBSERVED S6b completed task, summary before/after:", before[0][5],
              after[completed_id][5], "audit records:",
              len(_audit(world.engagement_id, completed_id)))
        assert after[completed_id][1] == "completed" and after[completed_id][5] == "not_run"
        assert len(_audit(world.engagement_id, completed_id)) == 2         # a second record
        others = [r for r in task_rows(world.engagement_id) if r[0] != completed_id]
        assert [r[5] for r in others] == ["DENY"] * 2                      # nothing else touched

        mistyped = "TASK-h7-no-such-task"
        done = _recover(world.engagement_id, mistyped)
        assert done.returncode == 0, done.stderr
        assert task_rows(world.engagement_id) == list(after.values())      # no row changed
        written = len(_audit(world.engagement_id, mistyped))
        print("OBSERVED S6b mistyped id, audit records:", written)
        assert written == 1                                       # and a record was written


# == S7 the kill switch (runbook 5.3) ==


def test_s7_a_killed_engagement_is_skipped_and_counted_and_the_run_ends_by_the_rules(world):
    with _ended(world.engagement_id):
        assert _register(world.engagement_id).returncode == 0
        with engagement_scope(world.engagement_id) as conn:    # the tests' way: a direct call
            engage_kill_switch(conn, engagement_id=world.engagement_id, actor=ACTOR, reason="h7")

        once = _run_loop([world])
        last = once.stderr.splitlines()[-1]
        print("OBSERVED S7 --once:", once.returncode, last)
        assert once.returncode == 0
        assert "'skipped_engagement': 1" in last                 # "skipped and counted"
        assert task_rows(world.engagement_id) == []              # no Supervisor call, no task
        assert _read(world.engagement_id, "SELECT 1 FROM action_proposals") == []

        # "a round in which every engagement was skipped counts as no progress" (item 54): a run
        # that is not --once stops by the no-progress limit, exit 14 (runbook 4)
        looping = _run_loop([world], rounds=5, once=False, no_progress=2)
        print("OBSERVED S7 no --once:", looping.returncode, looping.stderr.splitlines()[-1])
        assert looping.returncode == 14
        assert "reason=no_progress" in looping.stderr.splitlines()[-1]
        assert "'skipped_engagement': 2" in looping.stderr.splitlines()[-1]
        assert task_rows(world.engagement_id) == []


# == S8 how to tell whether a proposal got past the decision (runbook 6.4 step 4) ==


def test_s8_the_proposal_of_a_task_is_found_by_its_key_and_says_how_far_it_got(world):
    with _ended(world.engagement_id):
        _after_a_fault(world)
        claimed = _residue_tasks(_residue())["claimed"][0]
        stuck = _proposal_of_task(world.engagement_id, claimed)
        # the stuck one: no decision, so it did not get past the decision stage; no run
        assert (stuck["pipeline_stage"], stuck["decision"]) == ("received", None)

        # the contrast, on the same query: a task whose proposal was decided (a DENY here)
        for task_id in _residue_tasks(_residue())["claimed"] + _residue_tasks(_residue())["queued"]:
            assert _recover(world.engagement_id, task_id).returncode == 0
        assert _run_loop([world]).returncode == 0
        decided = _read(world.engagement_id,
                        "SELECT task_id FROM tasks WHERE result_summary = 'DENY' LIMIT 1")
        contrast = _proposal_of_task(world.engagement_id, decided[0]["task_id"])
        print("OBSERVED S8 stuck:", stuck)
        print("OBSERVED S8 decided:", contrast)
        assert contrast["decision"] == "DENY" and contrast["pipeline_stage"] == "closed"
        assert contrast["capabilities"] == 0 and contrast["runs"] == 0

        # and query_state's counts, which the runbook does not rely on, name no task
        counts = _read(world.engagement_id, "SELECT (SELECT count(*) FROM action_proposals) AS p")
        assert counts[0]["p"] == 1 + 3


# == S9 the reconciler (runbook 6.2 (b)) ==


def _reconciler_env() -> dict:
    """The thresholds the reconciler requires, from ``.env.example`` (the recommended values); the
    ``.env`` of the working copy is not touched."""
    values = {}
    for line in (ROOT / ".env.example").read_text().splitlines():
        found = re.match(r"^(RECONCILER_[A-Z_]+)=(\d+)\s*(#.*)?$", line)
        if found and found.group(1) in RECONCILER_KEYS:
            values[found.group(1)] = found.group(2)
    assert set(values) == set(RECONCILER_KEYS)
    return _env(**values)


def _reconcile(mode: str, engagement_id: str):
    done = _call(RECONCILER, "--mode", mode, "--once", "--engagement", engagement_id,
                 env=_reconciler_env())
    lines = [json.loads(ln) for ln in done.stdout.splitlines() if ln.startswith("{")]
    return done, lines


def _set_back(engagement_id: str, proposal_id: str) -> None:
    """As the table's owner with the engagement bound, as ``reconciler_support.close_touched``."""
    engine = create_engine(os.environ["MIGRATION_DATABASE_URL"], future=True)
    try:
        with engine.begin() as conn:
            conn.execute(text("SELECT set_config('cyberorch.engagement_id', :e, true)"),
                         {"e": engagement_id})
            conn.execute(text("UPDATE action_proposals SET stage_updated_at = "
                              "CAST(:t AS timestamptz) WHERE proposal_id = :p"),
                         {"t": EPOCH, "p": proposal_id})
    finally:
        engine.dispose()


def test_s9_the_reconciler_abandons_the_stuck_proposal_only_after_its_grace(world):
    with _ended(world.engagement_id):
        _after_a_fault(world)
        claimed = _residue_tasks(_residue())["claimed"][0]
        stuck = _proposal_of_task(world.engagement_id, claimed)["proposal_id"]

        # inside the grace (the fresh, real proposal): a dry run lists nothing for it
        inside, lines = _reconcile("dry-run", world.engagement_id)
        print("OBSERVED S9 dry run inside the grace:", inside.returncode, lines)
        assert inside.returncode == 0
        assert not [ln for ln in lines if ln.get("subject_id") == stuck]

        # outside it: the stage time is set back; the dry run now plans to abandon it, and changes
        # nothing
        _set_back(world.engagement_id, stuck)
        outside, lines = _reconcile("dry-run", world.engagement_id)
        planned = [ln for ln in lines if ln.get("subject_id") == stuck]
        print("OBSERVED S9 dry run outside the grace:", outside.returncode, planned)
        assert outside.returncode == 0
        assert [(p["kind"], p["reason_code"]) for p in planned] == [
            ("abandon", "undecided_past_grace")]
        assert _proposal_of_task(world.engagement_id, claimed)["pipeline_stage"] == "received"

        # state-only, with no --enable: the stage moves, and nothing else does
        carried, lines = _reconcile("state-only", world.engagement_id)
        done = [ln for ln in lines if ln.get("subject_id") == stuck]
        print("OBSERVED S9 state-only:", carried.returncode, done)
        assert carried.returncode == 0, carried.stderr
        assert [(d["kind"], d["reason_code"]) for d in done] == [
            ("abandon", "undecided_past_grace")]
        after = _proposal_of_task(world.engagement_id, claimed)
        print("OBSERVED S9 proposal after:", after)
        assert (after["pipeline_stage"], after["decision"], after["stage_detail"]) == (
            "abandoned", None, "undecided_past_grace")


# == S9b the same key again (runbook 6.2 (d)) ==


def _send_again(world, proposal_row, key, reviewer):
    (stored,) = _read(world.engagement_id,
                      "SELECT target -> 'logical_identity' ->> 'value' AS value "
                      "FROM action_proposals WHERE proposal_id = :p", p=proposal_row["proposal_id"])
    host = int(stored["value"].rsplit(".", 1)[1])
    proposal = world.proposal(world.task(host), None)
    with engagement_scope(world.engagement_id) as conn:
        policy = load_effective_policy(conn, world.engagement_id)
    return propose_action(
        engagement_id=world.engagement_id, proposal=proposal, reviewer=reviewer, policy=policy,
        agent_id="h7-worker", actor=ACTOR, sandbox=FakeSandbox(), idempotency_key=key)


class _CountingReviewer(HonestFakeReviewer):
    def __init__(self):
        super().__init__()
        self.calls = 0

    def review(self, **kwargs):
        self.calls += 1
        return super().review(**kwargs)


def test_s9b_the_same_key_resumes_a_received_proposal_and_is_told_abandoned_after_it(world):
    with _ended(world.engagement_id):
        _after_a_fault(world)
        claimed = _residue_tasks(_residue())["claimed"][0]
        stuck = _proposal_of_task(world.engagement_id, claimed)
        key = f"h5:{claimed}:1"

        # runbook 6.2 (d): while it is `received`, the same key resumes it at the decision stage:
        # a new Reviewer call and a decision (the neutral baseline of the test database denies)
        reviewer = _CountingReviewer()
        outcome = _send_again(world, stuck, key, reviewer)
        resumed = _proposal_of_task(world.engagement_id, claimed)
        print("OBSERVED S9b resumed:", outcome.decision, outcome.proposal_id, reviewer.calls,
              resumed)
        assert reviewer.calls == 1
        assert outcome.proposal_id == stuck["proposal_id"]      # the same proposal, not a new one
        assert outcome.decision == "DENY" and resumed["decision"] == "DENY"
        assert resumed["pipeline_stage"] == "closed"


def test_s9b_after_the_reconciler_the_same_key_is_answered_abandoned_and_asks_no_reviewer(world):
    with _ended(world.engagement_id):
        _after_a_fault(world)
        claimed = _residue_tasks(_residue())["claimed"][0]
        stuck = _proposal_of_task(world.engagement_id, claimed)
        _set_back(world.engagement_id, stuck["proposal_id"])
        carried, _ = _reconcile("state-only", world.engagement_id)
        assert carried.returncode == 0, carried.stderr

        reviewer = _CountingReviewer()
        outcome = _send_again(world, stuck, f"h5:{claimed}:1", reviewer)
        print("OBSERVED S9b abandoned:", outcome.decision, outcome.failure, outcome.deny_reasons,
              reviewer.calls)
        assert reviewer.calls == 0
        assert outcome.failure == "abandoned" and outcome.decision == "DENY"
        assert outcome.proposal_id == stuck["proposal_id"]
