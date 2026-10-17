"""The soak on a machine that is not the development machine (D66, ACCEPTANCE 5.112): the caps are
derived from what was measured, never above the default; a check that never ran fails the run;
sudo is used for the restarts of Postgres and of the Docker daemon and for nothing else.
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path
from types import SimpleNamespace

from scripts.soak import checks, faults, lib, measure, report

SOAK = Path(__file__).resolve().parents[1] / "scripts" / "soak"

RUNNER = {"mem_total_mb": 16000, "cores": 4, "disk_total_mb": 150_000, "disk_free_mb": 90_000,
          "nofile_soft": 65536, "pg_max_connections": 100, "pg_superuser_reserved": 3}


# -- the caps ---------------------------------------------------------------------------------

def test_a_big_machine_keeps_the_defaults_where_they_are_smaller():
    caps = measure.derive_caps(RUNNER)
    assert caps["rss_mb"] == {"scheduler": 512, "reconciler": 512, "worker": 1024,
                              "conductor": 1024}
    assert caps["fds"] == 1024 and caps["networks"] == 20
    assert caps["containers_total"] == 100                      # 25 per core, 4 cores
    assert caps["pg_backends_total"] == 77                      # 80 % of (100 - 3)
    assert caps["pg_connections_per_process"] == 20
    assert caps["run_dir_mb"] == 2048 and caps["disk_free_mb_min"] == 2048


def test_a_small_machine_gets_smaller_caps_and_none_is_ever_above_the_default():
    small = {"mem_total_mb": 2000, "cores": 1, "disk_total_mb": 8000, "disk_free_mb": 3000,
             "nofile_soft": 1024, "pg_max_connections": 40, "pg_superuser_reserved": 3}
    caps, defaults = measure.derive_caps(small), measure.DEFAULT_CAPS
    assert caps["rss_mb"]["scheduler"] == 100 and caps["rss_mb"]["worker"] == 160
    assert caps["fds"] == 512 and caps["containers_total"] == 25
    assert caps["pg_connections_per_process"] == 10 and caps["pg_backends_total"] == 29
    assert caps["run_dir_mb"] == 750 and caps["events_file_mb"] == 375
    assert caps["disk_free_mb_min"] == 512
    for key, value in defaults.items():
        if isinstance(value, dict):
            assert all(caps[key][k] <= v for k, v in value.items())
        else:
            assert caps[key] <= value


def test_what_is_not_measured_stays_at_the_default():
    assert measure.derive_caps({}) == measure.DEFAULT_CAPS | {
        "events_file_mb": measure.DEFAULT_CAPS["events_file_mb"]}


# -- a check that never ran -------------------------------------------------------------------

def every_check(*, judged=True):
    return [{"name": n, "ok": True, "judged": judged} for n in checks.CYCLE_CHECKS] + [
        {"name": checks.DRAIN_CHECK, "ok": True, "judged": True}]


def test_a_run_in_which_every_check_ran_and_judged_is_complete():
    assert checks.never_ran(every_check(), expect_drain=True) == []


def test_a_check_with_no_execution_is_named_and_fails_the_run():
    rows = [r for r in every_check() if r["name"] != "coherence"]
    assert checks.never_ran(rows, expect_drain=True) == ["coherence: never executed"]


def test_the_drain_check_is_expected_only_when_the_run_reached_the_drain():
    rows = [r for r in every_check() if r["name"] != checks.DRAIN_CHECK]
    assert checks.never_ran(rows, expect_drain=False) == []
    assert checks.never_ran(rows, expect_drain=True) == [f"{checks.DRAIN_CHECK}: never executed"]


def test_a_series_check_that_never_had_enough_windows_to_judge_fails_too():
    rows = [r for r in every_check() if r["name"] != "no connection leak"]
    rows += [{"name": "no connection leak", "ok": True, "judged": False}] * 3
    assert checks.never_ran(rows, expect_drain=True) == [
        "no connection leak: executed 3 times, never judged anything"]


def test_a_listed_check_is_exempt_from_judging_but_not_from_running():
    name = "unresolved reconciler intents (listed, not judged)"
    rows = [r for r in every_check() if r["name"] != name]
    assert checks.never_ran(rows, expect_drain=True) == [f"{name}: never executed"]
    rows.append({"name": name, "ok": True, "judged": False})
    assert checks.never_ran(rows, expect_drain=True) == []


def test_the_series_checks_say_when_they_had_too_little_to_judge():
    short = [{"ts": float(i * 60), "docker": {"tools": {"running": 1, "exited": 0},
                                              "proxies": {"running": 0}, "networks": 1,
                                              "files": 0},
              "pg": {"total": 10, "idle_in_transaction_max_age_s": 0}, "procs": {}}
             for i in range(10)]
    assert checks.residue_does_not_grow(short, 900.0).judged is False
    assert checks.no_connection_leak(short, 900.0).judged is False
    assert checks.residue_does_not_grow(short, 60.0).judged is True


def test_the_report_lists_every_check_with_its_count_and_marks_a_zero_as_failed():
    rows = [r for r in every_check() if r["name"] != "coherence"]
    conductor = SimpleNamespace(check_results=rows, halted=None)
    text = "\n".join(report._check_counts(conductor))
    assert "| coherence | 0 | 0 | **FAILED: coherence: never executed**" in text
    assert f"| {checks.DRAIN_CHECK} | 1 | 1 | ok |" in text
    assert "| schema is identical to the one at the start | 1 | 1 | ok |" in text


# -- the schema -------------------------------------------------------------------------------

def test_the_schema_check_holds_against_itself_and_fails_on_any_difference():
    from control_plane.config import load_dotenv
    load_dotenv()
    before = checks.schema_now()
    assert before and checks.schema_unchanged(before).ok
    changed = dict(before)
    changed["table:invented_table"] = "an extra fact"
    result = checks.schema_unchanged(changed)
    assert not result.ok and "invented_table" in result.detail


# -- the database as a role, and privilege ----------------------------------------------------

def test_a_monitoring_url_is_used_when_given_and_su_postgres_when_not(monkeypatch):
    seen = []

    def fake_run(command, **kwargs):
        seen.append(command)
        return SimpleNamespace(returncode=0, stdout="a|b\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setenv("SOAK_PSQL_URL", "postgresql://monitor@127.0.0.1/cyberorch")
    assert lib.psql("SELECT 1") == [["a", "b"]]
    assert seen[-1][:2] == ["psql", "postgresql://monitor@127.0.0.1/cyberorch"]
    monkeypatch.delenv("SOAK_PSQL_URL")
    lib.psql("SELECT 1")
    assert seen[-1][:3] == ["su", "postgres", "-c"]


def test_privileged_prefixes_sudo_only_when_not_root(monkeypatch):
    monkeypatch.setattr(faults.os, "geteuid", lambda: 0)
    assert faults.privileged(["dockerd"]) == ["dockerd"]
    monkeypatch.setattr(faults.os, "geteuid", lambda: 1001)
    assert faults.privileged(["dockerd"]) == ["sudo", "-n", "dockerd"]


def _parents(tree):
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node
    return tree


def test_sudo_is_named_in_one_function_and_privileged_is_called_by_two_restarts_only():
    allowed = {"postgres_restart", "docker_restart"}
    named, callers = [], set()
    for path in sorted(SOAK.glob("*.py")):
        tree = _parents(ast.parse(path.read_text()))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                    and "sudo" in node.value and "tests" not in path.name:
                function = node
                while function is not None and not isinstance(function, ast.FunctionDef):
                    function = getattr(function, "parent", None)
                named.append((path.name, function.name if function else "<module>"))
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "privileged":
                function = node
                while function is not None and not isinstance(function, ast.FunctionDef):
                    function = getattr(function, "parent", None)
                callers.add((path.name, function.name if function else "<module>"))
    # the word appears in the helper's docstring-free body: the command prefix only
    assert {n for n in named if n[1] != "privileged"} == set(), named
    assert callers == {("faults.py", n) for n in allowed}, callers


# -- what a smoke run does not enforce --------------------------------------------------------

def test_only_the_residue_check_is_not_enforced_and_only_in_a_smoke_run():
    residue = checks.Result(checks.SMOKE_NOT_ENFORCED[0], False, "floor rising")
    other = checks.Result("coherence", False, "a proposal is incoherent")
    assert checks.SMOKE_NOT_ENFORCED == (checks.CYCLE_CHECKS[5],)
    assert checks.is_finding(residue, smoke=False)             # a soak: an invariant
    assert not checks.is_finding(residue, smoke=True)          # a smoke run: recorded, not enforced
    assert checks.is_finding(other, smoke=True) and checks.is_finding(other, smoke=False)
    assert not checks.is_finding(checks.Result(checks.SMOKE_NOT_ENFORCED[0], True), smoke=False)


# -- a run that exercised nothing --------------------------------------------------------------

def test_a_run_in_which_every_request_was_refused_exercised_nothing():
    assert checks.workload_exercised(10, 3) == []
    assert checks.workload_exercised(0, 3) == [
        "no ALLOW proposal was ever recorded: the sandbox was not exercised"]
    assert checks.workload_exercised(10, 0)[0].startswith("no HUMAN_APPROVAL proposal")
    assert len(checks.workload_exercised(0, 0)) == 2
