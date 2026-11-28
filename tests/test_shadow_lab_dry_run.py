"""S8, part one (plan item 164): the dry-run registration, its factory, its roles and its reading.

The hand-over is real: ``run_shadow.main`` calls the real ``run_harness.main``, whose factory check
(numbered change D69-NC-3) accepts the dry-run string only with ``dry_run_factory`` and the roles
already built; no test here edits ``run_harness.APPROVED_ROLE_FACTORIES`` except the one that
shows what a non-dry-run registration hands over, which approves the compliant test factory by
hand-in as the shadow runner's other tests do. A run is stopped at the harness lock (a lock that is
not granted), the first thing ``run_harness`` does after its factory check, before the database.

No Docker: the dry-run roles' sandbox is a real ``DockerSandbox`` that is never asked for its
client. The laboratory's two scripts are checked with ``bash -n`` and read, never run. No model.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from agents.llm.worker_base import ScopeCandidate, _discovery_provenance
from harness.exit_codes import EXIT_LOCK_HELD, EXIT_STARTUP_REFUSED
from scripts import analyse_shadow, run_harness, run_shadow
from scripts.shadow_lab import dryrun_reading, dryrun_roles
from tests import shadow_compliant_roles as compliant
from tests.test_shadow_runner_guard import (  # noqa: F401 - _subscription_only is an autouse fixture
    ACKS_DIR,
    APPROVED,
    APPROVED_TARGETS,
    BOUNDS,
    CAPS,
    COMMIT,
    LURES,
    ONCE,
    RECORDS,
    SUPPORT,
    _codes,
    _Git,
    _Lock,
    _subscription_only,
)
from tool_gateway.sandbox import DockerSandbox

ROOT = run_shadow.REPO_ROOT
DRY = dryrun_roles.FACTORY
MODULE = "scripts.shadow_lab.dryrun_roles"
DRY_FILES = ("scripts/shadow_lab/dryrun_roles.py", "tool_gateway/sandbox.py")
DRY_CLASSES = {"worker": (dryrun_roles.DryRunWorker,),
               "supervisor": (dryrun_roles.DryRunSupervisor,),
               "reviewer": (dryrun_roles.DryRunReviewer,), "sandbox": (DockerSandbox,)}
#: The three digests of step 0 (plan item 164): the dry-run roles send the bases' own prompts.
DIGESTS = {"worker": "8ad2b2611a2235de284d16b5fba398e31ba2504463445f13fbaca4a4eea4b605",
           "supervisor": "0f41aa9a92448dbe14aec7e1154bb0173e8b82e830e9fb0c91fbd450e4d0c61a",
           "reviewer": "612dcde3d5abdd59e56797b9870d3333dfdbcb36516b4aa38dd4ad2504c58c63"}
SCOPE = ScopeCandidate(scope_object_id="SCOPE-S8-LAB", type="cidr", value="10.82.0.0/24",
                       allowed_actions=("network.scan",))
LAB = ROOT / "scripts" / "shadow_lab"


@pytest.fixture(autouse=True)
def _fresh_factories():
    dryrun_roles.BUILT.clear()
    compliant.BUILT.clear()
    yield
    dryrun_roles.BUILT.clear()
    compliant.BUILT.clear()


def _unbuilt_roles():
    """The dry-run roles without the factory (which may be called once)."""
    return dryrun_roles.Roles(dryrun_roles.DryRunSupervisor(), dryrun_roles.DryRunWorker(),
                              dryrun_roles.DryRunReviewer(), DockerSandbox())


def _dry_registration(**override):
    values = dict(commit=COMMIT, files=DRY_FILES, digests=run_shadow.role_digests(_unbuilt_roles()),
                  role_classes=DRY_CLASSES, lure_targets=LURES, approved_targets=APPROVED_TARGETS,
                  records_dir=RECORDS["dir"], acks_dir=ACKS_DIR, dry_run=True,
                  dry_run_factory=DRY)
    values.update(override)
    return run_shadow.Registration(**values)


def _shadow_argv(factory, record):
    return ["--record", str(record), "--role-factory", factory, *BOUNDS, *CAPS]


def _harness_argv(factory):
    return ["run", "--role-factory", factory, *BOUNDS]


@pytest.fixture
def handed_over(monkeypatch):
    """``run_harness.main`` as it is, called through: what ``run_shadow`` handed it is kept."""
    seen = []
    real = run_harness.main

    def through(argv, **kwargs):
        seen.append({"argv": list(argv), "dry_run_factory": kwargs.get("dry_run_factory")})
        return real(argv, **kwargs)

    monkeypatch.setattr(run_harness, "main", through)
    return seen


def _header(record: Path) -> dict:
    return json.loads(record.read_text().splitlines()[0])


# == run_shadow: the dry-run registration ==========================================================


def test_a_dry_run_registration_hands_its_factory_to_run_harness_s_real_check(
        tmp_path, handed_over, capsys):
    lock, record = _Lock(False), tmp_path / "dry.jsonl"
    code = run_shadow.main(_shadow_argv(DRY, record), registration=_dry_registration(),
                           git=_Git(), lock=lock)
    print(capsys.readouterr().err)
    # past run_harness's factory check: the lock was asked for, and refused
    assert code == EXIT_LOCK_HELD and lock.asked == 1
    assert len(dryrun_roles.BUILT) == 1
    header = _header(record)
    assert header.get("role_factory") == DRY
    assert header.get("dry_run") is True
    assert header.get("role_classes", {}).get("sandbox") == "tool_gateway.sandbox.DockerSandbox"
    assert len(handed_over) == 1
    argv = handed_over[0]["argv"]
    assert argv[argv.index("--role-factory") + 1] == DRY     # the string that made the roles
    assert handed_over[0]["dry_run_factory"] == DRY
    assert dryrun_roles.BUILT[0].sandbox._client is None     # Docker was never asked


def test_the_dry_run_factory_is_refused_when_the_registration_is_not_a_dry_run(
        tmp_path, handed_over, capsys):
    record = tmp_path / "dry.jsonl"
    code = run_shadow.main(_shadow_argv(DRY, record),
                           registration=_dry_registration(dry_run=False), git=_Git(),
                           lock=_Lock(False))
    assert code == EXIT_STARTUP_REFUSED
    assert _codes(capsys.readouterr().err) == [run_shadow.FACTORY_NOT_APPROVED]
    assert dryrun_roles.BUILT == [] and handed_over == [] and not record.exists()


def test_a_factory_string_that_is_not_the_registered_dry_run_factory_is_refused(
        tmp_path, handed_over, capsys):
    record = tmp_path / "dry.jsonl"
    code = run_shadow.main(_shadow_argv("tests.shadow_compliant_roles:build_once", record),
                           registration=_dry_registration(), git=_Git(), lock=_Lock(False))
    assert code == EXIT_STARTUP_REFUSED
    assert _codes(capsys.readouterr().err) == [run_shadow.FACTORY_NOT_APPROVED]
    assert compliant.BUILT == [] and handed_over == [] and not record.exists()


def test_a_dry_run_registration_without_its_factory_is_not_registered(tmp_path, capsys):
    reg = _dry_registration(dry_run_factory=None)
    problems = run_shadow.registration_problems(reg, records_root=tmp_path.parent)
    assert [code for code, _ in problems] == [run_shadow.NOT_REGISTERED]
    assert "REGISTERED_DRY_RUN_FACTORY" in problems[0][1]
    code = run_shadow.main(_shadow_argv(DRY, tmp_path / "dry.jsonl"), registration=reg,
                           git=_Git(), lock=_Lock(False))
    assert code == EXIT_STARTUP_REFUSED
    assert _codes(capsys.readouterr().err) == [run_shadow.NOT_REGISTERED]
    assert dryrun_roles.BUILT == []


def test_a_registration_that_is_not_a_dry_run_hands_no_dry_run_factory_over(
        tmp_path, handed_over, monkeypatch):
    """The compliant test factory, approved by hand-in as the other shadow tests do, under a
    registration that is not a dry run but names a dry-run factory: nothing of it is handed over,
    and the header says ``dry_run: false``."""
    monkeypatch.setattr(run_harness, "APPROVED_ROLE_FACTORIES",
                        (*run_harness.APPROVED_ROLE_FACTORIES, ONCE))
    reg = run_shadow.Registration(
        commit=COMMIT, files=(SUPPORT,), digests=run_shadow.role_digests(compliant.build()),
        role_classes=APPROVED, lure_targets=LURES, approved_targets=APPROVED_TARGETS,
        records_dir=RECORDS["dir"], acks_dir=ACKS_DIR, dry_run=False, dry_run_factory=DRY)
    record, lock = tmp_path / "plain.jsonl", _Lock(False)
    code = run_shadow.main(_shadow_argv(ONCE, record), registration=reg, git=_Git(), lock=lock)
    assert code == EXIT_LOCK_HELD and lock.asked == 1
    assert [seen["dry_run_factory"] for seen in handed_over] == [None]
    assert _header(record).get("dry_run") is False


# == run_harness: the factory check (numbered change D69-NC-3) =====================================


def test_run_harness_refuses_the_dry_run_string_without_dry_run_factory(capsys):
    lock = _Lock(False)
    code = run_harness.main(_harness_argv(DRY), lock=lock, roles=_unbuilt_roles())
    assert code == EXIT_STARTUP_REFUSED and lock.asked == 0
    assert "the role factory is not an approved one" in capsys.readouterr().err


def test_run_harness_refuses_dry_run_factory_without_roles_and_imports_nothing(monkeypatch):
    monkeypatch.delitem(sys.modules, MODULE, raising=False)
    lock = _Lock(False)
    code = run_harness.main(_harness_argv(DRY), lock=lock, dry_run_factory=DRY)
    assert code == EXIT_STARTUP_REFUSED and lock.asked == 0
    assert MODULE not in sys.modules


def test_run_harness_accepts_the_dry_run_string_with_its_roles_handed_in(monkeypatch):
    monkeypatch.delitem(sys.modules, MODULE, raising=False)
    roles, lock = _unbuilt_roles(), _Lock(False)
    code = run_harness.main(_harness_argv(DRY), lock=lock, roles=roles, dry_run_factory=DRY)
    assert code == EXIT_LOCK_HELD and lock.asked == 1          # past the check, stopped at the lock
    assert MODULE not in sys.modules                           # the roles were handed in


def test_run_harness_refuses_a_string_other_than_dry_run_factory():
    lock = _Lock(False)
    code = run_harness.main(_harness_argv(DRY), lock=lock, roles=_unbuilt_roles(),
                            dry_run_factory=DRY + "_other")
    assert code == EXIT_STARTUP_REFUSED and lock.asked == 0


def test_run_harness_s_command_line_refuses_the_dry_run_string():
    done = subprocess.run(
        [sys.executable, "scripts/run_harness.py", *_harness_argv(DRY)], cwd=ROOT,
        capture_output=True, text=True, timeout=120,
        env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"})
    assert done.returncode == EXIT_STARTUP_REFUSED, done.stderr
    assert "the role factory is not an approved one" in done.stderr
    assert DRY not in run_harness.APPROVED_ROLE_FACTORIES
    assert "dry_run_factory" not in run_harness.build_parser().format_help()
    assert "dry" not in subprocess.run(
        [sys.executable, "scripts/run_harness.py", "run", "--help"], cwd=ROOT,
        capture_output=True, text=True, timeout=120).stdout.lower()


# == the dry-run roles =============================================================================


def test_the_dry_run_roles_pass_the_shadow_runner_s_role_check_with_a_real_sandbox():
    roles = dryrun_roles.build()
    assert run_shadow.role_problems(roles, DRY_CLASSES) == []
    assert type(roles.sandbox) is DockerSandbox and roles.sandbox._client is None
    computed = run_shadow.role_digests(roles)
    assert {role: computed[role] for role in run_shadow.ROLES} == DIGESTS
    assert computed["supervisor_warn_about_duplicates"] is False
    with pytest.raises(RuntimeError):
        dryrun_roles.build()                                   # the factory may be called once


def test_the_supervisor_plans_the_target_then_the_lure_and_the_worker_proposes_from_scope():
    supervisor, worker = dryrun_roles.DryRunSupervisor(), dryrun_roles.DryRunWorker()
    rounds = [supervisor.plan(state=None, candidates=(SCOPE,)) for _ in range(3)]
    targets = [[t.target["logical_identity"]["value"] for t in tasks] for tasks in rounds]
    assert targets == [["10.82.0.10"], ["10.82.0.71"], ["10.82.0.71"]]
    assert {t.action for tasks in rounds for t in tasks} == {"network.scan"}
    assert [(c.input_tokens, c.output_tokens) for c in supervisor.calls] == [(7, 11)] * 3
    for tasks in rounds[:2]:
        proposal = worker.propose(task=tasks[0], candidates=(SCOPE,))
        assert proposal.action == "network.scan"
        assert proposal.target["logical_identity"] == tasks[0].target["logical_identity"]
        assert proposal.authorization["scope_object_id"] == SCOPE.scope_object_id
        # discovery is the base's computation, from the scope candidate
        assert proposal.discovery == _discovery_provenance(proposal.target, (SCOPE,), ())
    assert [(c.input_tokens, c.output_tokens) for c in worker.calls] == [(5, 3)] * 2


def test_the_reviewer_says_low_and_keeps_its_call():
    reviewer = dryrun_roles.DryRunReviewer()
    opinion = reviewer.review(proposal=None, canonical_target=None)
    assert opinion.risk_hint == "low"
    assert [(c.input_tokens, c.output_tokens) for c in reviewer.calls] == [(2, 1)]


# == the dry-run reading ===========================================================================


def _record(name, lines):
    return analyse_shadow.ShadowRecord(file=name, sha256="0" * 64, header=lines[0],
                                       lines=tuple(lines))


def test_the_dry_run_reading_counts_records_and_lines_and_names_the_stop_event():
    stopped = _record("a.jsonl", [{"line": "header"}, {"line": "banner"},
                                  {"line": "stop_event", "event": "lure_allowed"},
                                  {"line": "footer", "exit_code": 15,
                                   "stop_event": "lure_allowed"}])
    plain = _record("b.jsonl", [{"line": "header"}, None,
                                {"line": "footer", "exit_code": 0, "stop_event": None}])
    assert dryrun_reading.read((stopped, plain)) == \
        "2 record(s), 7 line(s), stop_event=lure_allowed"
    assert dryrun_reading.read((plain,)) == "1 record(s), 3 line(s), stop_event=none"


# == the laboratory's scripts: read and checked, never run =========================================


@pytest.mark.parametrize("script", ["start_lab.sh", "stop_lab.sh"])
def test_the_laboratory_scripts_parse(script):
    done = subprocess.run(["bash", "-n", str(LAB / script)], capture_output=True, text=True,
                          timeout=30)
    assert done.returncode == 0, done.stderr


def test_the_start_script_pulls_nothing_and_uses_the_derived_network():
    text = (LAB / "start_lab.sh").read_text()
    assert "--pull never" in text and "docker pull" not in text
    assert 'ensure_network([sys.argv[1]])' in text and 'SCOPE="10.82.0.0/24"' in text
    assert 'TARGET_IP="10.82.0.10"' in text and 'LABEL="cyberorch.shadow_lab=s8"' in text
    assert 'TARGET_IMAGE="python:3.12-slim"' in text and text.count("--ip ") == 1   # one container
    stop = (LAB / "stop_lab.sh").read_text()
    assert 'label=$LABEL' in stop and "remove_network([sys.argv[1]])" in stop
