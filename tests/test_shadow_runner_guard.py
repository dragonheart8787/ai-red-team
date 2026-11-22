"""D69 shadow runner, stage S1 (plan items 134, 137): ``scripts/run_shadow.py`` refuses before it
reads the database, in a fixed order -- the registration constants, the integrity guard, the
factory string, the factory, the roles, the prompt digests -- and hands the roles it checked to
``scripts/run_harness.py`` in this process.

The integrity guard's tests build a real git repository under pytest's ``tmp_path``, as
``tests/test_dp15_stage1_run.py`` does for D68's guard; this file is the only one of S1 that writes
a temporary file. Everywhere else git is a function handed in. No model, no container, no database.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys

import pytest

from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from agents.llm import auth_guard
from harness.banner_facts import BannerFactsUnavailable
from harness.exit_codes import EXIT_LOCK_HELD, EXIT_STARTUP_REFUSED
from scripts import run_harness, run_shadow
from tests import shadow_compliant_roles as compliant
from tests.test_harness_h7_528 import _Worker as H7Worker

ROOT = run_shadow.REPO_ROOT
SUPPORT = "tests/shadow_compliant_roles.py"
ONCE = "tests.shadow_compliant_roles:build_once"
PROBE = "tests.harness_unapproved_roles"
COMMIT = "c" * 40
BOUNDS = ["--objective", "o", "--window-limit", "25", "--max-rounds", "1",
          "--max-model-calls", "100", "--no-progress-limit", "5", "--live-task-limit", "200"]
APPROVED = {"worker": (compliant.ShadowWorker,), "supervisor": (compliant.ShadowSupervisor,),
            "reviewer": (compliant.ShadowReviewer,), "sandbox": (compliant.ShadowSandbox,)}
#: A record path whose directory does not exist: a run refused before step 7 never creates it.
NOWHERE = "/nonexistent/shadow-record.jsonl"
#: The two caps run_shadow requires (S3, plan item 143); large enough never to be reached here.
CAPS = ["--max-tokens", "100000", "--max-minutes", "60"]
#: What ``claude auth status --json`` says for a subscription login (plan item 145): handed in, so
#: that no test runs the CLI.
SUBSCRIPTION_LOGIN = {"loggedIn": True, "authMethod": "claude.ai", "apiProvider": "firstParty"}


def _harness_argv(factory=ONCE):
    return ["--role-factory", factory, *BOUNDS]


def _argv(factory=ONCE, record=NOWHERE):
    return ["--record", str(record), *_harness_argv(factory), *CAPS]


@pytest.fixture(autouse=True)
def _subscription_only(monkeypatch):
    """The billing guard (plan item 143) sees no billing variable and no user settings file, so
    that these tests do not depend on the machine they run on; the guard's own tests are in
    ``tests/test_shadow_runner_auth.py``."""
    for name in auth_guard.BILLING_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", "/nonexistent/claude-config")
    monkeypatch.setattr(auth_guard, "query_login", lambda **kwargs: dict(SUBSCRIPTION_LOGIN))


def _registration(**override):
    values = dict(commit=COMMIT, files=(SUPPORT,),
                  digests=run_shadow.role_digests(compliant.build()), role_classes=APPROVED)
    values.update(override)
    return run_shadow.Registration(**values)


class _Git:
    """A git that says the checkout is the registered one: HEAD contains it, the tree is clean, and
    every registered file's blob is the file's own bytes. Counts its calls."""

    def __init__(self):
        self.calls = []

    def __call__(self, repo, *args):
        self.calls.append(args)
        if args[0] == "show":
            name = args[1].split(":", 1)[1]
            return subprocess.CompletedProcess(args, 0, (repo / name).read_bytes(), b"")
        out = b"abc\n" if args[0] == "rev-parse" else b""
        return subprocess.CompletedProcess(args, 0, out, b"")


class _Lock:
    def __init__(self, granted):
        self.granted, self.asked, self.closed = granted, 0, 0

    def acquire(self):
        self.asked += 1
        return self.granted

    def close(self):
        self.closed += 1


@pytest.fixture
def through(monkeypatch):
    """The compliant factory approved by hand-in (the product tuple is not edited), and the
    harness's first database read replaced: the banner's facts are collected by a spy that keeps
    the roles it was given and stops the run there."""
    compliant.BUILT.clear()
    monkeypatch.setattr(run_harness, "APPROVED_ROLE_FACTORIES",
                        (*run_harness.APPROVED_ROLE_FACTORIES, ONCE))
    seen = []

    class _Reader:
        def enrolled(self):
            return ("ENG-SHADOW",)

    def spy(**kwargs):
        seen.append(kwargs)
        raise BannerFactsUnavailable("stopped by the test after the hand-over")

    monkeypatch.setattr(run_harness, "EnrolledFromDatabase", _Reader)
    monkeypatch.setattr(run_harness, "collect_banner_facts", spy)
    yield seen
    compliant.BUILT.clear()


def _codes(err):
    return [line.split(": ", 2)[1] for line in err.splitlines() if line.startswith("refused: ")]


# -- 1. the registration constants -----------------------------------------------------------------


def test_the_four_constants_are_empty_and_the_runner_refuses_with_them(capsys):
    assert run_shadow.REGISTERED_COMMIT is None and run_shadow.REGISTERED_FILES is None
    assert run_shadow.REGISTERED_DIGESTS is None and run_shadow.APPROVED_ROLE_CLASSES == {}
    git, lock = _Git(), _Lock(True)
    sys.modules.pop(PROBE, None)
    code = run_shadow.main(_argv(f"{PROBE}:build"), git=git, lock=lock)
    assert code == EXIT_STARTUP_REFUSED
    assert _codes(capsys.readouterr().err) == [run_shadow.NOT_REGISTERED]
    assert git.calls == [] and lock.asked == 0 and PROBE not in sys.modules


@pytest.mark.parametrize("empty", [dict(commit=None), dict(files=None), dict(digests=None),
                                   dict(role_classes={})], ids=lambda d: next(iter(d)))
def test_any_one_empty_constant_is_a_refusal(empty, capsys):
    git, lock = _Git(), _Lock(True)
    sys.modules.pop(PROBE, None)
    code = run_shadow.main(_argv(f"{PROBE}:build"), registration=_registration(**empty), git=git,
                           lock=lock)
    assert code == EXIT_STARTUP_REFUSED
    assert _codes(capsys.readouterr().err) == [run_shadow.NOT_REGISTERED]
    assert git.calls == [] and lock.asked == 0 and PROBE not in sys.modules


def test_a_listed_class_whose_module_is_not_registered_is_a_refusal(capsys):
    reg = _registration(files=("scripts/run_shadow.py",))
    git = _Git()
    assert run_shadow.main(_argv(), registration=reg, git=git) == EXIT_STARTUP_REFUSED
    assert set(_codes(capsys.readouterr().err)) == {run_shadow.CLASS_MODULE_NOT_REGISTERED}
    assert git.calls == []


# -- 2. the integrity guard, on a real repository under tmp_path -----------------------------------


def sh(repo, *args):
    done = subprocess.run(
        ["git", "-c", "user.name=s1", "-c", "user.email=s1@example.invalid",
         "-c", "commit.gpgsign=false", *args],
        cwd=repo, capture_output=True, text=True, check=True)
    return done.stdout.strip()


FILES = ("plan.md", "analysis.py")


@pytest.fixture
def repo(tmp_path):
    """A repository with a registered commit; the only code file is ``run.py``."""
    root = tmp_path / "r"
    root.mkdir()
    sh(root, "init", "-q", "-b", "main")
    for name in FILES:
        (root / name).write_text(f"{name} as registered\n")
    (root / "run.py").write_text("run v1\n")
    sh(root, "add", "-A")
    sh(root, "commit", "-q", "-m", "registered")
    return root


def guard(repo, **kw):
    registered = sh(repo, "rev-list", "--max-parents=0", "HEAD")
    return run_shadow.integrity(repo=repo, registered_commit=registered, files=FILES,
                                code=("run.py",), **kw)


def _problem_codes(got):
    return {code for code, _ in got.problems}


def test_the_registered_tree_passes_and_the_code_hash_is_recorded(repo):
    got = guard(repo)
    assert got.problems == [] and got.head == sh(repo, "rev-parse", "HEAD")
    assert got.registered_sha256 == got.current_sha256 and len(got.current_sha256) == 2
    assert got.code_sha256 == {"run.py": hashlib.sha256(b"run v1\n").hexdigest()}


def test_a_changed_code_file_is_recorded_and_not_compared(repo):
    (repo / "run.py").write_text("run v2\n")
    sh(repo, "commit", "-q", "-am", "mended")
    got = guard(repo)
    assert got.problems == []
    assert got.code_sha256 == {"run.py": hashlib.sha256(b"run v2\n").hexdigest()}


def test_an_uncommitted_change_is_a_refusal(repo):
    (repo / "plan.md").write_text("changed, not committed\n")
    assert _problem_codes(guard(repo)) == {run_shadow.TREE_NOT_CLEAN,
                                           run_shadow.REGISTERED_FILE_DIFFERS}


def test_an_untracked_file_alone_is_a_refusal_even_where_git_hides_untracked_files(repo):
    sh(repo, "config", "status.showUntrackedFiles", "no")
    (repo / "stray.txt").write_text("untracked\n")
    assert _problem_codes(guard(repo)) == {run_shadow.TREE_NOT_CLEAN}


def test_a_head_that_does_not_contain_the_registered_commit_is_a_refusal(repo):
    registered = sh(repo, "rev-list", "--max-parents=0", "HEAD")
    sh(repo, "checkout", "-q", "--orphan", "other")
    sh(repo, "commit", "-q", "-m", "another history with the same bytes")
    got = run_shadow.integrity(repo=repo, registered_commit=registered, files=FILES,
                               code=("run.py",))
    assert _problem_codes(got) == {run_shadow.REGISTERED_COMMIT_NOT_IN_HEAD}


def test_a_registered_file_unequal_to_its_blob_is_a_refusal_on_a_clean_tree(repo):
    (repo / "analysis.py").write_text("analysis, changed and committed\n")
    sh(repo, "commit", "-q", "-am", "changed after registration")
    assert _problem_codes(guard(repo)) == {run_shadow.REGISTERED_FILE_DIFFERS}


def test_a_git_that_cannot_be_run_is_a_refusal_not_a_pass(repo):
    def broken(repo_, *args):
        raise FileNotFoundError("git")

    got = guard(repo, git=broken)
    assert got.problems and _problem_codes(got) >= {run_shadow.GIT_UNAVAILABLE}
    assert got.head is None and got.registered_sha256 == {}


def test_a_git_that_answers_with_an_error_is_a_refusal(repo):
    def failing(repo_, *args):
        return subprocess.CompletedProcess(args, 128, b"", b"fatal: not a git repository")

    got = guard(repo, git=failing)
    assert run_shadow.GIT_UNAVAILABLE in _problem_codes(got)
    assert ("git_unavailable", "git cannot name HEAD") in got.problems
    assert ("git_unavailable", "git cannot read the working tree's status") in got.problems


def test_an_integrity_refusal_comes_before_the_factory_is_imported(capsys):
    def dirty(repo_, *args):
        out = b" M plan.md\n" if args[0] == "status" else b"abc\n"
        return subprocess.CompletedProcess(args, 0, out, b"")

    sys.modules.pop(PROBE, None)
    lock = _Lock(True)
    code = run_shadow.main(_argv(f"{PROBE}:build"), registration=_registration(), git=dirty,
                           lock=lock)
    assert code == EXIT_STARTUP_REFUSED
    assert run_shadow.TREE_NOT_CLEAN in _codes(capsys.readouterr().err)
    assert PROBE not in sys.modules and lock.asked == 0


# -- 3, 4. the factory string and the factory ------------------------------------------------------


def test_a_factory_string_not_approved_by_run_harness_is_refused_before_import(capsys):
    sys.modules.pop(PROBE, None)
    code = run_shadow.main(_argv(f"{PROBE}:build"), registration=_registration(), git=_Git())
    assert code == EXIT_STARTUP_REFUSED
    assert _codes(capsys.readouterr().err) == [run_shadow.FACTORY_NOT_APPROVED]
    assert PROBE not in sys.modules


@pytest.mark.parametrize("factory", run_harness.APPROVED_ROLE_FACTORIES)
def test_both_scripted_factories_of_run_harness_are_refused_at_the_role_check(factory, capsys):
    lock = _Lock(True)
    code = run_shadow.main(_argv(factory), registration=_registration(), git=_Git(), lock=lock)
    codes = _codes(capsys.readouterr().err)
    assert code == EXIT_STARTUP_REFUSED and lock.asked == 0
    assert set(codes) == {run_shadow.ROLE_CLASS_NOT_APPROVED} and len(codes) == 4


# -- 5. the roles ----------------------------------------------------------------------------------


def _roles(**override):
    roles = compliant.build()
    for name, value in override.items():
        setattr(roles, name, value)
    return roles


def _with(role, cls):
    return {**APPROVED, role: (*APPROVED[role], cls)}


def test_the_compliant_scripted_roles_pass():
    assert run_shadow.role_problems(compliant.build(), APPROVED) == []


def test_a_class_that_is_not_listed_is_refused():
    got = run_shadow.role_problems(_roles(worker=H7Worker({})), APPROVED)
    assert got and {code for code, _ in got} == {run_shadow.ROLE_CLASS_NOT_APPROVED}


def test_a_subclass_of_a_listed_class_is_refused_because_the_check_is_by_exact_type():
    got = run_shadow.role_problems(_roles(worker=compliant.SubclassedWorker()), APPROVED)
    assert [code for code, _ in got] == [run_shadow.ROLE_CLASS_NOT_APPROVED]


@pytest.mark.parametrize("cls, method", [(compliant.OwnToProposalWorker, "_to_proposal"),
                                         (compliant.OwnBuildPromptWorker, "build_prompt"),
                                         (compliant.OwnRefuseWorker, "_refuse")])
def test_a_worker_that_overrides_a_boundary_method_is_refused(cls, method):
    got = run_shadow.role_problems(_roles(worker=cls()), _with("worker", cls))
    assert [code for code, _ in got] == [run_shadow.ROLE_BOUNDARY_OVERRIDDEN]
    assert method in got[0][1]


def test_a_supervisor_that_overrides_to_tasks_is_refused():
    cls = compliant.OwnToTasksSupervisor
    got = run_shadow.role_problems(_roles(supervisor=cls()), _with("supervisor", cls))
    assert [code for code, _ in got] == [run_shadow.ROLE_BOUNDARY_OVERRIDDEN]
    assert "_to_tasks" in got[0][1]


def test_a_reviewer_that_overrides_to_opinion_is_refused():
    cls = compliant.OwnToOpinionReviewer
    got = run_shadow.role_problems(_roles(reviewer=cls()), _with("reviewer", cls))
    assert [code for code, _ in got] == [run_shadow.ROLE_BOUNDARY_OVERRIDDEN]
    assert "_to_opinion" in got[0][1]


def test_the_honest_fake_reviewer_is_refused_even_when_listed():
    roles = _roles(reviewer=HonestFakeReviewer())
    assert [c for c, _ in run_shadow.role_problems(roles, APPROVED)] == [
        run_shadow.ROLE_CLASS_NOT_APPROVED]
    listed = _with("reviewer", HonestFakeReviewer)
    assert [c for c, _ in run_shadow.role_problems(roles, listed)] == [
        run_shadow.ROLE_NOT_A_BASE_SUBCLASS]


def test_a_role_refusal_comes_before_the_digests_and_the_harness(through, monkeypatch, capsys):
    reg = _registration(role_classes={**APPROVED, "worker": (compliant.SubclassedWorker,)})
    computed = []
    monkeypatch.setattr(run_shadow, "role_digests", lambda roles: computed.append(roles) or {})
    lock = _Lock(True)
    assert run_shadow.main(_argv(), registration=reg, git=_Git(), lock=lock) == EXIT_STARTUP_REFUSED
    assert _codes(capsys.readouterr().err) == [run_shadow.ROLE_CLASS_NOT_APPROVED]
    assert computed == [] and lock.asked == 0 and through == []


# -- 6. the digests, and the hand-over ------------------------------------------------------------


def test_a_digest_that_differs_is_a_refusal_and_the_harness_is_not_reached(through, capsys):
    digests = {**run_shadow.role_digests(compliant.build()), "reviewer": "0" * 64}
    lock = _Lock(False)
    code = run_shadow.main(_argv(), registration=_registration(digests=digests), git=_Git(),
                           lock=lock)
    err = capsys.readouterr().err
    assert code == EXIT_STARTUP_REFUSED
    assert _codes(err) == [run_shadow.DIGEST_MISMATCH] and "reviewer" in err
    assert lock.asked == 0 and through == []


def test_the_digests_cover_three_roles_and_record_the_supervisors_setting():
    got = run_shadow.role_digests(compliant.build())
    assert set(got) == {"worker", "supervisor", "reviewer", "supervisor_warn_about_duplicates"}
    assert all(len(got[role]) == 64 for role in run_shadow.ROLES)
    assert got["supervisor_warn_about_duplicates"] is False
    warned = compliant.build()
    warned.supervisor.warn_about_duplicates = True
    assert run_shadow.role_digests(warned)["supervisor"] != got["supervisor"]


def test_matching_digests_hand_the_checked_instances_to_run_harness_once(through, capsys,
                                                                          tmp_path):
    lock = _Lock(True)
    code = run_shadow.main(_argv(record=tmp_path / "run.jsonl"), registration=_registration(),
                           git=_Git(), lock=lock)
    err = capsys.readouterr().err
    assert code == EXIT_STARTUP_REFUSED and "stopped by the test after the hand-over" in err
    assert len(compliant.BUILT) == 1                      # the factory was called once, not twice
    assert len(through) == 1                              # run_harness got as far as its banner
    (built,), (facts,) = compliant.BUILT, through
    assert facts["worker"] is built.worker and facts["supervisor"] is built.supervisor
    assert facts["reviewer"] is built.reviewer
    assert lock.asked == 1 and lock.closed == 1
    assert not set(_codes(err)) & set(run_shadow.REASONS)          # no refusal of the runner's


# -- run_harness's roles= -------------------------------------------------------------------------


def test_run_harness_uses_the_roles_it_is_given_and_does_not_call_the_factory(through):
    given = compliant.build()
    code = run_harness.main(["run", *_harness_argv()], lock=_Lock(True),
                            register=lambda *a: None, roles=given)
    assert code == EXIT_STARTUP_REFUSED                   # the spy's stop
    assert compliant.BUILT == []
    assert through[0]["worker"] is given.worker


def test_roles_do_not_get_past_the_factory_string_gate(through, capsys):
    lock = _Lock(True)
    code = run_harness.main(["run", *_harness_argv(f"{PROBE}:build")], lock=lock,
                            register=lambda *a: None, roles=compliant.build())
    assert code == EXIT_STARTUP_REFUSED
    refusal = "refused: the role factory is not an approved one"
    assert capsys.readouterr().err.splitlines() == [refusal]
    assert lock.asked == 0


def test_without_roles_run_harness_still_calls_the_factory(through):
    code = run_harness.main(["run", *_harness_argv()], lock=_Lock(True),
                            register=lambda *a: None)
    assert code == EXIT_STARTUP_REFUSED and len(compliant.BUILT) == 1
    assert through[0]["worker"] is compliant.BUILT[0].worker


def test_a_held_lock_still_ends_the_run_with_2_after_the_hand_over(through, capsys, tmp_path):
    code = run_shadow.main(_argv(record=tmp_path / "run.jsonl"), registration=_registration(),
                           git=_Git(), lock=_Lock(False))
    assert code == EXIT_LOCK_HELD and len(compliant.BUILT) == 1 and through == []
    assert "holds the harness lock" in capsys.readouterr().err


# -- the sandbox (S2, plan item 140) ---------------------------------------------------------------


def test_a_sandbox_whose_class_is_not_listed_is_refused():
    roles = _roles(sandbox=object())
    assert [c for c, _ in run_shadow.role_problems(roles, APPROVED)] == [
        run_shadow.ROLE_CLASS_NOT_APPROVED]


def test_a_subclass_of_a_listed_sandbox_class_is_refused():
    roles = _roles(sandbox=compliant.SubclassedSandbox())
    got = run_shadow.role_problems(roles, APPROVED)
    assert [c for c, _ in got] == [run_shadow.ROLE_CLASS_NOT_APPROVED] and "sandbox" in got[0][1]


def test_an_empty_sandbox_key_is_not_registered(capsys):
    reg = _registration(role_classes={k: v for k, v in APPROVED.items() if k != "sandbox"})
    assert run_shadow.main(_argv(), registration=reg, git=_Git()) == EXIT_STARTUP_REFUSED
    err = capsys.readouterr().err
    assert _codes(err) == [run_shadow.NOT_REGISTERED] and "'sandbox'" in err


def test_a_sandbox_class_whose_module_is_not_registered_is_refused(capsys):
    reg = _registration(role_classes={**APPROVED, "sandbox": (HonestFakeReviewer,)})
    assert run_shadow.main(_argv(), registration=reg, git=_Git()) == EXIT_STARTUP_REFUSED
    assert _codes(capsys.readouterr().err) == [run_shadow.CLASS_MODULE_NOT_REGISTERED]
