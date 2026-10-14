"""The five switches for irreversible actions (completion 3, item 4; ACCEPTANCE 5.92).

Each is off; the command line is the only way on; a person at a terminal confirms; ``network`` and
``file`` are refused in this version; what was enabled is written to ``reconciler.started``. Each
from both sides, and the ones that matter most with a real subprocess and a real terminal:

* validation -- exact names only, nothing implied, the two unavailable categories refused;
* the gate -- with one category on, exactly its kinds reach the act half, the other four do not;
* the command line -- refusals come *before* the configuration is read (exit 7, nothing opened),
  a pipe cannot confirm, a wrong phrase does not, the right phrase at a pseudo-terminal does;
* the record -- ``reconciler.started`` carries the sorted list, ``[]`` when there is none;
* nothing else turns one on -- no environment variable, no configuration key.
"""

from __future__ import annotations

import ast
import importlib.util
import io
import json
import os
import pty
import select
import subprocess
import sys
import time
from pathlib import Path

import pytest
from sqlalchemy import text

from control_plane.reconciler import act, config, emit, flags, vocab
from control_plane.reconciler.act import Mode, Settings
from control_plane.reconciler.model import Action
from control_plane.reconciler.outcome import SKIPPED_OFF
from control_plane.state.db import global_auditor_scope
from tests.test_reconciler_config import VALID

REPO = Path(__file__).resolve().parents[1]
SCRIPT = str(REPO / "scripts" / "run_reconciler.py")
EXIT_REFUSED = 7

_spec = importlib.util.spec_from_file_location("run_reconciler_under_test", SCRIPT)
runner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runner)                 # (the script does nothing until main() is called)


# ---------------------------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------------------------

def test_the_five_categories_cover_every_irreversible_kind_exactly_once():
    assert flags.CATEGORIES == ("kill", "container", "proxy", "network", "file")
    covered = [kind for kinds in flags.KINDS.values() for kind in kinds]
    assert sorted(covered) == sorted(vocab.DOCKER_ACTIONS + (vocab.UNLINK_FILE,))
    assert len(covered) == len(set(covered))
    assert set(flags.CATEGORY_OF) == set(covered)
    assert set(runner.EFFECT) == set(flags.CATEGORIES)


def test_nothing_is_enabled_by_default_and_an_operator_with_no_words_enables_nothing():
    assert Settings(Mode.STATE_ONLY).enabled == frozenset()
    assert Settings(Mode.DRY_RUN).enabled == frozenset()
    for name in act.MODE_NAMES:
        assert act.settings_for(name).enabled == frozenset()
        assert act.settings_for(name, []).enabled == frozenset()


@pytest.mark.parametrize("category", flags.OPERATOR_MAY_ENABLE)
def test_the_first_three_can_be_named(category, tmp_path):
    vault = tmp_path / "evidence"
    vault.mkdir(mode=0o700)
    assert flags.validate([category]) == frozenset({category})
    assert act.settings_for("state-only", [category], str(vault)).enabled == frozenset({category})


def test_all_three_together_and_naming_one_twice():
    assert flags.validate(["proxy", "kill", "container", "kill"]) == frozenset(
        {"kill", "container", "proxy"})


@pytest.mark.parametrize("category", ["network", "file"])
def test_network_and_file_are_refused_whatever_else_is_asked(category):
    with pytest.raises(flags.FlagRefused, match="cannot be enabled in this version"):
        flags.validate([category])
    with pytest.raises(flags.FlagRefused):
        flags.validate(["kill", category])               # one bad word refuses the lot
    with pytest.raises(flags.FlagRefused):
        act.settings_for("state-only", ["kill", category])


@pytest.mark.parametrize("word", [
    "all", "ALL", "Kill", "KILL", "kill,container", "kill container", "", " ", "*", "delete",
    "deletions", "containers", "kill ", " kill", "kill\n", "proxies", "force", "yes", "1", "true"])
def test_any_word_that_is_not_exactly_a_category_is_refused(word):
    with pytest.raises(flags.FlagRefused, match="not a category"):
        flags.validate([word])


def test_a_dry_run_changes_nothing_so_it_cannot_carry_a_switch():
    with pytest.raises(ValueError):
        Settings(Mode.DRY_RUN, enabled=frozenset({"kill"}))
    with pytest.raises(ValueError):
        act.settings_for("dry-run", ["kill"])


def test_settings_refuses_a_word_that_is_not_a_category_even_from_the_tests():
    with pytest.raises(ValueError):
        Settings(Mode.STATE_ONLY, enabled=frozenset({"everything"}))
    Settings(Mode.STATE_ONLY, enabled=flags.EVERYTHING)       # the act half's tests use all five


# ---------------------------------------------------------------------------------------------
# the gate
# ---------------------------------------------------------------------------------------------

#: one action per kind that cannot do anything if it gets through (a name that is not a full id, a
#: file name that is not ours): whatever it reaches answers "invalid", never "skipped_deletions_off"
ONE_OF_EACH = {
    vocab.KILL_CONTAINER: Action(vocab.KILL_CONTAINER, vocab.OVERRAN_DEADLINE, "short"),
    vocab.REMOVE_CONTAINER: Action(vocab.REMOVE_CONTAINER, vocab.RUN_FINISHED, "short"),
    vocab.REMOVE_PROXY: Action(vocab.REMOVE_PROXY, vocab.OWNER_RUN_ENDED, "short"),
    vocab.REMOVE_NETWORK: Action(vocab.REMOVE_NETWORK, vocab.IDLE_SWEEP, "short",
                                 name="cyberorch-allow-x"),
    vocab.UNLINK_FILE: Action(vocab.UNLINK_FILE, "credential_mount", "not-ours", name="not-ours",
                              directory="/nonexistent-directory-for-tests"),
}


class Tripwire:
    """A Docker client that records that it was asked anything."""

    def __init__(self):
        self.touched = []

    def __getattr__(self, name):
        self.touched.append(name)
        raise AssertionError(f"the Docker client was used: {name}")


def carried(settings, kind, th):
    client = Tripwire()
    (result,) = act.carry_out([ONE_OF_EACH[kind]], settings, th=th, client=client,
                              directory="/nonexistent-directory-for-tests", expected_uid=0)
    return result, client


#: written out here, apart from the module's own table, so that a table that is wrong is caught
WHICH_KIND = {
    "kill": (vocab.KILL_CONTAINER,), "container": (vocab.REMOVE_CONTAINER,),
    "proxy": (vocab.REMOVE_PROXY,), "network": (vocab.REMOVE_NETWORK,),
    "file": (vocab.UNLINK_FILE,),
}


def test_each_category_covers_the_kind_its_name_says():
    assert flags.KINDS == WHICH_KIND


@pytest.mark.parametrize("category", flags.CATEGORIES)
def test_with_one_category_on_exactly_its_kinds_reach_the_act_half(category):
    th = config.load(VALID)
    settings = Settings(Mode.STATE_ONLY, enabled=frozenset({category}))
    for kind in ONE_OF_EACH:
        result, client = carried(settings, kind, th)
        if kind in WHICH_KIND[category]:
            assert result.outcome != SKIPPED_OFF, (category, kind, result)
        else:
            assert result.outcome == SKIPPED_OFF, (category, kind, result)
            assert client.touched == [], "a category that is off must not touch Docker"


def test_with_none_on_every_irreversible_kind_is_skipped_and_docker_is_never_touched():
    th = config.load(VALID)
    for kind in ONE_OF_EACH:
        result, client = carried(Settings(Mode.STATE_ONLY), kind, th)
        assert result.outcome == SKIPPED_OFF and client.touched == []


def test_proposal_transitions_do_not_depend_on_any_switch():
    transitions = [k for k in vocab.ACTION_KINDS if k in vocab.PROPOSAL_ACTIONS]
    assert transitions and not set(transitions) & set(flags.CATEGORY_OF)


# ---------------------------------------------------------------------------------------------
# confirm: a person at a terminal
# ---------------------------------------------------------------------------------------------

class Stream(io.StringIO):
    def __init__(self, text="", *, terminal):
        super().__init__(text)
        self._terminal = terminal

    def isatty(self):
        return self._terminal


def test_the_phrase_is_enable_and_the_sorted_categories():
    assert flags.phrase({"proxy", "kill"}) == "enable kill proxy"
    assert flags.phrase(["container"]) == "enable container"


def test_the_right_phrase_at_a_terminal_confirms():
    out = Stream(terminal=True)
    assert runner.confirm({"kill", "container"}, stdin=Stream("enable container kill\n",
                                                             terminal=True), stdout=out)
    shown = out.getvalue()
    assert "enable container kill" in shown and "KILL" in shown
    assert "REMOVE a tool container" in shown
    assert "egress proxy" not in shown                   # not asked for, so not shown


@pytest.mark.parametrize("typed", [
    "", "\n", "yes\n", "y\n", "enable kill\n", "enable kill container\n", "ENABLE container kill\n",
    "enable  container kill\n", " enable container kill\n", "enable container kill \n",
    "enable all\n"])
def test_any_other_answer_does_not_confirm(typed):
    assert not runner.confirm({"kill", "container"}, stdin=Stream(typed, terminal=True),
                             stdout=Stream(terminal=True))


def test_a_pipe_cannot_confirm_even_with_the_right_phrase():
    out = Stream(terminal=True)
    assert not runner.confirm({"kill"}, stdin=Stream("enable kill\n", terminal=False), stdout=out)
    assert "not one" in out.getvalue() and "no --yes" in out.getvalue()
    # nor can a terminal whose output goes to a file (a script that only reads from a tty)
    assert not runner.confirm({"kill"}, stdin=Stream("enable kill\n", terminal=True),
                             stdout=Stream(terminal=False))


def test_nothing_to_confirm_is_nothing_asked():
    assert runner.confirm(set(), stdin=Stream(terminal=False), stdout=Stream(terminal=False))


def test_a_stream_that_cannot_say_whether_it_is_a_terminal_is_not_one():
    class Opaque:
        def readline(self):
            return "enable kill\n"

        def write(self, _):
            pass

        def flush(self):
            pass

    assert not runner.confirm({"kill"}, stdin=Opaque(), stdout=Opaque())


# ---------------------------------------------------------------------------------------------
# the command line, as a real process
# ---------------------------------------------------------------------------------------------

def cli(*args, env=None, stdin=subprocess.DEVNULL):
    base = {k: v for k, v in os.environ.items() if not k.startswith("RECONCILER_")
            or k == "RECONCILER_READER_DATABASE_URL"}
    return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True,
                          env={**base, **(env or {})}, cwd=str(REPO), timeout=120, stdin=stdin)


def started_events() -> list[dict]:
    with global_auditor_scope() as conn:
        return [dict(r) for r in conn.execute(text(
            "SELECT audit_id, payload FROM audit_log WHERE scope = 'global' "
            "AND event_type = :t ORDER BY audit_id"), {"t": emit.STARTED}).mappings()]


def on_a_terminal(args, typed, env):
    """Run the command line with a pseudo-terminal for stdin and stdout; type ``typed`` when it
    asks. Returns (exit status, everything the terminal showed)."""
    pid, fd = pty.fork()
    if pid == 0:                                          # the child: becomes the command line
        os.chdir(str(REPO))
        base = {k: v for k, v in os.environ.items() if not k.startswith("RECONCILER_")
                or k == "RECONCILER_READER_DATABASE_URL"}
        os.execve(sys.executable, [sys.executable, SCRIPT, *args], {**base, **env})
    shown = b""
    sent = False
    deadline = time.monotonic() + 90
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
                os.write(fd, typed.encode())
                sent = True
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), shown.decode(errors="replace")


@pytest.mark.parametrize("args", [
    ["--mode", "state-only", "--enable", "network"],
    ["--mode", "state-only", "--enable", "file"],
    ["--mode", "state-only", "--enable", "kill", "--enable", "file"],
    ["--mode", "state-only", "--enable", "all"],
    ["--mode", "state-only", "--enable", "Kill"],
    ["--mode", "state-only", "--enable", "kill,container"],
    ["--mode", "state-only", "--enable", ""],
    ["--mode", "dry-run", "--enable", "kill"],
])
def test_a_refused_word_is_exit_7_before_the_configuration_is_even_read(args):
    """No ``RECONCILER_*`` setting and no database URL is given: had the configuration been read
    first the answer would be exit 8. Nothing is printed to stdout, nothing is opened."""
    done = cli(*args, "--once", env={"RECONCILER_READER_DATABASE_URL": "postgresql://nowhere/x"})
    assert done.returncode == EXIT_REFUSED, (done.returncode, done.stderr)
    assert done.stdout == ""
    assert done.stderr.startswith("refused: ")


@pytest.mark.parametrize("how", ["absent", "missing", "open"])
def test_container_without_a_private_evidence_directory_is_exit_7_before_anything(
        engagement_id, tmp_path, how):
    """Nothing is asked of the person, nothing is read, nothing started (ACCEPTANCE 5.97)."""
    before = len(started_events())
    args = ["--mode", "state-only", "--once", "--engagement", engagement_id,
            "--enable", "container"]
    if how == "missing":
        args += ["--evidence-dir", str(tmp_path / "nowhere")]
    if how == "open":
        (tmp_path / "open").mkdir()
        os.chmod(tmp_path / "open", 0o755)
        args += ["--evidence-dir", str(tmp_path / "open")]
    done = cli(*args, env={"RECONCILER_READER_DATABASE_URL": "postgresql://nowhere/x"})
    assert done.returncode == EXIT_REFUSED, (done.returncode, done.stderr)
    assert done.stdout == "" and "evidence-dir" in done.stderr
    assert len(started_events()) == before


def test_a_pipe_is_refused_exit_7_and_nothing_is_started(engagement_id):
    before = len(started_events())
    done = cli("--mode", "state-only", "--once", "--engagement", engagement_id,
               "--enable", "kill", env=VALID, stdin=subprocess.PIPE)
    assert done.returncode == EXIT_REFUSED, done.stderr
    assert "not one" in done.stdout + done.stderr
    assert len(started_events()) == before


def test_a_wrong_phrase_at_a_terminal_is_exit_7_and_nothing_is_started(engagement_id):
    before = len(started_events())
    status, shown = on_a_terminal(
        ["--mode", "state-only", "--once", "--engagement", engagement_id,
         "--enable", "kill", "--enable", "proxy"], "yes\n", VALID)
    assert status == EXIT_REFUSED, shown
    assert "enable kill proxy" in shown
    assert len(started_events()) == before


def test_the_right_phrase_at_a_terminal_starts_and_the_record_says_what_was_enabled(
        engagement_id, tmp_path):
    before = max((e["audit_id"] for e in started_events()), default=0)
    vault = tmp_path / "evidence"
    vault.mkdir(mode=0o700)
    status, shown = on_a_terminal(
        ["--mode", "state-only", "--once", "--engagement", engagement_id,
         "--directory", str(tmp_path), "--evidence-dir", str(vault), "--enable", "proxy",
         "--enable", "kill", "--enable", "container"], "enable container kill proxy\n", VALID)
    assert status == 0, shown
    assert "reconciler stopped (exit 0)" in shown or '"summary"' in shown
    new = [e for e in started_events() if e["audit_id"] > before]
    assert [e["payload"]["enabled"] for e in new] == [["container", "kill", "proxy"]]
    assert new[0]["payload"]["mode"] == "state_only"


def test_a_run_with_no_switch_needs_no_terminal_and_records_an_empty_list(engagement_id, tmp_path):
    before = max((e["audit_id"] for e in started_events()), default=0)
    done = cli("--mode", "state-only", "--once", "--engagement", engagement_id,
               "--directory", str(tmp_path), env=VALID)
    assert done.returncode == 0, done.stderr
    new = [e for e in started_events() if e["audit_id"] > before]
    assert [e["payload"]["enabled"] for e in new] == [[]]


def test_a_dry_run_records_nothing_and_so_has_nothing_to_enable(engagement_id, tmp_path):
    before = len(started_events())
    done = cli("--mode", "dry-run", "--once", "--engagement", engagement_id,
               "--directory", str(tmp_path), env=VALID)
    assert done.returncode == 0
    assert len(started_events()) == before


# ---------------------------------------------------------------------------------------------
# the record
# ---------------------------------------------------------------------------------------------

def test_the_started_event_accepts_a_sorted_list_of_known_categories_and_nothing_else():
    ok = {"instance_id": "RECON-x", "mode": "state_only", "planned": {}, "enabled": ["kill"]}
    assert emit.validate(emit.STARTED, ok)["enabled"] == ["kill"]
    for bad in (["Kill"], ["kill", "kill"], ["proxy", "kill"], ["everything"], "kill", None,
                [1], ["kill", None]):
        with pytest.raises(emit.PayloadRejected):
            emit.validate(emit.STARTED, {**ok, "enabled": bad})
    with pytest.raises(emit.PayloadRejected):                    # not optional
        emit.validate(emit.STARTED, {k: v for k, v in ok.items() if k != "enabled"})


# ---------------------------------------------------------------------------------------------
# nothing else turns one on
# ---------------------------------------------------------------------------------------------

def test_no_configuration_key_and_no_environment_variable_names_a_switch():
    for key in config.KEYS:
        assert not any(word in key for word in ("ENABLE", "ALLOW", "DELET", "KILL_FLAG", "FORCE"))
    source = (REPO / "scripts" / "run_reconciler.py").read_text()
    reads = [n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Attribute)
             and n.attr in {"environ", "getenv"}]
    assert len(reads) == 1, "the command line reads the environment in one place: the thresholds"


def test_the_environment_cannot_turn_one_on(engagement_id, tmp_path):
    """Every spelling of a switch in the environment, with the right values for the rest: the run
    needs no terminal, so nothing was enabled."""
    before = max((e["audit_id"] for e in started_events()), default=0)
    env = {**VALID, "RECONCILER_ENABLE": "kill", "RECONCILER_ENABLE_KILL": "1",
           "RECONCILER_ALLOW_DELETIONS": "1", "CYBERORCH_ENABLE": "kill,container,proxy"}
    done = cli("--mode", "state-only", "--once", "--engagement", engagement_id,
               "--directory", str(tmp_path), env=env)
    assert done.returncode == 0, done.stderr
    new = [e for e in started_events() if e["audit_id"] > before]
    assert [e["payload"]["enabled"] for e in new] == [[]]


def test_exactly_one_place_in_the_product_builds_settings_from_words():
    """``enabled=`` is passed by name in one function of one file (``act.settings_for``), and its
    value there is what ``flags.validate`` returned."""
    found = []
    for top in ("control_plane", "scripts", "agents", "tool_gateway"):
        for path in (REPO / top).rglob("*.py"):
            if path.name.startswith("mutations_"):
                continue
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.keyword) and node.arg == "enabled":
                    found.append((str(path.relative_to(REPO)), ast.unparse(node.value)))
    assert found == [("control_plane/reconciler/act.py", "chosen")], found
    source = (REPO / "control_plane" / "reconciler" / "act.py").read_text()
    assert "chosen = flags.validate(" in source


def test_the_two_unavailable_categories_have_no_other_door():
    assert set(flags.OPERATOR_MAY_ENABLE) == {"kill", "container", "proxy"}
    assert not {"network", "file"} & set(flags.OPERATOR_MAY_ENABLE)
    tree = ast.parse((REPO / "scripts" / "run_reconciler.py").read_text())
    (call,) = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
               and isinstance(n.func, ast.Attribute) and n.func.attr == "add_argument"
               and n.args and ast.unparse(n.args[0]) == "'--enable'"]
    assert "choices" not in {k.arg for k in call.keywords}, (
        "argparse's own error (exit 2, the lock's) must not stand in for the refusal (exit 7)")


def test_the_started_payload_is_what_the_service_writes(engagement_id, tmp_path):
    from control_plane.reconciler.lock import SingletonLock
    from control_plane.reconciler.service import Reconciler
    from tests.test_reconciler_service import TH, FakeDocker
    r = Reconciler(settings=Settings(Mode.STATE_ONLY, enabled=frozenset({"proxy", "kill"})),
                   th=TH, client=FakeDocker(), directory=str(tmp_path), expected_uid=os.getuid(),
                   only_engagements=frozenset({engagement_id}), lock=SingletonLock(),
                   watchdog_interval=0.2)
    before = max((e["audit_id"] for e in started_events()), default=0)
    try:
        r.begin()
    finally:
        r.finish("signal")
    new = [e for e in started_events() if e["audit_id"] > before]
    assert [e["payload"]["enabled"] for e in new] == [["kill", "proxy"]]
    assert json.loads(json.dumps(new[0]["payload"]))["instance_id"] == r.instance_id

