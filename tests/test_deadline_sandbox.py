"""The sandbox side of the in-container deadline (D65-A, ACCEPTANCE 5.77).

``DockerSandbox.run`` wraps every tool container's command in ``cyberorch-deadline`` (the
program in ``tool_gateway/deadline/``), mounts it read-only, verifies its sha256 before *every*
run, and maps what comes back: the helper's exit 124 -- when Docker's own timestamps agree the
container ran as long as the deadline -- becomes ``timed_out`` (so ``FAILED``), the helper's
"cannot execute" becomes a ``NotStarted``, and a helper that is missing or altered stops the run
before any container exists.

Three layers, each answering something the others cannot:

* fake-client tests pin the exact arguments given to Docker and the arithmetic of the mapping,
  including its boundaries;
* real-Docker tests run the built helper as PID 1 in ``python:3.12-slim`` (an image CI pulls) and
  watch what the kernel and Docker report, never what the helper says about itself;
* structure tests keep ``run`` the only place a tool container is created.
"""

from __future__ import annotations

import ast
import os
import shutil
import signal
import subprocess
import sys
import textwrap
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.deadline_support import helper_under_test  # noqa: F401 - autouse, see the module
from tool_gateway import deadline_helper as dh
from tool_gateway import sandbox as sandbox_module
from tool_gateway.sandbox import (
    DEADLINE_LABEL,
    ContainerStartRefused,
    DeadlineHelperUnavailable,
    DockerSandbox,
    NotStarted,
    ToolNotExecutable,
)

REPO = Path(__file__).resolve().parent.parent
ALLOW = ["10.243.14.0/29"]
PY_IMAGE = "python:3.12-slim"


def box(image: str = PY_IMAGE) -> DockerSandbox:
    return DockerSandbox(image=image)


def run(sb, command, *, budget=30, run_id=None, **kw):
    return sb.run(command=command, network_allowlist=ALLOW, max_duration_seconds=budget,
                  no_network=True, run_id=run_id or f"RUN-DL-{uuid.uuid4().hex[:8]}",
                  engagement_id="ENG-DEADLINE", **kw)


def ran(sb, command, **kw):
    """``run`` for a test that expects a *result*: a refusal is a failed assertion, not a trace."""
    try:
        return run(sb, command, **kw)
    except NotStarted as exc:
        pytest.fail(f"the run was refused ({exc.reason}) where a result was expected")


def py(script: str) -> list[str]:
    return ["python3", "-u", "-c", textwrap.dedent(script)]


def containers_for(run_id: str):
    import docker
    return docker.from_env().containers.list(
        all=True, filters={"label": f"cyberorch.run_id={run_id}"})


pytestmark = pytest.mark.usefixtures("helper_under_test")


# ====================================================================================
# 1. what is given to Docker -- a fake client records it
# ====================================================================================

class FakeContainer:
    def __init__(self, *, exit_code=0, ran_seconds=0.2, stderr=b"", stdout=b"", entrypoint=None):
        started = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        self.id = self.short_id = "fakecontainer"
        self.status = "exited"
        self.labels = {}
        self._exit, self._stderr, self._stdout = exit_code, stderr, stdout
        self.attrs = {"State": {
            "StartedAt": started.strftime("%Y-%m-%dT%H:%M:%S.123456789Z"),
            "FinishedAt": (started + timedelta(seconds=ran_seconds)).strftime(
                "%Y-%m-%dT%H:%M:%S.123456789Z"),
        }}
        self.removed = False

    def start(self):
        pass

    def reload(self):
        pass

    def kill(self):
        pass

    def wait(self, timeout=None):
        return {"StatusCode": self._exit}

    def logs(self, stdout=True, stderr=True):
        return self._stdout if stdout and not stderr else self._stderr

    def remove(self, force=False):
        self.removed = True


class FakeClient:
    def __init__(self, container: FakeContainer, entrypoint=None):
        self.container, self.entrypoint, self.created = container, entrypoint, []
        outer = self

        class Images:
            def get(self, name):
                class Image:
                    attrs = {"Config": {"Entrypoint": outer.entrypoint}}
                return Image()

        class Containers:
            def create(self, **kwargs):
                outer.created.append(kwargs)
                return outer.container

        self.images, self.containers = Images(), Containers()


def fake_run(container=None, *, entrypoint=None, budget=30, **kw):
    container = container or FakeContainer()
    client = FakeClient(container, entrypoint)
    sb = box("fake/image:none")
    sb._client = client
    result = run(sb, ["tool", "--flag"], budget=budget, **kw)
    return result, client


def test_the_helper_is_the_entrypoint_and_the_tools_command_follows_it():
    _, client = fake_run(budget=30)
    kwargs = client.created[0]
    assert kwargs.get("entrypoint") == [dh.CONTAINER_PATH, "40", "--"]
    assert kwargs["command"] == ["tool", "--flag"]


def test_an_images_own_entrypoint_is_kept_and_wrapped_not_replaced():
    """Semgrep's and the browser's images set one; the tool still runs exactly as before."""
    _, client = fake_run(entrypoint=["/usr/local/bin/semgrep"], budget=30)
    assert client.created[0].get("entrypoint") == [dh.CONTAINER_PATH, "40", "--",
                                                   "/usr/local/bin/semgrep"]
    assert client.created[0]["command"] == ["tool", "--flag"]


def test_the_helper_is_mounted_read_only_and_the_container_is_labelled_with_its_deadline():
    _, client = fake_run(budget=17)
    kwargs = client.created[0]
    assert kwargs["volumes"].get(dh.default_path()) == {"bind": dh.CONTAINER_PATH, "mode": "ro"}
    assert kwargs["labels"].get(DEADLINE_LABEL) == "27" == str(dh.deadline_for(17))
    assert kwargs["cap_drop"] == ["ALL"] and kwargs["read_only"] is True


def test_opting_out_is_explicit_and_the_label_says_none():
    _, client = fake_run(deadline_helper=None, entrypoint=["/x"])
    kwargs = client.created[0]
    assert not kwargs.get("entrypoint")
    assert kwargs["command"] == ["tool", "--flag"]
    assert dh.default_path() not in kwargs["volumes"]
    assert kwargs["labels"].get(DEADLINE_LABEL) == "none"


def test_a_mount_that_would_cover_the_helpers_path_is_refused_before_anything_is_created():
    client = FakeClient(FakeContainer())
    sb = box("fake/image:none")
    sb._client = client
    with pytest.raises(DeadlineHelperUnavailable) as caught:
        run(sb, ["tool"], source_mounts={"/tmp": dh.CONTAINER_PATH})
    assert caught.value.reason == "deadline_helper_path_in_use"
    assert client.created == []


# -- the mapping of exit 124 ------------------------------------------------------------------

@pytest.mark.parametrize("ran, expect_timeout", [
    (0.2, False),       # a tool that exits 124 straight away
    (37.9, False),      # just under D - 2 for a budget of 30 (D = 40)
    (38.0, True),       # exactly D - 2
    (40.3, True),       # the helper's own deadline
    (200.0, True),
])
def test_exit_124_is_the_deadline_only_if_the_container_ran_as_long_as_the_deadline(
        ran, expect_timeout):
    result, _ = fake_run(FakeContainer(exit_code=124, ran_seconds=ran,
                                       stderr=b"cyberorch-deadline: expired after 40s\n"),
                         budget=30)
    assert result.timed_out is expect_timeout
    assert result.exit_code == (-1 if expect_timeout else 124)
    assert result.succeeded is False


def test_the_discriminator_follows_the_budget_not_a_fixed_number():
    result, _ = fake_run(FakeContainer(exit_code=124, ran_seconds=12.0), budget=3)    # D = 13
    assert result.timed_out is True
    result, _ = fake_run(FakeContainer(exit_code=124, ran_seconds=12.0), budget=30)   # D = 40
    assert result.timed_out is False


def test_a_container_whose_timestamps_cannot_be_read_is_not_called_timed_out():
    container = FakeContainer(exit_code=124, ran_seconds=40)
    container.attrs["State"]["FinishedAt"] = "0001-01-01T00:00:00Z"
    result, _ = fake_run(container, budget=30)
    assert result.timed_out is False and result.exit_code == 124


@pytest.mark.parametrize("code", [0, 1, 3, 125, 126, 137])
def test_every_other_exit_code_is_passed_through_untouched(code):
    result, _ = fake_run(FakeContainer(exit_code=code, ran_seconds=45), budget=30)
    assert result.exit_code == code and result.timed_out is False


def test_with_the_helper_opted_out_exit_124_means_nothing_special():
    result, _ = fake_run(FakeContainer(exit_code=124, ran_seconds=500), deadline_helper=None)
    assert result.exit_code == 124 and result.timed_out is False


# -- the mapping of 127 -----------------------------------------------------------------------

def test_the_helpers_cannot_execute_line_is_a_not_started():
    stderr = (dh.NOT_EXECUTABLE_PREFIX + "/nope: No such file or directory (os error 2)\n").encode()
    container = FakeContainer(exit_code=127, stderr=stderr)
    with pytest.raises(ToolNotExecutable) as caught:
        fake_run(container)
    assert isinstance(caught.value, ContainerStartRefused) and isinstance(caught.value, NotStarted)
    assert caught.value.reason == "tool_command_not_executable"
    assert container.removed, "the container is torn down like any other"


@pytest.mark.parametrize("stderr", [
    b"",                                                               # a tool that exits 127
    b"sh: 1: foo: not found\n",                                        # a shell's own 127
    (dh.NOT_EXECUTABLE_PREFIX + "x: gone\nand then the tool wrote more\n").encode(),
    b"the tool wrote first\n" + (dh.NOT_EXECUTABLE_PREFIX + "x: gone\n").encode(),
])
def test_a_127_that_is_not_only_the_helpers_line_is_the_tools_own_result(stderr):
    try:
        result, _ = fake_run(FakeContainer(exit_code=127, stderr=stderr))
    except NotStarted as exc:
        pytest.fail(f"taken for the helper's refusal ({exc.reason})")
    assert result.exit_code == 127 and result.timed_out is False


def test_the_not_started_for_a_missing_command_needs_the_helper_to_have_wrapped_the_run():
    stderr = (dh.NOT_EXECUTABLE_PREFIX + "/nope: gone\n").encode()
    result, _ = fake_run(FakeContainer(exit_code=127, stderr=stderr), deadline_helper=None)
    assert result.exit_code == 127


# ====================================================================================
# 2. the check before every run
# ====================================================================================

def copied_helper(tmp_path, mode=0o755) -> Path:
    target = tmp_path / "bin" / Path(dh.default_path()).name
    target.parent.mkdir(exist_ok=True)
    shutil.copy(dh.default_path(), target)
    target.chmod(mode)
    return target


def refused(sb, path, run_id):
    with pytest.raises(DeadlineHelperUnavailable) as caught:
        run(sb, py("print('should never run')"), run_id=run_id, deadline_helper=str(path))
    assert isinstance(caught.value, NotStarted)
    assert containers_for(run_id) == [], "a refusal must come before any container exists"
    return caught.value


def test_a_correct_copy_is_accepted_and_verified_again_on_every_run(tmp_path):
    sb = box()
    path = copied_helper(tmp_path)
    assert run(sb, py("print('first')"), deadline_helper=str(path)).stdout.strip() == "first"
    assert run(sb, py("print('second')"), deadline_helper=str(path)).stdout.strip() == "second"
    # replaced between two runs by the same process: the second is refused, the first was not
    path.write_bytes(path.read_bytes() + b"\0")
    error = refused(sb, path, "RUN-DL-REPLACED")
    assert error.reason == "deadline_helper_hash_mismatch"


def test_a_missing_file_stops_the_run_before_a_container_exists(tmp_path):
    error = refused(box(), tmp_path / "nowhere", "RUN-DL-MISSING")
    assert error.reason == "deadline_helper_missing"


def test_an_unreadable_path_stops_the_run(tmp_path):
    """A directory where the file should be: unreadable even to root."""
    error = refused(box(), tmp_path, "RUN-DL-DIR")
    assert error.reason == "deadline_helper_unreadable"


def test_the_right_bytes_without_an_execute_bit_for_everyone_stop_the_run(tmp_path):
    error = refused(box(), copied_helper(tmp_path, mode=0o700), "RUN-DL-NOX")
    assert error.reason == "deadline_helper_not_executable"


def test_a_binary_for_another_architecture_has_no_pin_and_stops_the_run(tmp_path, monkeypatch):
    path = copied_helper(tmp_path)
    monkeypatch.setattr(dh.platform, "machine", lambda: "riscv64")
    error = refused(box(), path, "RUN-DL-ARCH")
    assert error.reason == "deadline_helper_unsupported_architecture"


def test_a_pin_file_without_an_entry_stops_the_run(tmp_path, monkeypatch):
    sums = tmp_path / "SHA256SUMS"
    sums.write_text("")
    path = copied_helper(tmp_path)
    monkeypatch.setattr(dh, "SHA256SUMS", sums)
    error = refused(box(), path, "RUN-DL-UNPINNED")
    assert error.reason == "deadline_helper_unpinned"


def test_a_helper_that_is_not_the_pinned_one_is_refused_even_if_it_works(tmp_path):
    """A one-byte-different copy of a working program: it would run, and is refused anyway."""
    path = copied_helper(tmp_path)
    data = bytearray(path.read_bytes())
    data[-1] ^= 0x01
    path.write_bytes(bytes(data))
    assert refused(box(), path, "RUN-DL-TAMPERED").reason == "deadline_helper_hash_mismatch"


def test_every_refusal_carries_a_stable_reason_code_dispatch_can_record():
    codes = {"deadline_helper_missing", "deadline_helper_unreadable",
             "deadline_helper_hash_mismatch",
             "deadline_helper_not_executable", "deadline_helper_unpinned",
             "deadline_helper_unsupported_architecture", "deadline_helper_path_in_use"}
    source = Path(sandbox_module.__file__).read_text() + Path(dh.__file__).read_text()
    for code in codes:
        assert f'"{code}"' in source, code


# ====================================================================================
# 3. real Docker, the built helper as PID 1
# ====================================================================================

def test_pid_1_of_a_tool_container_is_the_helper_with_the_budget_plus_slack():
    out = run(box(), py("print(open('/proc/1/cmdline','rb').read().split(b'\\0'))"), budget=30)
    assert out.exit_code == 0
    argv = ast.literal_eval(out.stdout.strip())
    assert argv[:3] == [dh.CONTAINER_PATH.encode(), b"40", b"--"]
    assert argv[3] == b"python3"


def test_the_container_is_labelled_with_its_deadline_while_it_runs():
    import docker
    run_id = f"RUN-DL-{uuid.uuid4().hex[:8]}"
    done = {}
    thread = threading.Thread(target=lambda: done.update(
        r=run(box(), py("import time; time.sleep(30)"), budget=20, run_id=run_id)))
    thread.start()
    try:
        deadline = time.monotonic() + 20
        found = []
        while not found and time.monotonic() < deadline:
            found = [c for c in containers_for(run_id) if c.status == "running"]
            time.sleep(0.2)
        assert found and found[0].labels.get(DEADLINE_LABEL) == "30"
    finally:
        for c in containers_for(run_id):
            c.kill()
        thread.join(timeout=30)
        docker.from_env().close()


def test_with_the_helper_opted_out_pid_1_is_the_tool_and_the_label_says_none():
    out = run(box(), py("print(open('/proc/1/cmdline','rb').read().split(b'\\0')[0])"),
              deadline_helper=None)
    assert out.stdout.strip() == "b'python3'"


def test_the_exit_code_the_tool_chose_is_the_containers():
    sb = box()
    assert run(sb, ["sh", "-c", "exit 3"]).exit_code == 3
    assert run(sb, ["sh", "-c", "kill -9 $$"]).exit_code == 137
    assert run(sb, ["sh", "-c", "exit 0"]).succeeded


def test_stdin_reaches_the_tool_through_the_helper():
    out = run(box(), py("import sys; sys.stdout.write(sys.stdin.read().upper())"),
              stdin="body of the request\n")
    assert out.stdout == "BODY OF THE REQUEST\n"


def test_a_tool_that_exits_124_on_its_own_is_a_failed_run_not_a_timeout():
    started = time.monotonic()
    out = run(box(), ["sh", "-c", "exit 124"], budget=30)
    assert out.exit_code == 124 and out.timed_out is False
    assert time.monotonic() - started < 15
    assert out.succeeded is False


def test_a_run_that_overruns_its_budget_is_cut_by_the_control_plane_first():
    """The normal path: the helper's deadline (budget + 10 s) is never reached."""
    started = time.monotonic()
    out = run(box(), ["sleep", "120"], budget=4)
    took = time.monotonic() - started
    assert out.timed_out is True and out.exit_code == -1
    assert 3.5 <= out.duration_seconds < 9 and took < 20
    assert "expired" not in out.stderr, "the helper did not have to act"


def test_when_the_helper_fires_first_the_run_is_a_timeout_just_the_same(monkeypatch):
    """Control plane alive but not acting: the helper's deadline (budget - 3 s here) ends it, the
    container exits 124 having run that long by Docker's own clock, and that is a timeout."""
    monkeypatch.setattr(dh, "SLACK_SECONDS", -3)
    out = run(box(), ["sleep", "120"], budget=6)
    assert out.timed_out is True and out.exit_code == -1
    assert 2.5 <= out.duration_seconds < 5.5, out.duration_seconds
    assert "cyberorch-deadline: expired after 3s" in out.stderr


def test_the_tools_stdout_is_not_disturbed_by_the_helpers_stderr_line(monkeypatch):
    monkeypatch.setattr(dh, "SLACK_SECONDS", -3)
    out = run(box(), py("print('partial result', flush=True); import time; time.sleep(60)"),
              budget=6)
    assert out.stdout == "partial result\n"
    assert out.stderr.strip().endswith("expired after 3s")


def test_a_command_that_does_not_exist_is_a_not_started_and_leaves_no_container():
    run_id = f"RUN-DL-{uuid.uuid4().hex[:8]}"
    with pytest.raises(ToolNotExecutable) as caught:
        run(box(), ["/definitely/not/here", "--version"], run_id=run_id)
    assert isinstance(caught.value, NotStarted)
    assert containers_for(run_id) == []


def test_a_tool_that_simply_exits_127_is_a_result_not_a_refusal():
    out = ran(box(), ["sh", "-c", "exit 127"])
    assert out.exit_code == 127


def test_docker_stop_reaches_the_tool_through_the_helper_in_well_under_the_grace_period():
    import docker
    run_id = f"RUN-DL-{uuid.uuid4().hex[:8]}"
    got = {}
    script = """
        import signal, sys, time
        def on(num, frame):
            print('terminated', flush=True); sys.exit(7)
        signal.signal(signal.SIGTERM, on)
        print('ready', flush=True)
        time.sleep(100)
    """
    thread = threading.Thread(target=lambda: got.update(r=run(box(), py(script), run_id=run_id)))
    thread.start()
    try:
        client = docker.from_env()
        end = time.monotonic() + 30
        target = None
        while target is None and time.monotonic() < end:
            for c in containers_for(run_id):
                if c.status == "running" and "ready" in c.logs().decode():
                    target = c
            time.sleep(0.2)
        assert target is not None
        asked = time.monotonic()
        target.stop(timeout=10)
        stopped_in = time.monotonic() - asked
        thread.join(timeout=30)
        client.close()
    finally:
        for c in containers_for(run_id):
            c.kill()
    assert stopped_in < 4, f"stop waited {stopped_in:.1f}s: TERM was not forwarded"
    assert got["r"].exit_code == 7 and "terminated" in got["r"].stdout


def test_orphans_that_end_after_their_parent_are_reaped_not_left_as_zombies():
    script = """
        import os, time
        for _ in range(3):
            pid = os.fork()
            if pid == 0:
                if os.fork() == 0:          # grandchild: outlives its parent, ends 0.3 s later
                    time.sleep(0.3); os._exit(0)
                os._exit(0)                 # parent: ends at once, orphaning the grandchild
            os.waitpid(pid, 0)              # the tool reaps its own child; PID 1 gets the orphan
        time.sleep(1.5)
        states = []
        for pid in filter(str.isdigit, os.listdir('/proc')):
            try:
                states.append(open(f'/proc/{pid}/stat').read().rsplit(')', 1)[1].split()[0])
            except OSError:
                pass
        print('zombies', states.count('Z'), 'processes', len(states))
    """
    out = run(box(), py(script))
    assert out.stdout.split()[:2] == ["zombies", "0"], out.stdout


def test_a_tool_that_ends_leaving_a_process_behind_ends_the_container_at_once():
    started = time.monotonic()
    out = run(box(), ["sh", "-c", "(sleep 600 &) ; exit 5"], budget=60)
    assert out.exit_code == 5
    assert time.monotonic() - started < 10, "the container waited for the orphan it was left"


def test_a_setsid_grandchild_that_ignores_term_does_not_survive_the_deadline(monkeypatch):
    marker = f"cyberorch-survivor-{uuid.uuid4().hex}"
    script = f"""
        import os, signal, subprocess, time
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        subprocess.Popen(['sleep', '300', '{marker}'], start_new_session=True)
        print('started', flush=True)
        time.sleep(300)
    """
    monkeypatch.setattr(dh, "SLACK_SECONDS", -2)
    out = run(box(), py(script), budget=5)
    assert out.timed_out is True
    time.sleep(1.0)
    survivors = subprocess.run(["pgrep", "-f", marker], capture_output=True, text=True).stdout
    assert survivors.strip() == ""


# -- the control plane dying ---------------------------------------------------------------------

_KILLED_PARENT = """
import sys
sys.path.insert(0, {repo!r})
from tool_gateway import deadline_helper as dh
from tool_gateway.sandbox import DockerSandbox
dh.SLACK_SECONDS = -2          # budget 9, so the helper's deadline is 7 s
DockerSandbox(image="python:3.12-slim").run(
    command=["python3", "-c", "import signal, subprocess, time\\n"
             "signal.signal(signal.SIGTERM, signal.SIG_IGN)\\n"
             "subprocess.Popen(['sleep', '4000', {marker!r}], start_new_session=True)\\n"
             "time.sleep(4000)"],
    network_allowlist=["10.243.14.0/29"], max_duration_seconds=9, no_network=True,
    run_id={run_id!r}, engagement_id="ENG-DEADLINE")
"""


def _ran_seconds(state) -> float:
    def parse(text):
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    return (parse(state["FinishedAt"]) - parse(state["StartedAt"])).total_seconds()


def test_a_container_outlives_a_killed_control_plane_only_until_its_deadline():
    """The point of the helper. The process that called ``run`` is ``kill -9``'d two seconds in; the
    container -- a tool that ignores TERM and a ``setsid`` grandchild -- is found ``exited`` with
    124 at its deadline, by Docker's own timestamps, and nothing of it is left on the host."""
    run_id = f"RUN-DL-KILL-{uuid.uuid4().hex[:8]}"
    marker = f"cyberorch-orphan-{uuid.uuid4().hex}"
    code = _KILLED_PARENT.format(repo=str(REPO), run_id=run_id, marker=marker)
    parent = subprocess.Popen([sys.executable, "-c", code])
    found = None
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not any(
                c.status == "running" for c in containers_for(run_id)):
            time.sleep(0.1)
        time.sleep(1.5)
        assert subprocess.run(["pgrep", "-f", marker], capture_output=True).returncode == 0, (
            "positive control: the grandchild was running")
        os.kill(parent.pid, signal.SIGKILL)
        parent.wait(timeout=10)
        end = time.monotonic() + 30
        while time.monotonic() < end:
            cs = containers_for(run_id)
            if cs and cs[0].status == "exited":
                found = cs[0]
                break
            time.sleep(0.25)
        assert found is not None, "the container was still running 30 s after its parent died"
        found.reload()
        state = found.attrs["State"]
        assert state["ExitCode"] == 124
        assert 6.0 <= _ran_seconds(state) < 8.5, _ran_seconds(state)
        assert subprocess.run(["pgrep", "-f", marker], capture_output=True).returncode == 1
    finally:
        if parent.poll() is None:
            parent.kill()
        for c in containers_for(run_id):
            c.remove(force=True)
        subprocess.run(["pkill", "-f", marker], check=False)


# -- images and mounts -----------------------------------------------------------------------------

def test_an_image_that_sets_an_entrypoint_runs_unchanged_under_the_helper():
    """Semgrep's image has ENTRYPOINT [semgrep]; the adapter's command is semgrep's arguments."""
    from tool_gateway.adapters import semgrep
    out = ran(box("cyberorch/semgrep:local"),
              ["--version", "--metrics=off", "--disable-version-check"], tmpfs=semgrep.TMPFS,
              budget=60)
    assert out.exit_code == 0 and out.stdout.strip()[:1].isdigit(), (out.stdout, out.stderr)


def _mount_noexec(directory: Path) -> None:
    command = ["mount", "-t", "tmpfs", "-o", "noexec,size=4m", "tmpfs", str(directory)]
    if os.geteuid() != 0:
        command = ["sudo", "-n", *command]
    subprocess.run(command, check=True, capture_output=True)


def _umount(directory: Path) -> None:
    command = ["umount", str(directory)]
    if os.geteuid() != 0:
        command = ["sudo", "-n", *command]
    subprocess.run(command, check=False, capture_output=True)


def test_a_helper_on_a_noexec_filesystem_is_a_start_refusal_that_ran_nothing(tmp_path):
    """Docker refuses to start the container; the sandbox types that as ``ContainerStartRefused``
    (a ``NotStarted``), so the run is recorded as never having run. Needs the right to mount."""
    mountpoint = tmp_path / "noexec"
    mountpoint.mkdir()
    _mount_noexec(mountpoint)
    try:
        path = mountpoint / Path(dh.default_path()).name
        shutil.copy(dh.default_path(), path)
        path.chmod(0o755)
        assert dh.verify(str(path)).sha256 == dh.pinned_sha256(), "the bytes are the pinned ones"
        run_id = f"RUN-DL-{uuid.uuid4().hex[:8]}"
        with pytest.raises(ContainerStartRefused) as caught:
            run(box(), py("print('ran')"), run_id=run_id, deadline_helper=str(path))
        assert isinstance(caught.value, NotStarted)
        assert [c for c in containers_for(run_id)] == [], "torn down like any refused run"
    finally:
        _umount(mountpoint)


# ====================================================================================
# 4. structure
# ====================================================================================

def _sandbox_ast():
    return ast.parse(Path(sandbox_module.__file__).read_text())


def _create_calls():
    tree = _sandbox_ast()
    found = []
    for function in ast.walk(tree):
        if isinstance(function, ast.FunctionDef):
            for node in ast.walk(function):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "create"
                        and isinstance(node.func.value, ast.Attribute)
                        and node.func.value.attr == "containers"):
                    found.append((function.name, node))
    return found


def test_a_tool_container_is_created_in_exactly_one_place_and_it_sets_the_entrypoint():
    calls = {}
    for function, node in _create_calls():
        calls.setdefault(function, []).append(node)
    assert set(calls) == {"start_egress_proxy", "run"}, (
        "a new place that creates containers must either wrap its command in the helper or be "
        "added to this test with the reason it need not")
    (run_call,) = calls["run"]
    keywords = {k.arg for k in run_call.keywords}
    assert {"entrypoint", "command", "labels", "volumes"} <= keywords
    labels = next(k.value for k in run_call.keywords if k.arg == "labels")
    assert any(isinstance(n, ast.Name) and n.id == "DEADLINE_LABEL" for n in ast.walk(labels))


def test_run_has_no_default_that_turns_the_deadline_off():
    tree = _sandbox_ast()
    function = next(f for f in ast.walk(tree) if isinstance(f, ast.FunctionDef) and f.name == "run")
    names = [a.arg for a in function.args.kwonlyargs]
    defaults = function.args.kw_defaults
    default = defaults[names.index("deadline_helper")]
    assert not (isinstance(default, ast.Constant) and default.value is None), (
        "opting out must be spelled out by the caller, never the default")


def test_every_caller_inside_the_repository_that_opts_out_is_listed_here():
    """Today there is none in production code: lab scripts and tests that want a bare container
    pass ``deadline_helper=None`` and appear here by name."""
    found = []
    sources = [*(REPO / "control_plane").rglob("*.py"), *(REPO / "tool_gateway").rglob("*.py")]
    for path in sources:
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call) and any(
                    k.arg == "deadline_helper" and isinstance(k.value, ast.Constant)
                    and k.value.value is None for k in node.keywords):
                found.append(f"{path.relative_to(REPO)}:{node.lineno}")
    assert found == [], found
