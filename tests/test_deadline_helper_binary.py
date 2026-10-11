"""The deadline helper program itself, and what pins it (D65-A, ACCEPTANCE 5.77).

``tool_gateway/deadline/`` is a Rust program that runs as PID 1 of every tool container and ends the
container if a deadline passes. These tests run the *built* binary the sandbox mounts -- not a
rebuild, not a stand-in -- outside Docker first (fast, and every code path of the program), then
check the things that make its hash worth trusting: the committed pin file, the vendored source of
its one dependency, the toolchain pin, the build flags and the CI job that rebuilds it.

A helper that is not built is a failure, not a skip: ``tool_gateway/deadline/build.sh`` builds it
(CI's first job does, and hands the binary to the test job).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path

import pytest
import yaml

from tests.deadline_support import helper_under_test  # noqa: F401 - autouse, see the module
from tool_gateway import deadline_helper as dh

REPO = Path(__file__).resolve().parent.parent
DEADLINE = REPO / "tool_gateway" / "deadline"


pytestmark = pytest.mark.usefixtures("helper_under_test")


@pytest.fixture
def helper() -> str:
    path = dh.default_path()
    assert os.path.exists(path), (
        f"{path} is not built. Run tool_gateway/deadline/build.sh (CI builds it in its first job); "
        "a missing helper is a failure here, not a skip."
    )
    return dh.verify().path


def finish(proc, timeout, what):
    """Wait for ``proc``; a program that does not end is a failed assertion, not a stack trace."""
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        pytest.fail(f"{what}: still running after {timeout} s")


def run_helper(helper, seconds, *command, timeout=30, stdin=None):
    """Run the helper to completion. Output goes to files, not pipes, so that a grandchild which
    holds a descriptor open cannot make this wait for it."""
    started = time.monotonic()
    with tempfile.TemporaryFile("w+") as out, tempfile.TemporaryFile("w+") as err:
        proc = subprocess.Popen([helper, str(seconds), "--", *command], stdout=out, stderr=err,
                                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                text=True)
        if stdin is not None:
            proc.stdin.write(stdin)
            proc.stdin.close()
        code = finish(proc, timeout, "the helper")
        out.seek(0)
        err.seek(0)
        done = subprocess.CompletedProcess(proc.args, code, out.read(), err.read())
    return done, time.monotonic() - started


def sh(script: str) -> tuple[str, ...]:
    return ("/bin/sh", "-c", script)


def processes_with(marker: str) -> list[int]:
    """Host processes whose command line contains ``marker``."""
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
        except OSError:
            continue
        if marker in cmdline:
            found.append(int(entry.name))
    return found


# -- exit status -----------------------------------------------------------------------------

def test_a_command_that_ends_first_gives_its_own_exit_code(helper):
    done, took = run_helper(helper, 20, *sh("exit 3"))
    assert done.returncode == 3 and took < 5


@pytest.mark.parametrize("signum", [9, 15, 11])
def test_a_command_killed_by_a_signal_gives_128_plus_the_signal(helper, signum):
    done, _ = run_helper(helper, 20, *sh(f"kill -{signum} $$"))
    assert done.returncode == 128 + signum


def test_a_command_that_exits_124_on_its_own_is_just_124_with_no_helper_message(helper):
    """124 alone is not the deadline: the sandbox tells them apart by how long the container ran."""
    done, took = run_helper(helper, 20, *sh("exit 124"))
    assert done.returncode == 124 and took < 5
    assert "expired" not in done.stderr


def test_the_deadline_ends_the_run_with_124_and_says_so(helper):
    done, took = run_helper(helper, 1, "/bin/sleep", "60")
    assert done.returncode == 124
    assert 0.9 <= took < 4, took
    assert done.stderr.strip() == "cyberorch-deadline: expired after 1s"


def test_stdin_and_stdout_pass_through(helper):
    done, _ = run_helper(helper, 20, "/bin/cat", stdin="body\nof the request\n")
    assert done.returncode == 0 and done.stdout == "body\nof the request\n"


# -- usage (125) and exec failure (127) --------------------------------------------------------

@pytest.mark.parametrize("argv", [
    [],                                # nothing at all
    ["5"],                             # no separator, no command
    ["5", "/bin/true"],                # no separator
    ["5", "--"],                       # no command
    ["0", "--", "/bin/true"],          # below the range
    ["86401", "--", "/bin/true"],      # above the range
    ["-3", "--", "/bin/true"],
    ["soon", "--", "/bin/true"],
    ["1.5", "--", "/bin/true"],
    ["", "--", "/bin/true"],
])
def test_a_usage_error_is_125_and_runs_nothing(helper, argv):
    done = subprocess.run([helper, *argv], capture_output=True, text=True, timeout=10, check=False)
    assert done.returncode == 125, done.stderr
    assert "usage: cyberorch-deadline" in done.stderr


def test_a_command_that_cannot_be_executed_is_127_with_the_helpers_own_line(helper):
    done, took = run_helper(helper, 20, "/definitely/not/here")
    assert done.returncode == 127 and took < 5
    assert done.stderr.startswith(dh.NOT_EXECUTABLE_PREFIX + "/definitely/not/here: ")
    assert done.stderr.count("\n") == 1, "one line, and nothing of any tool before or after it"


def test_a_file_that_is_not_executable_is_127_too(helper, tmp_path):
    plain = tmp_path / "not-a-program"
    plain.write_text("#!/bin/sh\necho ran\n")
    plain.chmod(0o644)
    done, _ = run_helper(helper, 20, str(plain))
    assert done.returncode == 127 and "ran" not in done.stdout
    assert done.stderr.startswith(dh.NOT_EXECUTABLE_PREFIX)


# -- signals -----------------------------------------------------------------------------------

_HANDLER = (
    "import signal, sys, time\n"
    "def on(num, frame):\n"
    "    print('got', num, flush=True); sys.exit(9)\n"
    "for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT,\n"
    "          signal.SIGUSR1, signal.SIGUSR2):\n"
    "    signal.signal(s, on)\n"
    "print('ready', flush=True)\n"
    "time.sleep(60)\n"
)


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT,
                                    signal.SIGUSR1, signal.SIGUSR2])
def test_the_signals_docker_stop_and_friends_send_reach_the_command(helper, signum):
    """A signal sent to the helper reaches the tool, which handles it and chooses its code."""
    proc = subprocess.Popen([helper, "30", "--", sys.executable, "-u", "-c", _HANDLER],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert proc.stdout.readline().strip() == "ready"
        sent = time.monotonic()
        proc.send_signal(signum)
        finish(proc, 10, f"signal {int(signum)} was not delivered to the command")
        out, err = proc.stdout.read(), proc.stderr.read()
    finally:
        proc.kill()
    assert proc.returncode == 9, (proc.returncode, out, err)
    assert f"got {int(signum)}" in out
    assert time.monotonic() - sent < 3


def test_sigterm_to_a_command_that_ignores_it_does_not_end_the_run_early(helper):
    """Forwarding is forwarding: the helper does not turn a TERM into a kill on its own."""
    script = ("import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
              "print('ready', flush=True)\ntime.sleep(60)\n")
    proc = subprocess.Popen([helper, "3", "--", sys.executable, "-u", "-c", script],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert proc.stdout.readline().strip() == "ready"
        started = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        finish(proc, 15, "the deadline did not end the run")
    finally:
        proc.kill()
    assert proc.returncode == 124, "the deadline, not the TERM, ended it"
    assert time.monotonic() - started > 1.5


# -- the child ending early, the deadline killing the tree --------------------------------------

def test_a_child_that_ends_early_gives_its_exit_code_at_once_even_with_a_grandchild_running(helper):
    marker = f"cyberorch-early-{os.getpid()}-{time.time_ns()}"
    script = ("import subprocess, sys\n"
              "subprocess.Popen([sys.executable, '-c',\n"
              f"                  'import time; time.sleep(4)  # {marker}'],\n"
              "                 start_new_session=True)\n"
              "sys.exit(5)\n")
    started = time.monotonic()
    # no pipes: a grandchild that inherits one would hold it open and make *us* wait for it
    proc = subprocess.Popen([helper, "30", "--", sys.executable, "-c", script],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert proc.wait(timeout=20) == 5
    assert time.monotonic() - started < 2, "it waits for its child, not for the grandchild"
    # outside a container the helper is not PID 1, so the grandchild is left to end by itself
    deadline = time.monotonic() + 8
    while processes_with(marker) and time.monotonic() < deadline:
        time.sleep(0.2)


def test_the_deadline_kills_the_commands_whole_process_group(helper):
    marker = f"cyberorch-group-{os.getpid()}-{time.time_ns()}"
    # the subshells carry the script (and so the marker) in their command line
    script = f"(sleep 40; : {marker}) & (sleep 41; : {marker}) & wait"
    proc = subprocess.Popen([helper, "2", "--", *sh(script)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    alive_during = len(processes_with(marker))
    finish(proc, 15, "the deadline did not end the run")
    time.sleep(0.5)
    left = processes_with(marker)
    for pid in left:                       # whatever the assertion says, leave nothing behind
        os.kill(pid, signal.SIGKILL)
    assert alive_during >= 3, "positive control: the group was running"
    assert proc.returncode == 124
    assert left == [], "the deadline left part of the command's process group running"


# -- what pins it ------------------------------------------------------------------------------

def test_the_pin_file_has_a_valid_entry_for_each_architecture():
    text = (DEADLINE / "SHA256SUMS").read_text()
    entries = dict((name, digest) for digest, name in (line.split() for line in text.splitlines()))
    assert set(entries) == {"cyberorch-deadline-linux-x86_64", "cyberorch-deadline-linux-aarch64"}
    for name, digest in entries.items():
        assert re.fullmatch(r"[0-9a-f]{64}", digest), name
    assert len(set(entries.values())) == 2


def test_the_built_binary_for_this_machine_equals_the_pin(helper):
    assert hashlib.sha256(Path(helper).read_bytes()).hexdigest() == dh.pinned_sha256()


def test_the_vendored_libc_is_the_crate_cargo_lock_names_and_every_file_is_unchanged():
    lock = tomllib.loads((DEADLINE / "Cargo.lock").read_text())
    libc = next(p for p in lock["package"] if p["name"] == "libc")
    assert libc["source"].startswith("registry+")
    checksum = json.loads((DEADLINE / "vendor" / "libc" / ".cargo-checksum.json").read_text())
    assert checksum["package"] == libc["checksum"], "vendored source is not the locked crate"
    manifest = tomllib.loads((DEADLINE / "vendor" / "libc" / "Cargo.toml").read_text())
    assert manifest["package"]["version"] == libc["version"]
    assert checksum["files"], "an empty file list would verify nothing"
    for relative, digest in checksum["files"].items():
        actual = hashlib.sha256((DEADLINE / "vendor" / "libc" / relative).read_bytes()).hexdigest()
        assert actual == digest, f"vendor/libc/{relative} was modified"
    # the one dependency of the program is the one that is vendored
    names = {p["name"] for p in lock["package"]}
    assert names == {"cyberorch-deadline", "libc"}


def test_cargo_is_configured_offline_and_replaced_by_the_vendor_directory():
    config = tomllib.loads((DEADLINE / ".cargo" / "config.toml").read_text())
    assert config["source"]["crates-io"]["replace-with"] == "vendored-sources"
    assert config["source"]["vendored-sources"]["directory"] == "vendor"
    assert config["net"]["offline"] is True


def test_the_toolchain_pin_names_five_tarballs_with_valid_digests_and_one_version():
    lines = [ln for ln in (DEADLINE / "TOOLCHAIN.sha256").read_text().splitlines()
             if ln.strip() and not ln.startswith("#")]
    assert len(lines) == 5
    versions = set()
    for line in lines:
        digest, name = line.split()
        assert re.fullmatch(r"[0-9a-f]{64}", digest), line
        match = re.fullmatch(r"(rustc|cargo|rust-std)-(\d+\.\d+\.\d+)-[a-z0-9_-]+\.tar\.xz", name)
        assert match, name
        versions.add(match.group(2))
    assert len(versions) == 1
    channel = tomllib.loads((DEADLINE / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    assert versions == {channel}, "rust-toolchain.toml and TOOLCHAIN.sha256 name two compilers"


def test_the_build_is_locked_offline_and_uses_the_pinned_toolchain_only():
    build = (DEADLINE / "build.sh").read_text()
    assert "--locked" in build and "--offline" in build
    assert 'toolchain.sh' in build
    assert "rustup" not in "\n".join(
        ln for ln in build.splitlines() if not ln.lstrip().startswith("#"))
    assert re.search(r'^export PATH="\$prefix/bin:', build, re.M), (
        "the compiler must come from the pinned prefix, ahead of anything on the host")
    assert "--remap-path-prefix" in build
    assert "linker=rust-lld" in build or "_LINKER=rust-lld" in build
    # a changed pin is a commit, never something the build script does: it only reads SHA256SUMS
    assert not re.search(r">\s*\"?\$here/SHA256SUMS", build)


def test_the_toolchain_script_verifies_each_tarball_before_unpacking_it():
    script = (DEADLINE / "toolchain.sh").read_text()
    verify = script.index("sha256sum")
    unpack = script.index("tar -xJf")
    install = script.index("install.sh")
    assert verify < unpack < install
    assert 'exit 1' in script[verify:unpack]
    code = "\n".join(ln for ln in script.splitlines() if not ln.lstrip().startswith("#"))
    assert "rustup" not in code and "latest" not in code


def test_toolchain_script_refuses_a_tarball_that_is_not_the_pinned_one(tmp_path):
    """Served from a local directory (the one place the script accepts a file:// base): garbage
    where the compiler should be. Nothing is installed and the script says which digest it saw."""
    dist = tmp_path / "dist"
    dist.mkdir()
    pins = [ln.split() for ln in (DEADLINE / "TOOLCHAIN.sha256").read_text().splitlines()
            if ln.strip() and not ln.startswith("#")]
    for _, name in pins:
        (dist / name).write_bytes(b"this is not a compiler\n")
    home = tmp_path / "home"
    env = {**os.environ, "CYBERORCH_RUST_HOME": str(home),
           "CYBERORCH_RUST_DIST": str(tmp_path / "cache"),
           "CYBERORCH_RUST_DIST_URL": dist.as_uri()}
    done = subprocess.run([str(DEADLINE / "toolchain.sh")], env=env, capture_output=True,
                          text=True, timeout=60, check=False)
    assert done.returncode == 1, done.stdout + done.stderr
    assert "Nothing was installed" in done.stderr
    assert f"expected {pins[0][0]}" in done.stderr
    assert not (home / "prefix" / "bin" / "rustc").exists()


def test_ci_builds_the_helper_in_its_own_job_and_compares_it_with_the_pin():
    workflow = yaml.safe_load((REPO / ".github" / "workflows" / "test.yml").read_text())
    jobs = workflow["jobs"]
    assert "deadline-helper" in jobs
    build_steps = " ".join(s.get("run", "") for s in jobs["deadline-helper"]["steps"])
    assert "tool_gateway/deadline/build.sh --check" in build_steps
    # the test job runs against that job's binary and only after it passed
    assert jobs["test"]["needs"] == "deadline-helper"
    text = (REPO / ".github" / "workflows" / "test.yml").read_text()
    assert "download-artifact" in text and "chmod 0755 tool_gateway/deadline/bin/" in text
    # the workflow never writes the expected value
    assert not re.search(r">\s*\S*SHA256SUMS", text)
