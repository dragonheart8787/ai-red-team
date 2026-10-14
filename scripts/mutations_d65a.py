# ruff: noqa: E501  -- the edits quote source lines verbatim; they must match exactly
"""The mutations of D65-A (ACCEPTANCE 5.77), as runnable checks (see ``mutation_check.py``).

``python scripts/mutations_d65a.py --list`` names them. ``D65A-R*`` change the helper's Rust
source: the mutated program is built with the pinned toolchain into a scratch directory
(``tool_gateway/deadline/build.sh`` with ``CYBERORCH_DEADLINE_OUT``) and the tests are pointed at it
(``tests/deadline_support.py``); a mutation that does not build is INVALID, like a Python edit that
does not compile. ``D65A-P*`` change ``tool_gateway/sandbox.py`` or ``deadline_helper.py``.
"""

from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mutation_check import Edit, Mutation, main  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RS = "tool_gateway/deadline/src/main.rs"
SANDBOX = "tool_gateway/sandbox.py"
HELPER_PY = "tool_gateway/deadline_helper.py"
BINARY = ("tests/test_deadline_helper_binary.py",)
SANDBOX_TESTS = ("tests/test_deadline_sandbox.py",)
ZOMBIES = ("tests/test_deadline_sandbox.py::test_orphans_that_end_after_their_parent_are_reaped_not_left_as_zombies",)
FAKE = ("tests/test_deadline_sandbox.py",)

_scratch: list[str] = []
atexit.register(lambda: [shutil.rmtree(p, ignore_errors=True) for p in _scratch])


def build_mutated_helper() -> dict[str, str]:
    """Build the edited ``main.rs`` into a scratch directory; point the tests at the result."""
    out = tempfile.mkdtemp(prefix="d65a-mutant-")
    _scratch.append(out)
    done = subprocess.run(
        [str(ROOT / "tool_gateway/deadline/build.sh"), "x86_64"], capture_output=True, text=True,
        env={**os.environ, "CYBERORCH_DEADLINE_OUT": out})
    if done.returncode != 0:
        raise RuntimeError(done.stderr[-300:] or done.stdout[-300:])
    return {"CYBERORCH_DEADLINE_UNDER_TEST": f"{out}/bin/cyberorch-deadline-linux-x86_64"}


def rust(mid: str, summary: str, old: str, new: str, tests, targets, **kw) -> Mutation:
    return Mutation(mid, summary, tests, edits=(Edit(RS, old, new),), targets=targets,
                    prepare=build_mutated_helper, **kw)


CATALOGUE = [
    # ---- the program (Rust)
    rust("D65A-R1", "signals sent to the helper are no longer forwarded to the command",
         "        unsafe {\n            libc::kill(pid, signal);\n        }\n",
         "        let _ = signal;\n",
         BINARY, ("test_the_signals_docker_stop_and_friends_send_reach_the_command",)),
    rust("D65A-R2", "the deadline kills the command only, not its process group",
         "        libc::kill(-pid, libc::SIGKILL);\n", "        libc::kill(pid, libc::SIGKILL);\n",
         BINARY, ("test_the_deadline_kills_the_commands_whole_process_group",)),
    rust("D65A-R3", "the command is not given its own process group",
         "            libc::setpgid(0, 0);\n", "",
         BINARY, ("test_the_deadline_kills_the_commands_whole_process_group",)),
    rust("D65A-R4", "the deadline exits 125 instead of 124",
         "const EXIT_DEADLINE: i32 = 124;", "const EXIT_DEADLINE: i32 = 125;",
         BINARY, ("test_the_deadline_ends_the_run_with_124_and_says_so",)),
    rust("D65A-R5", "a command killed by a signal gives N, not 128 + N",
         "        128 + libc::WTERMSIG(status)\n", "        libc::WTERMSIG(status)\n",
         BINARY, ("test_a_command_killed_by_a_signal_gives_128_plus_the_signal",)),
    rust("D65A-R6", "a command that cannot be executed exits 126, not 127",
         "const EXIT_NOT_EXECUTABLE: i32 = 127;", "const EXIT_NOT_EXECUTABLE: i32 = 126;",
         BINARY, ("test_a_command_that_cannot_be_executed_is_127_with_the_helpers_own_line",)),
    rust("D65A-R7", "the helper does not leave when its command ends (it waits for the deadline)",
         "                if reaped == pid {\n                    exit(exit_code_of(status));\n                }\n",
         "                if reaped == pid {\n                    let _ = status;\n                }\n",
         BINARY, ("test_a_command_that_ends_first_gives_its_own_exit_code",)),
    rust("D65A-R8", "a deadline of 0 seconds is accepted",
         "(1..=MAX_SECONDS)", "(0..=MAX_SECONDS)",
         BINARY, ("test_a_usage_error_is_125_and_runs_nothing",)),
    rust("D65A-R9", "orphans re-parented to the helper are no longer reaped (waits for its child only)",
         "libc::waitpid(-1, &mut status, libc::WNOHANG)", "libc::waitpid(pid, &mut status, libc::WNOHANG)",
         ZOMBIES, ("test_orphans_that_end_after_their_parent_are_reaped_not_left_as_zombies",)),
    rust("D65A-R10", "the deadline no longer says it expired",
         '    eprintln!("cyberorch-deadline: expired after {seconds}s");\n', "",
         BINARY, ("test_the_deadline_ends_the_run_with_124_and_says_so",)),
    rust("D65A-R11", "the \"cannot execute\" line changes its wording",
         '"cyberorch-deadline: cannot execute {}: {error}"', '"cyberorch-deadline: failed to run {}: {error}"',
         BINARY, ("test_a_command_that_cannot_be_executed_is_127_with_the_helpers_own_line",)),
    # ---- the sandbox and the pin check (Python)
    Mutation("D65A-P1", "the helper's sha256 is read but not compared", SANDBOX_TESTS,
             edits=(Edit(HELPER_PY, "    if digest != expected:\n", "    if False:\n"),),
             targets=("test_a_helper_that_is_not_the_pinned_one_is_refused_even_if_it_works",
                      "test_a_correct_copy_is_accepted_and_verified_again_on_every_run")),
    Mutation("D65A-P2", "the check happens once per path, not before every run", SANDBOX_TESTS,
             edits=(Edit(SANDBOX, "_REPOSITORY_HELPER: Any = object()\n",
                         "_REPOSITORY_HELPER: Any = object()\n_CHECKED: dict = {}\n"),
                    Edit(SANDBOX, "            return dh.verify(None if requested is _REPOSITORY_HELPER else requested)\n",
                         "            key = repr(requested)\n            if key not in _CHECKED:\n"
                         "                _CHECKED[key] = dh.verify(None if requested is _REPOSITORY_HELPER else requested)\n"
                         "            return _CHECKED[key]\n")),
             targets=("test_a_correct_copy_is_accepted_and_verified_again_on_every_run",)),
    Mutation("D65A-P3", "a helper that fails its check is skipped and the run goes ahead without one", SANDBOX_TESTS,
             edits=(Edit(SANDBOX, "            raise DeadlineHelperUnavailable(str(exc), exc.reason) from exc\n",
                         "            return None\n"),),
             targets=("test_a_missing_file_stops_the_run_before_a_container_exists",
                      "test_a_helper_that_is_not_the_pinned_one_is_refused_even_if_it_works")),
    Mutation("D65A-P4", "every exit 124 is taken to be the deadline", SANDBOX_TESTS,
             edits=(Edit(SANDBOX, "    return ran >= deadline_seconds - dh.TOLERANCE_SECONDS\n", "    return True\n"),),
             targets=("test_exit_124_is_the_deadline_only_if_the_container_ran_as_long_as_the_deadline",
                      "test_a_tool_that_exits_124_on_its_own_is_a_failed_run_not_a_timeout")),
    Mutation("D65A-P5", "the exit-124 test is strict at the boundary (> instead of >=)", SANDBOX_TESTS,
             edits=(Edit(SANDBOX, "    return ran >= deadline_seconds - dh.TOLERANCE_SECONDS\n",
                         "    return ran > deadline_seconds - dh.TOLERANCE_SECONDS\n"),),
             targets=("test_exit_124_is_the_deadline_only_if_the_container_ran_as_long_as_the_deadline",)),
    Mutation("D65A-P6", "the tolerance is ten seconds instead of two", SANDBOX_TESTS,
             edits=(Edit(SANDBOX, "    return ran >= deadline_seconds - dh.TOLERANCE_SECONDS\n",
                         "    return ran >= deadline_seconds - 10\n"),),
             targets=("test_exit_124_is_the_deadline_only_if_the_container_ran_as_long_as_the_deadline",)),
    Mutation("D65A-P7", "an image's own entrypoint is dropped from the wrapped command", SANDBOX_TESTS,
             edits=(Edit(SANDBOX, '[dh.CONTAINER_PATH, str(deadline), "--", *image_entrypoint]',
                         '[dh.CONTAINER_PATH, str(deadline), "--"]'),),
             targets=("test_an_images_own_entrypoint_is_kept_and_wrapped_not_replaced",
                      "test_an_image_that_sets_an_entrypoint_runs_unchanged_under_the_helper")),
    Mutation("D65A-P8", "any exit 127 is taken for the helper's refusal", SANDBOX_TESTS,
             edits=(Edit(SANDBOX, "if exit_code == dh.EXIT_NOT_EXECUTABLE and _is_only_the_helpers_refusal(stderr):",
                         "if exit_code == dh.EXIT_NOT_EXECUTABLE:"),),
             targets=("test_a_127_that_is_not_only_the_helpers_line_is_the_tools_own_result",
                      "test_a_tool_that_simply_exits_127_is_a_result_not_a_refusal")),
    Mutation("D65A-P9", "the container is not labelled with its deadline", SANDBOX_TESTS,
             edits=(Edit(SANDBOX, '                            DEADLINE_LABEL: "none" if deadline is None else str(deadline)},\n',
                         "                            },\n"),),
             targets=("test_the_helper_is_mounted_read_only_and_the_container_is_labelled_with_its_deadline",
                      "test_a_tool_container_is_created_in_exactly_one_place_and_it_sets_the_entrypoint")),
    Mutation("D65A-P10", "no slack: the helper's deadline equals the budget", SANDBOX_TESTS,
             edits=(Edit(HELPER_PY, "SLACK_SECONDS = 10\n", "SLACK_SECONDS = 0\n"),),
             targets=("test_the_helper_is_the_entrypoint_and_the_tools_command_follows_it",
                      "test_pid_1_of_a_tool_container_is_the_helper_with_the_budget_plus_slack")),
    Mutation("D65A-P11", "the deadline helper is off unless a caller turns it on", SANDBOX_TESTS,
             edits=(Edit(SANDBOX, "        deadline_helper: Any = _REPOSITORY_HELPER,\n",
                         "        deadline_helper: Any = None,\n"),),
             targets=("test_run_has_no_default_that_turns_the_deadline_off",
                      "test_the_helper_is_the_entrypoint_and_the_tools_command_follows_it")),
    Mutation("D65A-P12", "the helper is mounted read-write", SANDBOX_TESTS,
             edits=(Edit(SANDBOX, 'volumes[helper.path] = {"bind": dh.CONTAINER_PATH, "mode": "ro"}',
                         'volumes[helper.path] = {"bind": dh.CONTAINER_PATH, "mode": "rw"}'),),
             targets=("test_the_helper_is_mounted_read_only_and_the_container_is_labelled_with_its_deadline",)),
    Mutation("D65A-P13", "a mount that covers the helper's path is not noticed", SANDBOX_TESTS,
             edits=(Edit(SANDBOX, "        if dh.CONTAINER_PATH in taken:\n", "        if False:\n"),),
             targets=("test_a_mount_that_would_cover_the_helpers_path_is_refused_before_anything_is_created",)),
    Mutation("D65A-P14", "a helper without the execute bit for everyone is accepted", SANDBOX_TESTS,
             edits=(Edit(HELPER_PY, "    if not mode & stat.S_IXOTH:\n", "    if False:\n"),),
             targets=("test_the_right_bytes_without_an_execute_bit_for_everyone_stop_the_run",)),
    Mutation("D65A-P15", "a deadline exit leaves exit_code at 124 instead of -1", SANDBOX_TESTS,
             edits=(Edit(SANDBOX, "                    timed_out, exit_code = True, -1\n",
                         "                    timed_out = True\n"),),
             targets=("test_exit_124_is_the_deadline_only_if_the_container_ran_as_long_as_the_deadline",)),
    Mutation("D65A-P16", "the helper is no longer the entrypoint (the command is not wrapped)", SANDBOX_TESTS,
             edits=(Edit(SANDBOX, "                    entrypoint=(None if helper is None else\n"
                         "                                [dh.CONTAINER_PATH, str(deadline), \"--\", *image_entrypoint]),\n", ""),),
             targets=("test_the_helper_is_the_entrypoint_and_the_tools_command_follows_it",
                      "test_pid_1_of_a_tool_container_is_the_helper_with_the_budget_plus_slack",
                      "test_a_tool_container_is_created_in_exactly_one_place_and_it_sets_the_entrypoint")),
    # ---- the image guard (tests/test_image_literals.py): a build's base image is not "on the runner"
    Mutation("D65A-G1", "a build's BASE image is counted as present on the runner again",
             ("tests/test_image_literals.py",),
             edits=(Edit("tests/test_image_literals.py",
                         '            value = _script_default(IMAGES / script_name, "IMAGE")\n            if value:\n                have.add(value)\n',
                         '            for variable in ("IMAGE", "BASE"):\n                value = _script_default(IMAGES / script_name, variable)\n                if value:\n                    have.add(value)\n'),),
             targets=("test_an_image_a_build_pulls_is_not_counted_as_on_the_runner",)),
    Mutation("D65A-G2", "the workflow's explicit pull of python:3.12-slim is removed",
             ("tests/test_image_literals.py",),
             edits=(Edit(".github/workflows/test.yml", "        run: docker pull python:3.12-slim\n", "        run: 'true'\n"),),
             targets=("test_every_image_a_test_names_is_one_ci_builds_or_pulls",)),
    Mutation("D65A-G3", "a Dockerfile base nobody listed (a new FROM)",
             ("tests/test_image_literals.py",),
             edits=(Edit("tool_gateway/images/browser.Dockerfile", "ARG BASE=ubuntu:24.04\n", "ARG BASE=ubuntu:25.04\n"),),
             targets=("test_every_base_image_a_dockerfile_names_is_known",)),
    # ---- a run that timed out vs one that never started (tests/test_timeout_vs_not_started.py)
    Mutation("D65A-T1", "a timed-out run's audit record loses its reason",
             ("tests/test_timeout_vs_not_started.py",),
             edits=(Edit("control_plane/orchestrator/dispatch.py",
                         "                reasons=(TIMED_OUT,) if result.timed_out else (),\n", ""),),
             targets=("test_a_timed_out_run_is_failed_with_its_output_and_its_own_code",)),
    Mutation("D65A-T2", "the outcome of a timed-out run carries no failure",
             ("tests/test_timeout_vs_not_started.py",),
             edits=(Edit("control_plane/orchestrator/dispatch.py",
                         "                           reason=TIMED_OUT if result.timed_out else None)\n",
                         "                           reason=None)\n"),),
             targets=("test_a_timed_out_run_is_failed_with_its_output_and_its_own_code",)),
    Mutation("D65A-T3", "a resumed call no longer reports the timeout",
             ("tests/test_timeout_vs_not_started.py",),
             edits=(Edit("control_plane/api/function_api.py",
                         '    elif stage == stages.RECORDED and detail == "failed" and run_row and _run_timed_out(',
                         '    elif False and stage == stages.RECORDED and detail == "failed" and run_row and _run_timed_out('),),
             targets=("test_a_timed_out_run_asked_again_is_told_the_same_way_and_nothing_runs",)),
    Mutation("D65A-T4", "the timeout code collides with the not-started code",
             ("tests/test_timeout_vs_not_started.py",),
             edits=(Edit("control_plane/orchestrator/dispatch.py",
                         'TIMED_OUT = "tool_run_timed_out"', 'TIMED_OUT = "sandbox_not_started"'),),
             targets=("test_the_helper_refusal_codes_are_their_own_and_are_not_the_timeout_code",
                      "test_every_not_started_class_has_its_own_reason_and_none_is_the_timeout_code")),
    Mutation("D65A-T5", "a refusal's audit record drops the exception's own code",
             ("tests/test_timeout_vs_not_started.py",),
             edits=(Edit("control_plane/orchestrator/dispatch.py",
                         "                 else SANDBOX_NOT_STARTED, exc.reason),\n",
                         "                 else SANDBOX_NOT_STARTED,),\n"),),
             targets=("test_a_run_that_never_started_is_refused_with_the_exceptions_code_and_no_output",)),
    Mutation("D65A-T6", "ToolNotExecutable shares its code with another refusal",
             ("tests/test_timeout_vs_not_started.py",),
             edits=(Edit("tool_gateway/sandbox.py", '    reason = "tool_command_not_executable"\n',
                         '    reason = "container_start_refused"\n'),),
             targets=("test_every_not_started_class_has_its_own_reason_and_none_is_the_timeout_code",)),
]

if __name__ == "__main__":
    main({m.id: m for m in CATALOGUE})
