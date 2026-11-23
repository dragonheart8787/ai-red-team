"""The shadow runner (D69 shadow runner plan, stage S1): checks, then the harness in this process.

    python scripts/run_shadow.py --record PATH --role-factory module:function --objective TEXT \\
        --window-limit N --max-rounds N --max-model-calls N --no-progress-limit N \\
        --live-task-limit N --max-tokens N --max-minutes N [--once]

The arguments are those of ``scripts/run_harness.py run``, plus ``--record PATH``, required and with
no default: the run's record (plan item 140), a new file the runner creates and never appends to.
``--max-tokens`` and ``--max-minutes`` (S3, plan item 143), optional on ``run_harness.py``, are
required here and have no default; a missing one is a usage error (exit 2) before any check.
Before anything reads the database the runner refuses, in this order (plan items 131, 134, 137):

1. **the registration constants** -- ``REGISTERED_COMMIT``, ``REGISTERED_FILES``,
   ``REGISTERED_DIGESTS`` and ``APPROVED_ROLE_CLASSES`` -- when any is empty, or when a listed
   role class's module is not a registered file;

   1a. **the billing guard** (the owner's decision of 2026-11-22, plan items 141 c and 143): a
   variable of ``agents.llm.auth_guard.BILLING_VARIABLES`` with a value, or an ``apiKeyHelper`` in
   a Claude Code settings file, is ``api_billing_auth_present``; the refusal names the variable or
   the file and key, never a value;

   1b. **the login** (plan item 145): ``claude auth status --json`` (no model call) must say the
   CLI is logged in by the subscription; anything else, a failed query or output that is not a
   JSON object included, is ``login_not_subscription``;

   1c. **the CLI's version** (plan item 148): ``claude --version`` (no model call) must be
   ``agents.llm.auth_guard.REVIEWED_CLI_VERSION``, the version the name lists of 1a were reviewed
   on; another version, or a version that cannot be read, is ``cli_version_unreviewed``;

2. **the integrity guard**, with the meaning of ``integrity()`` in ``scripts/dp15_stage1_run.py``:
   an uncommitted or untracked path, a HEAD that does not contain the registered commit, a
   registered file whose bytes differ from its blob in that commit, or anything git cannot answer;
   the hashes of the code files are recorded and not compared;
3. **the factory string**, which must be in ``run_harness.APPROVED_ROLE_FACTORIES`` (the runner
   keeps no list of its own);
4. **the factory**, imported and called once;
5. **the roles**: each role's class exactly one of ``APPROVED_ROLE_CLASSES[role]`` (``type(...)``,
   not ``isinstance``), a subclass of its base, and its inherited boundary methods the base's own
   function objects (Worker ``build_prompt``, ``_to_proposal``, ``_refuse``; Supervisor
   ``build_prompt``, ``_to_tasks``, ``_refuse``; Reviewer ``build_prompt``, ``_to_opinion``,
   ``_escalate``); the sandbox's class exactly one of ``APPROVED_ROLE_CLASSES["sandbox"]``;
6. **the prompt digests** of the three roles, compared with ``REGISTERED_DIGESTS``;
7. **the record**: ``--record`` names a path that does not exist yet and can be created;

and then writes the record's header and hands the same role instances to
``run_harness.main(..., roles=..., observer=...)`` in this process. Every refusal prints
``refused: <code>: <explanation>`` to standard error, one line per problem, and ends with exit 10.
The codes are the closed list ``REASONS``.

**The record** (plan item 140) is one JSON object per line, each flushed and fsynced as it is
written: a ``header``, the ``banner``, every ``refusal`` of the harness's own check, every role
``call``, every ``round``, and a ``footer`` once ``run_harness`` has returned. No text a model wrote
is written: a call keeps its role, model, latency, tokens and whether it failed, and the kind of a
failure is the one its call record carries (numbered change D69-NC-1, plan item 142) when that is
one of ``control_plane/plan_fit/failure_kind.py``'s three, and ``unknown`` otherwise; never its free
text. A record with no footer is a run that did not end normally. The header says
``auth_guard: "passed"`` (it is written only once every check has passed) and the CLI's
``cli_version``; the footer has the cap reached (``cap_hit``) and the tokens of the run
(``token_use``).

All four constants are empty: **this runner refuses every start until a registration is
committed**, and S1 makes no real role runnable.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import inspect
import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from agents.llm import auth_guard  # noqa: E402
from agents.llm.reviewer_base import OPINION_SCHEMA, BaseReviewer  # noqa: E402
from agents.llm.reviewer_base import SYSTEM_PROMPT as REVIEWER_SYSTEM_PROMPT  # noqa: E402
from agents.llm.supervisor_base import BaseSupervisor, plan_schema  # noqa: E402
from agents.llm.worker_base import WORKER_SYSTEM_PROMPT, BaseWorker, proposal_schema  # noqa: E402
from control_plane.plan_fit.failure_kind import FAILURE_KINDS  # noqa: E402
from harness.action_allowlist import ALLOWED_ACTIONS  # noqa: E402
from harness.banner_facts import digest  # noqa: E402
from harness.exit_codes import EXIT_AUDIT_FAILED, EXIT_STARTUP_REFUSED  # noqa: E402
from scripts import run_harness  # noqa: E402

# -- the registration ------------------------------------------------------------------------------
# These four are written only by the commit that registers the shadow, authorized by the owner
# (plan section 10; items 134 and 137). Until then they are empty and the runner refuses to start.
# APPROVED_ROLE_CLASSES has four keys -- worker, supervisor, reviewer and sandbox (item 140) -- and
# an empty or missing key is a refusal. A real class put into it must have its module file in
# REGISTERED_FILES at the same time (checked in step 1), so that a later change to its
# ``propose``, ``plan``, ``review`` or ``run`` is refused by the integrity guard.
REGISTERED_COMMIT: str | None = None
REGISTERED_FILES: tuple[str, ...] | None = None
REGISTERED_DIGESTS: Mapping[str, str] | None = None
APPROVED_ROLE_CLASSES: Mapping[str, tuple[type, ...]] = {}

#: Recorded, not compared: the runner and the entry it calls may be mended after registration.
CODE_FILES = ("scripts/run_shadow.py", "scripts/run_harness.py")

ROLES = ("worker", "supervisor", "reviewer")
#: The keys of APPROVED_ROLE_CLASSES: the three roles and the sandbox, whose class is checked by
#: exact type only (it has no base class of the project's to compare methods with).
ROLE_KEYS = (*ROLES, "sandbox")
#: For each role: its base class, and the inherited methods that must be the base's own objects.
BOUNDARY: Mapping[str, tuple[type, tuple[str, ...]]] = {
    "worker": (BaseWorker, ("build_prompt", "_to_proposal", "_refuse")),
    "supervisor": (BaseSupervisor, ("build_prompt", "_to_tasks", "_refuse")),
    "reviewer": (BaseReviewer, ("build_prompt", "_to_opinion", "_escalate")),
}

# -- the closed list of refusal codes --------------------------------------------------------------
NOT_REGISTERED = "not_registered"
CLASS_MODULE_NOT_REGISTERED = "class_module_not_registered"
GIT_UNAVAILABLE = "git_unavailable"
TREE_NOT_CLEAN = "tree_not_clean"
REGISTERED_COMMIT_NOT_IN_HEAD = "registered_commit_not_in_head"
REGISTERED_FILE_MISSING = "registered_file_missing"
REGISTERED_FILE_DIFFERS = "registered_file_differs"
FACTORY_NOT_APPROVED = "factory_not_approved"
FACTORY_FAILED = "factory_failed"
ROLE_CLASS_NOT_APPROVED = "role_class_not_approved"
ROLE_NOT_A_BASE_SUBCLASS = "role_not_a_base_subclass"
ROLE_BOUNDARY_OVERRIDDEN = "role_boundary_overridden"
DIGEST_UNAVAILABLE = "digest_unavailable"
DIGEST_MISMATCH = "digest_mismatch"
RECORD_EXISTS = "record_exists"
RECORD_UNWRITABLE = "record_unwritable"
API_BILLING_AUTH_PRESENT = "api_billing_auth_present"
#: The login itself is not the subscription's, or cannot be read (plan item 145): kept apart from
#: ``api_billing_auth_present``, which names a variable or a setting the operator can remove.
LOGIN_NOT_SUBSCRIPTION = "login_not_subscription"
#: The CLI is not the version the name lists were reviewed on, or its version cannot be read (plan
#: item 148).
CLI_VERSION_UNREVIEWED = "cli_version_unreviewed"
REASONS = (
    NOT_REGISTERED, CLASS_MODULE_NOT_REGISTERED, GIT_UNAVAILABLE, TREE_NOT_CLEAN,
    REGISTERED_COMMIT_NOT_IN_HEAD, REGISTERED_FILE_MISSING, REGISTERED_FILE_DIFFERS,
    FACTORY_NOT_APPROVED, FACTORY_FAILED, ROLE_CLASS_NOT_APPROVED, ROLE_NOT_A_BASE_SUBCLASS,
    ROLE_BOUNDARY_OVERRIDDEN, DIGEST_UNAVAILABLE, DIGEST_MISMATCH, RECORD_EXISTS,
    RECORD_UNWRITABLE, API_BILLING_AUTH_PRESENT, LOGIN_NOT_SUBSCRIPTION, CLI_VERSION_UNREVIEWED,
)

Problem = tuple[str, str]          # (code, explanation)


@dataclass(frozen=True)
class Registration:
    """The four registration constants, as one value a test can hand in."""

    commit: str | None
    files: tuple[str, ...] | None
    digests: Mapping[str, str] | None
    role_classes: Mapping[str, tuple[type, ...]] = field(default_factory=dict)


def registered() -> Registration:
    return Registration(REGISTERED_COMMIT, REGISTERED_FILES, REGISTERED_DIGESTS,
                        APPROVED_ROLE_CLASSES)


# -- 1. the registration constants -----------------------------------------------------------------

def module_file(cls: type, repo: Path) -> str | None:
    """The repository-relative path of the file that defines ``cls``, or None outside the repo."""
    try:
        path = Path(inspect.getfile(cls)).resolve()
        return path.relative_to(repo.resolve()).as_posix()
    except (TypeError, ValueError):
        return None


def registration_problems(reg: Registration, *, repo: Path = REPO_ROOT) -> list[Problem]:
    empty = [name for name, value in (
        ("REGISTERED_COMMIT", reg.commit), ("REGISTERED_FILES", reg.files),
        ("REGISTERED_DIGESTS", reg.digests), ("APPROVED_ROLE_CLASSES", reg.role_classes))
        if not value]
    if reg.role_classes:
        empty += [f"APPROVED_ROLE_CLASSES[{key!r}]" for key in ROLE_KEYS
                  if not reg.role_classes.get(key)]
    if empty:
        return [(NOT_REGISTERED, f"{', '.join(empty)} empty: the shadow is not registered")]
    problems: list[Problem] = []
    for role, classes in reg.role_classes.items():
        for cls in classes:
            name = module_file(cls, repo)
            if name is None or name not in reg.files:
                problems.append((CLASS_MODULE_NOT_REGISTERED,
                                 f"{role} class {cls.__qualname__}: its module "
                                 f"{name or '(outside the repository)'} is not a registered file"))
    return problems


# -- 2. the integrity guard ------------------------------------------------------------------------

def _git(repo: Path, *args: str):
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, timeout=30)


@dataclass
class Integrity:
    head: str | None
    registered_sha256: dict
    current_sha256: dict
    code_sha256: dict              # recorded, not compared
    problems: list


def integrity(*, repo: Path, registered_commit: str, files: tuple[str, ...],
              code: tuple[str, ...] = CODE_FILES, git: Callable = _git) -> Integrity:
    """Whether this checkout is the registered one. Anything git cannot answer is a problem,
    never a pass (the meaning of ``integrity()`` in ``scripts/dp15_stage1_run.py``)."""
    problems: list[Problem] = []

    def ask(*args: str):
        try:
            return git(repo, *args)
        except Exception as exc:  # noqa: BLE001 - not being able to ask is a refusal
            problems.append((GIT_UNAVAILABLE,
                             f"git could not be run ({type(exc).__name__}): {' '.join(args[:2])}"))
            return None

    head = None
    done = ask("rev-parse", "HEAD")
    if done is not None:
        if done.returncode == 0:
            head = done.stdout.decode().strip()
        else:
            problems.append((GIT_UNAVAILABLE, "git cannot name HEAD"))
    done = ask("status", "--porcelain", "--untracked-files=all")
    if done is not None:
        if done.returncode != 0:
            problems.append((GIT_UNAVAILABLE, "git cannot read the working tree's status"))
        elif done.stdout.strip():
            lines = [x for x in done.stdout.decode().splitlines() if x.strip()]
            problems.append((TREE_NOT_CLEAN, f"{len(lines)} uncommitted or untracked path(s), "
                                             f"e.g. {lines[0][3:]!r}"))
    done = ask("merge-base", "--is-ancestor", registered_commit, "HEAD")
    if done is not None and done.returncode != 0:
        if done.returncode == 1:
            problems.append((REGISTERED_COMMIT_NOT_IN_HEAD,
                             f"HEAD {head} does not contain {registered_commit[:7]}"))
        else:
            problems.append((GIT_UNAVAILABLE, f"git could not check that HEAD contains "
                                              f"{registered_commit[:7]}"))
    registered_sha, current_sha = {}, {}
    for name in files:
        blob = ask("show", f"{registered_commit}:{name}")
        if blob is not None and blob.returncode == 0:
            registered_sha[name] = hashlib.sha256(blob.stdout).hexdigest()
        elif blob is not None:
            problems.append((REGISTERED_FILE_MISSING,
                             f"{name} is not in the registered commit {registered_commit[:7]}"))
        try:
            current_sha[name] = hashlib.sha256((repo / name).read_bytes()).hexdigest()
        except OSError as exc:
            problems.append((REGISTERED_FILE_MISSING, f"{name} cannot be read "
                                                      f"({type(exc).__name__})"))
        if name in registered_sha and name in current_sha \
                and registered_sha[name] != current_sha[name]:
            problems.append((REGISTERED_FILE_DIFFERS,
                             f"{name}: registered sha256 {registered_sha[name]}, "
                             f"on disk {current_sha[name]}"))
    code_sha = {}
    for name in code:
        try:
            code_sha[name] = hashlib.sha256((repo / name).read_bytes()).hexdigest()
        except OSError:
            code_sha[name] = None
    return Integrity(head, registered_sha, current_sha, code_sha, problems)


# -- 5. the roles ----------------------------------------------------------------------------------

def role_problems(roles: object, approved: Mapping[str, tuple[type, ...]]) -> list[Problem]:
    problems: list[Problem] = []
    sandbox = type(getattr(roles, "sandbox", None))
    if sandbox not in approved.get("sandbox", ()):
        problems.append((ROLE_CLASS_NOT_APPROVED,
                         f"sandbox {sandbox.__module__}.{sandbox.__qualname__} is not an approved "
                         "sandbox class"))
    for role in ROLES:
        cls = type(getattr(roles, role, None))
        base, methods = BOUNDARY[role]
        if cls not in approved.get(role, ()):
            problems.append((ROLE_CLASS_NOT_APPROVED,
                             f"{role} {cls.__module__}.{cls.__qualname__} is not an approved "
                             f"{role} class"))
            continue
        if not issubclass(cls, base):
            problems.append((ROLE_NOT_A_BASE_SUBCLASS,
                             f"{role} {cls.__qualname__} is not a {base.__name__}"))
            continue
        for method in methods:
            if getattr(cls, method, None) is not getattr(base, method):
                problems.append((ROLE_BOUNDARY_OVERRIDDEN,
                                 f"{role} {cls.__qualname__} overrides {method}, which is "
                                 f"{base.__name__}'s"))
    return problems


# -- 6. the prompt digests -------------------------------------------------------------------------

def role_digests(roles: object) -> dict:
    """The three roles' prompt-and-schema digests (``harness.banner_facts.digest``). The Worker's
    and the Reviewer's are of the constants their real adapters send; the Supervisor's is of the
    instance's ``system_prompt``, whose ``warn_about_duplicates`` is recorded with it."""
    actions = tuple(ALLOWED_ACTIONS)
    supervisor = roles.supervisor
    return {
        "worker": digest(WORKER_SYSTEM_PROMPT,
                         proposal_schema(scope_object_ids=(), actions=actions)),
        "supervisor": digest(supervisor.system_prompt,
                             plan_schema(scope_object_ids=(), actions=actions)),
        "reviewer": digest(REVIEWER_SYSTEM_PROMPT, OPINION_SCHEMA),
        "supervisor_warn_about_duplicates": bool(supervisor.warn_about_duplicates),
    }


def digest_problems(computed: Mapping[str, object], expected: Mapping[str, str]) -> list[Problem]:
    return [(DIGEST_MISMATCH, f"{role}: registered {expected.get(role)}, now {computed[role]}")
            for role in ROLES if expected.get(role) != computed[role]]


# -- the record ------------------------------------------------------------------------------------

def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Record:
    """The run's record, and ``run_harness``'s observer (plan item 140; shadow runner plan 2b, b3).

    One JSON object per line, written, flushed and fsynced as it happens, so that whatever was
    written before an abnormal end is in the file; a record with no ``footer`` is a run that did
    not end normally. Created with mode ``x``: an existing file is never appended to. Nothing a
    model wrote is written -- a Supervisor's ``assessment_note`` and the free text of a failure
    are not; the kind of a failure is its call record's ``failure_kind`` when that is one of
    ``FAILURE_KINDS`` (D69-NC-1, plan item 142), and ``unknown`` otherwise.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.stop_reason: str | None = None
        self.cap_hit: str | None = None
        self.token_use: dict | None = None
        #: Failed calls whose input and output tokens are both 0: their tokens are not known, so
        #: the token cap did not count them (D69-NC-1a, plan item 147); written in the footer.
        self.failed_calls_without_tokens = 0
        self._file = open(path, "x", encoding="utf-8")

    def _write(self, line: dict) -> None:
        self._file.write(json.dumps(line, sort_keys=True, default=str) + "\n")
        self._file.flush()
        os.fsync(self._file.fileno())

    def header(self, fields: Mapping[str, object]) -> None:
        self._write({"line": "header", **fields})

    # -- the observer's methods, called by run_harness as things happen --

    def on_banner(self, facts: Mapping[str, object]) -> None:
        self._write({"line": "banner", "facts": dict(facts)})

    def on_refusal(self, side: str, reason: str) -> None:
        self._write({"line": "refusal", "side": side, "reason": reason})

    def on_call(self, role: str, call: object) -> None:
        failed = bool(getattr(call, "failed", False))
        if failed and not (getattr(call, "input_tokens", 0) or getattr(call, "output_tokens", 0)):
            self.failed_calls_without_tokens += 1
        self._write({"line": "call", "role": role, "model": str(getattr(call, "model", "")),
                     "latency_seconds": float(getattr(call, "latency_seconds", 0.0)),
                     "input_tokens": int(getattr(call, "input_tokens", 0) or 0),
                     "output_tokens": int(getattr(call, "output_tokens", 0) or 0),
                     "failed": failed, "failure_kind": _kind(call) if failed else None})

    def on_round(self, number: int, progress: bool) -> None:
        self._write({"line": "round", "round": number, "progress": bool(progress)})

    def on_stop(self, reason: str, code: int, cap_hit: str | None = None,
                token_use: Mapping[str, int] | None = None) -> None:
        # written in the footer, once run_harness returns
        self.stop_reason, self.cap_hit = reason, cap_hit
        self.token_use = None if token_use is None else {k: int(v) for k, v in token_use.items()}

    def footer(self, code: int) -> None:
        self._write({"line": "footer", "stop_reason": self.stop_reason, "exit_code": code,
                     "cap_hit": self.cap_hit, "token_use": self.token_use,
                     "failed_calls_without_tokens": self.failed_calls_without_tokens,
                     "ended_at": _now()})

    def close(self) -> None:
        self._file.close()


def _kind(call: object) -> str:
    """A failed call's kind as its record carries it, if it is one of the closed three."""
    kind = getattr(call, "failure_kind", None)
    return kind if isinstance(kind, str) and kind in FAILURE_KINDS else "unknown"


def _shadow_argv(argv: list[str]) -> tuple[Path, list[str]]:
    """``--record PATH``, ``--max-tokens N`` and ``--max-minutes N`` (all three required, none
    with a default; a missing one is argparse's usage error, exit 2), and the arguments for
    run_harness, the two caps passed on to it."""
    parser = argparse.ArgumentParser(prog="run_shadow.py", add_help=False)
    parser.add_argument("--record", required=True, help="the run's record: a new file")
    for name in ("--max-tokens", "--max-minutes"):
        parser.add_argument(name, required=True, type=run_harness._positive,
                            help="required, no default (plan item 143)")
    known, rest = parser.parse_known_args(argv)
    caps = ["--max-tokens", str(known.max_tokens), "--max-minutes", str(known.max_minutes)]
    return Path(known.record), [*rest, *caps]


# -- the order -------------------------------------------------------------------------------------

def _factory(spec: str):
    module_name, _, function = spec.partition(":")
    return getattr(importlib.import_module(module_name), function)()


def refuse(problems: list[Problem]) -> int:
    for code, explanation in problems:
        print(f"refused: {code}: {explanation}", file=sys.stderr)
    return EXIT_STARTUP_REFUSED


def main(argv: list[str] | None = None, *, registration: Registration | None = None,
         repo: Path = REPO_ROOT, git: Callable = _git, lock=None,
         register=signal.signal, environ: Mapping[str, str] | None = None,
         settings_files: tuple[Path, ...] | None = None,
         login_query: Callable[[], Mapping[str, object]] | None = None,
         version_query: Callable[[], str] | None = None) -> int:
    record_path, harness_argv = _shadow_argv(sys.argv[1:] if argv is None else argv)
    reg = registration if registration is not None else registered()
    problems = registration_problems(reg, repo=repo)                                     # 1
    if problems:
        return refuse(problems)
    environ = os.environ if environ is None else environ                                  # 1a
    if settings_files is None:
        settings_files = auth_guard.settings_files(environ=environ, home=Path.home(), project=repo)
    found = auth_guard.problems(environ, settings_files)
    if found:
        return refuse([(API_BILLING_AUTH_PRESENT, f"{what}: the shadow runner uses the "
                                                  "subscription login only") for what in found])
    query = login_query if login_query is not None else (                                 # 1b
        lambda: auth_guard.query_login(environ=environ))
    try:
        login = query()
    except Exception as exc:  # noqa: BLE001 - a login that cannot be read is not the subscription
        return refuse([(LOGIN_NOT_SUBSCRIPTION, f"the login cannot be read "
                                                f"({type(exc).__name__})")])
    found = auth_guard.login_problems(login)
    if found:
        return refuse([(LOGIN_NOT_SUBSCRIPTION, what) for what in found])
    ask_version = version_query if version_query is not None else (                       # 1c
        lambda: auth_guard.query_cli_version(environ=environ))
    try:
        cli_version = ask_version()
    except Exception as exc:  # noqa: BLE001 - a version that cannot be read is not the reviewed one
        return refuse([(CLI_VERSION_UNREVIEWED, f"the CLI's version cannot be read "
                                                f"({type(exc).__name__})")])
    if cli_version != auth_guard.REVIEWED_CLI_VERSION:
        return refuse([(CLI_VERSION_UNREVIEWED, f"the CLI is {str(cli_version)[:40]!r}; the name "
                                                f"lists were reviewed on "
                                                f"{auth_guard.REVIEWED_CLI_VERSION} and are "
                                                "reviewed again before another version runs")])
    checked = integrity(repo=repo, registered_commit=reg.commit, files=reg.files, git=git)  # 2
    if checked.problems:
        return refuse(checked.problems)
    run_argv = ["run", *harness_argv]
    args = run_harness.build_parser().parse_args(run_argv)
    if args.role_factory not in run_harness.APPROVED_ROLE_FACTORIES:                       # 3
        return refuse([(FACTORY_NOT_APPROVED, f"{args.role_factory} is not in "
                                              "run_harness.APPROVED_ROLE_FACTORIES")])
    try:
        roles = _factory(args.role_factory)                                                 # 4
    except Exception as exc:  # noqa: BLE001 - what a factory raised is not printed
        return refuse([(FACTORY_FAILED, f"the role factory failed ({type(exc).__name__})")])
    problems = role_problems(roles, reg.role_classes)                                       # 5
    if problems:
        return refuse(problems)
    try:
        computed = role_digests(roles)                                                      # 6
    except Exception as exc:  # noqa: BLE001 - a digest that cannot be computed is a refusal
        return refuse([(DIGEST_UNAVAILABLE, f"a prompt digest cannot be computed "
                                            f"({type(exc).__name__})")])
    problems = digest_problems(computed, reg.digests)
    if problems:
        return refuse(problems)
    if record_path.exists():                                                                # 7
        return refuse([(RECORD_EXISTS, f"{record_path} exists: a run writes a new record")])
    try:
        record = Record(record_path)
    except FileExistsError:
        return refuse([(RECORD_EXISTS, f"{record_path} exists: a run writes a new record")])
    except OSError as exc:
        return refuse([(RECORD_UNWRITABLE, f"{record_path} cannot be created "
                                           f"({type(exc).__name__})")])
    try:
        try:
            record.header({
                "format": 1, "started_at": _now(), "auth_guard": "passed",
                "login": {"auth_method": login.get("authMethod"),
                          "api_provider": login.get("apiProvider")},
                "cli_version": cli_version,
                "registered_commit": reg.commit,
                "head": checked.head, "registered_sha256": checked.registered_sha256,
                "code_sha256": checked.code_sha256,
                "digests": {role: computed[role] for role in ROLES},
                "supervisor_warn_about_duplicates": computed["supervisor_warn_about_duplicates"],
                "role_factory": args.role_factory,
                "role_classes": {key: f"{type(getattr(roles, key)).__module__}."
                                      f"{type(getattr(roles, key)).__qualname__}"
                                 for key in ROLE_KEYS},
                "bounds": {"window_limit": args.window_limit, "max_rounds": args.max_rounds,
                           "max_model_calls": args.max_model_calls,
                           "no_progress_limit": args.no_progress_limit,
                           "live_task_limit": args.live_task_limit,
                           "max_tokens": args.max_tokens, "max_minutes": args.max_minutes},
                "once": args.once})
        except OSError as exc:
            return refuse([(RECORD_UNWRITABLE, f"{record_path}: the header cannot be written "
                                               f"({type(exc).__name__})")])
        code = run_harness.main(run_argv, lock=lock, register=register, roles=roles,
                                observer=record)
        try:
            record.footer(code)
        except Exception as exc:  # noqa: BLE001 - a footer that cannot be written ends the run as 3
            print(f"record: the footer could not be written ({type(exc).__name__})",
                  file=sys.stderr)
            return EXIT_AUDIT_FAILED
        return code
    finally:
        record.close()


if __name__ == "__main__":
    raise SystemExit(main())
