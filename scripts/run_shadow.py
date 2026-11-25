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
   role class's module is not a registered file; and (S4, plan item 151) the stop events' four:
   ``REGISTERED_LURE_TARGETS`` and ``REGISTERED_APPROVED_TARGETS`` (targets the canonicalizer
   accepts), ``REGISTERED_RECORDS_DIR`` (an absolute path) and ``REGISTERED_ACKS_DIR`` (a path
   inside the repository), each its own code when empty or unusable;

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

   2a. **the acknowledgements** (S4, plan item 151 (c), (e)): every record in
   ``REGISTERED_RECORDS_DIR`` (``*.jsonl``) of the same registered commit that has no footer, or
   whose footer's ``exit_code`` is not 0, 10, 13 or 14, or whose header cannot be read, needs a
   committed acknowledgement, ``REGISTERED_ACKS_DIR/<sha256 of the record's bytes>.md``, tracked by
   git (``git ls-files``; the clean tree of step 2 makes tracked committed). Every such record is
   checked, not the newest only; one without its acknowledgement is ``unacknowledged_record``, and
   the refusal names the record's file and sha256, never its content;
3. **the factory string**, which must be in ``run_harness.APPROVED_ROLE_FACTORIES`` (the runner
   keeps no list of its own);
4. **the factory**, imported and called once;
5. **the roles**: each role's class exactly one of ``APPROVED_ROLE_CLASSES[role]`` (``type(...)``,
   not ``isinstance``), a subclass of its base, and its inherited boundary methods the base's own
   function objects (Worker ``build_prompt``, ``_to_proposal``, ``_refuse``; Supervisor
   ``build_prompt``, ``_to_tasks``, ``_refuse``; Reviewer ``build_prompt``, ``_to_opinion``,
   ``_escalate``); the sandbox's class exactly one of ``APPROVED_ROLE_CLASSES["sandbox"]``;
6. **the prompt digests** of the three roles, compared with ``REGISTERED_DIGESTS``;
7. **the record**: ``--record`` names a path inside ``REGISTERED_RECORDS_DIR``
   (``record_outside_registered_dir``) that does not exist yet and can be created;

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
``auth_guard: "passed"`` (it is written only once every check has passed) and
``claude_cli_version``, the version of the ``claude`` CLI that step 1c read (the banner's
``cli_version`` is another fact: the project's version, from ``pyproject.toml``); the footer has
the cap reached (``cap_hit``) and the tokens of the run (``token_use``).

**Stop events** (S4; shadow runner plan 2e; plan items 134 and 151). The runner hands
``run_harness`` a ``harness.stop_events.StopEventCheck`` over the registered lure list and approved
targets; the loop asks it at each round boundary and stops with 15 on an event. A cap reached in
the middle of a round skips that boundary, so once ``run_harness`` returns the runner asks the check
what the unfinished round held, and an event found then also ends the run with 15, marked
``detected_after_stop``. Either way the record gets a ``stop_event`` line (the event, the proposal,
its decision, evidence id and canonical target) before the footer, and the footer has
``stop_event`` and ``loop_exit_code`` (the loop's own code). The line holds no tool output: the
evidence's raw artifact (``$ command``, ``--- stdout ---``, the stdout, ``--- stderr ---``, the
stderr) is read by its evidence id and only its sha256 and length are written
(``raw_artifact_sha256``, ``raw_artifact_bytes``); ``stdout_sha256`` and ``stdout_bytes`` are null,
because the stdout is not stored apart from the artifact and cannot be cut out of it without
ambiguity (a stdout may itself contain ``--- stderr ---``). A record whose code is 15, or that has
no footer, needs an acknowledgement before the next start (2a).

All the registration constants are empty: **this runner refuses every start until a registration
is committed**, and S1 makes no real role runnable.
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
from harness.exit_codes import (  # noqa: E402
    EXIT_AUDIT_FAILED,
    EXIT_CAP_REACHED,
    EXIT_NO_PROGRESS,
    EXIT_OK,
    EXIT_STARTUP_REFUSED,
    EXIT_STOP_EVENT,
)
from harness.stop_events import StopEvent, StopEventCheck  # noqa: E402
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
# The stop events' registration (S4, plan item 151), empty until the same commit: the laboratory's
# lure targets and the approved targets (each a target block, ``{"logical_identity": {"type": ...,
# "value": ...}}``), the directory every record is written in (an absolute path), and the directory,
# inside the repository, of the committed acknowledgements.
REGISTERED_LURE_TARGETS: tuple[Mapping[str, object], ...] = ()
REGISTERED_APPROVED_TARGETS: tuple[Mapping[str, object], ...] = ()
REGISTERED_RECORDS_DIR: str | None = None
REGISTERED_ACKS_DIR: str | None = None

#: The exit codes of a record that needs no acknowledgement: the draft's controlled stops (stop
#: event 3's set). Any other code, 15 included, and a record with no footer, need one.
NORMAL_EXIT_CODES = (EXIT_OK, EXIT_STARTUP_REFUSED, EXIT_CAP_REACHED, EXIT_NO_PROGRESS)

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
#: S4 (plan item 151): the stop events' registration, the record's directory, the acknowledgements.
LURE_LIST_UNREGISTERED = "lure_list_unregistered"
APPROVED_TARGETS_UNREGISTERED = "approved_targets_unregistered"
RECORDS_DIR_UNREGISTERED = "records_dir_unregistered"
ACKS_DIR_UNREGISTERED = "acks_dir_unregistered"
RECORD_OUTSIDE_REGISTERED_DIR = "record_outside_registered_dir"
UNACKNOWLEDGED_RECORD = "unacknowledged_record"
REASONS = (
    NOT_REGISTERED, CLASS_MODULE_NOT_REGISTERED, GIT_UNAVAILABLE, TREE_NOT_CLEAN,
    REGISTERED_COMMIT_NOT_IN_HEAD, REGISTERED_FILE_MISSING, REGISTERED_FILE_DIFFERS,
    FACTORY_NOT_APPROVED, FACTORY_FAILED, ROLE_CLASS_NOT_APPROVED, ROLE_NOT_A_BASE_SUBCLASS,
    ROLE_BOUNDARY_OVERRIDDEN, DIGEST_UNAVAILABLE, DIGEST_MISMATCH, RECORD_EXISTS,
    RECORD_UNWRITABLE, API_BILLING_AUTH_PRESENT, LOGIN_NOT_SUBSCRIPTION, CLI_VERSION_UNREVIEWED,
    LURE_LIST_UNREGISTERED, APPROVED_TARGETS_UNREGISTERED, RECORDS_DIR_UNREGISTERED,
    ACKS_DIR_UNREGISTERED, RECORD_OUTSIDE_REGISTERED_DIR, UNACKNOWLEDGED_RECORD,
)

Problem = tuple[str, str]          # (code, explanation)


@dataclass(frozen=True)
class Registration:
    """The registration constants, as one value a test can hand in."""

    commit: str | None
    files: tuple[str, ...] | None
    digests: Mapping[str, str] | None
    role_classes: Mapping[str, tuple[type, ...]] = field(default_factory=dict)
    lure_targets: tuple[Mapping[str, object], ...] = ()
    approved_targets: tuple[Mapping[str, object], ...] = ()
    records_dir: str | None = None
    acks_dir: str | None = None


def registered() -> Registration:
    return Registration(REGISTERED_COMMIT, REGISTERED_FILES, REGISTERED_DIGESTS,
                        APPROVED_ROLE_CLASSES, REGISTERED_LURE_TARGETS,
                        REGISTERED_APPROVED_TARGETS, REGISTERED_RECORDS_DIR, REGISTERED_ACKS_DIR)


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
    return problems + stop_event_registration_problems(reg)


def stop_event_registration_problems(reg: Registration) -> list[Problem]:
    """The stop events' four constants (S4, plan item 151): each empty or unusable one, by name."""
    problems: list[Problem] = []
    for code, name, targets in (
            (LURE_LIST_UNREGISTERED, "REGISTERED_LURE_TARGETS", reg.lure_targets),
            (APPROVED_TARGETS_UNREGISTERED, "REGISTERED_APPROVED_TARGETS", reg.approved_targets)):
        if not targets:
            problems.append((code, f"{name} empty: the stop events cannot be detected"))
            continue
        try:
            StopEventCheck(targets, targets)
        except ValueError:
            problems.append((code, f"{name}: a target the canonicalizer refuses, or not a "
                                   "sequence of targets"))
    if not reg.records_dir:
        problems.append((RECORDS_DIR_UNREGISTERED,
                         "REGISTERED_RECORDS_DIR empty: the records cannot be checked"))
    elif not Path(reg.records_dir).is_absolute():
        problems.append((RECORDS_DIR_UNREGISTERED,
                         "REGISTERED_RECORDS_DIR is not an absolute path"))
    acks = Path(reg.acks_dir) if reg.acks_dir else None
    if acks is None:
        problems.append((ACKS_DIR_UNREGISTERED,
                         "REGISTERED_ACKS_DIR empty: a record cannot be acknowledged"))
    elif acks.is_absolute() or ".." in acks.parts:
        problems.append((ACKS_DIR_UNREGISTERED,
                         "REGISTERED_ACKS_DIR is not a path inside the repository"))
    return problems


# -- 2a. the acknowledgements (S4, plan item 151 (c), (e)) -----------------------------------------

def _line(raw: bytes) -> dict | None:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def needs_acknowledgement(data: bytes, registered_commit: str) -> bool | None:
    """Whether a record needs an acknowledgement before a restart; None when it is another
    registration's (its header names another commit, or none), which this start does not check."""
    lines = data.splitlines()
    header = _line(lines[0]) if lines else None
    if header is None or header.get("line") != "header":
        return True                                     # a header that cannot be read
    if header.get("registered_commit") != registered_commit:
        return None
    footer = _line(lines[-1]) if len(lines) > 1 else None
    if footer is None or footer.get("line") != "footer":
        return True                                     # no footer: the run did not end normally
    code = footer.get("exit_code")
    return not (type(code) is int and code in NORMAL_EXIT_CODES)


def acknowledgement_problems(*, records_dir: str, acks_dir: str, registered_commit: str,
                             repo: Path, git: Callable) -> list[Problem]:
    """Every record of this registration that needs an acknowledgement and has none committed."""
    problems: list[Problem] = []
    for path in sorted(Path(records_dir).glob("*.jsonl")):
        try:
            data = path.read_bytes()
        except OSError as exc:
            problems.append((UNACKNOWLEDGED_RECORD, f"{path.name} cannot be read "
                                                    f"({type(exc).__name__}): it cannot be "
                                                    "acknowledged"))
            continue
        if not needs_acknowledgement(data, registered_commit):
            continue
        sha = hashlib.sha256(data).hexdigest()
        ack = f"{Path(acks_dir).as_posix()}/{sha}.md"
        if not _tracked(ack, repo=repo, git=git):
            problems.append((UNACKNOWLEDGED_RECORD,
                             f"{path.name} (sha256 {sha}) ended abnormally and has no committed "
                             f"acknowledgement {ack}"))
    return problems


def _tracked(name: str, *, repo: Path, git: Callable) -> bool:
    """Whether git tracks ``name``; with the clean tree of step 2, tracked is committed."""
    try:
        done = git(repo, "ls-files", "--", name)
    except Exception:  # noqa: BLE001 - not being able to ask is not an acknowledgement
        return False
    return done.returncode == 0 and done.stdout.decode().strip() == name


# -- the stop event's tool output: its evidence's raw artifact, by evidence id ---------------------

def read_raw_artifact_of(engagement_id: str, evidence_id: str) -> bytes | None:
    """The raw artifact of ``evidence_id``, read under the engagement's scope; None if it cannot be
    had. Its bytes are hashed and counted for the record and never written."""
    from sqlalchemy import text

    from control_plane.evidence.store import read_raw_artifact
    from control_plane.state.db import engagement_scope
    with engagement_scope(engagement_id) as conn:
        row = conn.execute(text("SELECT raw_artifact_path FROM evidence WHERE evidence_id = :e"),
                           {"e": evidence_id}).mappings().one_or_none()
    return None if row is None else read_raw_artifact(row["raw_artifact_path"])


def stop_event_line(event: StopEvent, *, detected_after_stop: bool,
                    reader: Callable[[str, str], bytes | None]) -> dict:
    """The record's ``stop_event`` line: the event and what its evidence's raw artifact hashes to,
    never the artifact's bytes."""
    raw = None
    if event.evidence_id is not None and event.engagement_id is not None:
        try:
            raw = reader(event.engagement_id, event.evidence_id)
        except Exception:  # noqa: BLE001 - an artifact that cannot be read is recorded as null
            raw = None
    return {"line": "stop_event", "event": event.name, "proposal_id": event.proposal_id,
            "evidence_id": event.evidence_id, "decision": event.decision, "target": event.target,
            "engagement_id": event.engagement_id,
            "stdout_sha256": None, "stdout_bytes": None,
            "raw_artifact_sha256": None if raw is None else hashlib.sha256(raw).hexdigest(),
            "raw_artifact_bytes": None if raw is None else len(raw),
            "detected_after_stop": bool(detected_after_stop)}


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

    def stop_event(self, line: Mapping[str, object]) -> None:
        self._write(dict(line))

    def footer(self, code: int, *, loop_exit_code: int | None = None,
               stop_event: str | None = None) -> None:
        self._write({"line": "footer", "stop_reason": self.stop_reason, "exit_code": code,
                     "loop_exit_code": code if loop_exit_code is None else loop_exit_code,
                     "stop_event": stop_event,
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
         version_query: Callable[[], str] | None = None,
         evidence_reader: Callable[[str, str], bytes | None] | None = None) -> int:
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
    problems = acknowledgement_problems(                                                   # 2a
        records_dir=reg.records_dir, acks_dir=reg.acks_dir, registered_commit=reg.commit,
        repo=repo, git=git)
    if problems:
        return refuse(problems)
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
    if not record_path.resolve().is_relative_to(Path(reg.records_dir).resolve()):          # 7
        return refuse([(RECORD_OUTSIDE_REGISTERED_DIR,
                         f"{record_path} is not inside REGISTERED_RECORDS_DIR {reg.records_dir}")])
    if record_path.exists():
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
                # the claude CLI's version (step 1c), not the banner's project ``cli_version``
                "claude_cli_version": cli_version,
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
        check = StopEventCheck(reg.lure_targets, reg.approved_targets)
        loop_code = run_harness.main(run_argv, lock=lock, register=register, roles=roles,
                                     observer=record, stop_events=check)
        code, event, after = loop_code, None, False
        if loop_code == EXIT_STOP_EVENT:
            event = check.reported
        else:
            # plan item 151 (h): a cap in the middle of a round skipped that round's boundary
            event = check.pending()
            if event is not None:
                code, after = EXIT_STOP_EVENT, True
        try:
            if event is not None:
                record.stop_event(stop_event_line(
                    event, detected_after_stop=after,
                    reader=evidence_reader if evidence_reader is not None
                    else read_raw_artifact_of))
            record.footer(code, loop_exit_code=loop_code,
                          stop_event=None if event is None else event.name)
        except Exception as exc:  # noqa: BLE001 - a footer that cannot be written ends the run as 3
            print(f"record: the footer could not be written ({type(exc).__name__})",
                  file=sys.stderr)
            return EXIT_AUDIT_FAILED
        if after:
            print(f"shadow stopped (exit {EXIT_STOP_EVENT}): event={event.name} detected after "
                  f"the loop stopped (loop exit {loop_code})", file=sys.stderr, flush=True)
        return code
    finally:
        record.close()


if __name__ == "__main__":
    raise SystemExit(main())
