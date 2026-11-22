"""The shadow runner (D69 shadow runner plan, stage S1): checks, then the harness in this process.

    python scripts/run_shadow.py --role-factory module:function --objective TEXT \\
        --window-limit N --max-rounds N --max-model-calls N --no-progress-limit N \\
        --live-task-limit N [--once]

The arguments are those of ``scripts/run_harness.py run``. Before anything reads the database the
runner refuses, in this order (plan items 131, 134, 137):

1. **the registration constants** -- ``REGISTERED_COMMIT``, ``REGISTERED_FILES``,
   ``REGISTERED_DIGESTS`` and ``APPROVED_ROLE_CLASSES`` -- when any is empty, or when a listed
   role class's module is not a registered file;
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
   ``_escalate``);
6. **the prompt digests** of the three roles, compared with ``REGISTERED_DIGESTS``;

and then hands the same role instances to ``run_harness.main(..., roles=...)`` in this process.
Every refusal prints ``refused: <code>: <explanation>`` to standard error, one line per problem,
and ends with exit 10. The codes are the closed list ``REASONS``.

All four constants are empty: **this runner refuses every start until a registration is
committed**, and S1 makes no real role runnable.
"""

from __future__ import annotations

import hashlib
import importlib
import inspect
import signal
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from agents.llm.reviewer_base import OPINION_SCHEMA, BaseReviewer  # noqa: E402
from agents.llm.reviewer_base import SYSTEM_PROMPT as REVIEWER_SYSTEM_PROMPT  # noqa: E402
from agents.llm.supervisor_base import BaseSupervisor, plan_schema  # noqa: E402
from agents.llm.worker_base import WORKER_SYSTEM_PROMPT, BaseWorker, proposal_schema  # noqa: E402
from harness.action_allowlist import ALLOWED_ACTIONS  # noqa: E402
from harness.banner_facts import digest  # noqa: E402
from harness.exit_codes import EXIT_STARTUP_REFUSED  # noqa: E402
from scripts import run_harness  # noqa: E402

# -- the registration ------------------------------------------------------------------------------
# These four are written only by the commit that registers the shadow, authorized by the owner
# (plan section 10; items 134 and 137). Until then they are empty and the runner refuses to start.
# A real role class put into APPROVED_ROLE_CLASSES must have its module file in REGISTERED_FILES
# at the same time (checked in step 1), so that a later change to its ``propose``, ``plan`` or
# ``review`` is refused by the integrity guard.
REGISTERED_COMMIT: str | None = None
REGISTERED_FILES: tuple[str, ...] | None = None
REGISTERED_DIGESTS: Mapping[str, str] | None = None
APPROVED_ROLE_CLASSES: Mapping[str, tuple[type, ...]] = {}

#: Recorded, not compared: the runner and the entry it calls may be mended after registration.
CODE_FILES = ("scripts/run_shadow.py", "scripts/run_harness.py")

ROLES = ("worker", "supervisor", "reviewer")
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
REASONS = (
    NOT_REGISTERED, CLASS_MODULE_NOT_REGISTERED, GIT_UNAVAILABLE, TREE_NOT_CLEAN,
    REGISTERED_COMMIT_NOT_IN_HEAD, REGISTERED_FILE_MISSING, REGISTERED_FILE_DIFFERS,
    FACTORY_NOT_APPROVED, FACTORY_FAILED, ROLE_CLASS_NOT_APPROVED, ROLE_NOT_A_BASE_SUBCLASS,
    ROLE_BOUNDARY_OVERRIDDEN, DIGEST_UNAVAILABLE, DIGEST_MISMATCH,
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
         register=signal.signal) -> int:
    reg = registration if registration is not None else registered()
    problems = registration_problems(reg, repo=repo)                                     # 1
    if problems:
        return refuse(problems)
    checked = integrity(repo=repo, registered_commit=reg.commit, files=reg.files, git=git)  # 2
    if checked.problems:
        return refuse(checked.problems)
    run_argv = ["run", *(sys.argv[1:] if argv is None else argv)]
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
    return run_harness.main(run_argv, lock=lock, register=register, roles=roles)


if __name__ == "__main__":
    raise SystemExit(main())
