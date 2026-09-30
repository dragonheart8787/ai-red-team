"""Gitleaks adapter -- secrets in a repository's git history (D55).

``code.secrets`` is the second tool of the D43 code-scan family and the first
onboarded through ``scripts/new_tool_scaffold.py`` (D53). It shares Semgrep's
shape -- a ``repo`` scope object (``<location>#<branch>``), a control-plane-side
fetch, a read-only mount, a container with no network -- and differs in the ways
``docs/ADR_GITLEAKS.md`` works through. The three that shape this module:

* **The input is history, not a tree.** The repository is fetched as a *bare,
  shallow-to-depth-N, single-branch* clone (``FETCH_BARE``, ``history_depth``).
  Bare so that no working tree exists for the repository to plant files in; the
  three ways a scanned repository can tell Gitleaks to ignore its own secrets
  (``.gitleaks.toml``, ``.gitleaksignore``, an inline ``gitleaks:allow``) are
  otherwise all *read from the thing being audited*. Single-branch so that
  authorizing ``repo#main`` does not scan a branch nobody authorized.
* **The finding is the secret.** Semgrep's output is code that *might* hold a
  secret, and D43-4 redacts it after the fact with a heuristic. Gitleaks'
  output *is* a suspected secret, and it knows exactly which bytes: ``--redact``
  removes them inside the container, so the raw artifact never contains the
  value, and :func:`derive_view` shows a model no source text and no commit
  metadata at all.
* **"No findings" is not "clean".** Confirmed against the real binary: when git
  cannot read the repository (``detected dubious ownership``) Gitleaks logs an
  error, prints ``[]``, reports ``no leaks found`` and exits 0 -- with
  ``--exit-code 0`` or without. The exit code cannot tell a clean repository from
  an unreadable one, so :func:`scan_incomplete_reason` reads the tool's own
  summary and a run that cannot show it read the repository is not recorded as
  a success (and is therefore never served from the dedup cache as one).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from control_plane.evidence.redaction import redact_snippet

TOOL = "gitleaks"
ACTION = "code.secrets"
IMAGE = "cyberorch/gitleaks:local"

#: Pinned exactly, and kept equal to the ``GITLEAKS_VERSION`` default in
#: tool_gateway/images/build_gitleaks_image.sh (tests/test_gitleaks_adapter.py
#: reads both). ``tool_version()`` returns this constant and never runs a
#: binary on the control-plane host: the tool lives in the image, not on this
#: machine (D43 ab2849a).
GITLEAKS_VERSION = "8.30.1"

#: Reading a repository's objects changes nothing about it: the mount is
#: read-only, and no verb in the built command writes anywhere but the report
#: on stdout.
WRITES_DATA = False
CHANGES_STATE = False

#: No network at all -- the repository arrives as a read-only bind mount, fetched
#: by the control plane (D43-5 Option B). The container is given no route, so
#: there is nothing for the D34 proxy to mediate.
REQUIRES_PROXY = False

#: The same bespoke dispatch as Semgrep: a control-plane git fetch before the
#: sandbox run and cleanup after it. ``dispatch_code_scan`` serves both tools.
NEEDS_DISPATCH = "dispatch_code_scan"

#: Gitleaks itself writes nothing (it reports on stdout); git wants a $HOME to
#: look for a global config in. Both are tmpfs so the read-only root stays read-only.
TMPFS = {"/home/gitleaks": "rw,mode=1777", "/tmp": "rw,mode=1777"}

TOOL_STOP_GRACE_SECONDS = 5

#: Where the sandbox mounts the fetched bare repository and the pinned config.
CONTAINER_REPO_PATH = "/repo"
CONTAINER_RULESET_PATH = "/rules/gitleaks.toml"

DEFAULT_RULESET_HOST_PATH = str(
    Path(__file__).resolve().parent.parent / "rulesets" / "gitleaks.toml"
)

#: How the fetch must be made for this tool (read by dispatch_code_scan; an
#: adapter that does not declare them gets Semgrep's depth-1 working-tree clone).
FETCH_BARE = True

#: History depth, in commits, counted back from the tip of the authorized branch.
#: A constraint, not a scope: D43-2 refused sub-repo containment, and *how far
#: back to look* is a property of one scan. It is a fingerprint dimension (a
#: deeper scan sees more), and the derived view says whether the history was cut
#: (``history_complete``) because "no findings in the last 100 commits" is not
#: "no findings".
DEFAULT_HISTORY_DEPTH = 100
MAX_HISTORY_DEPTH = 10_000

#: Findings carried in full detail in the derived view (D40/5.21).
DEFAULT_NOTABLE_FINDING_LIMIT = 10

_MAX_PATH_CHARS = 200
_RULE_ID = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_COMMITS_SCANNED = re.compile(r"\b(\d+) commits scanned\b")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


class AdapterError(ValueError):
    """The capability cannot be turned into a run of this tool."""


@dataclass(frozen=True)
class GitleaksPlan:
    """What will actually be executed, before it is executed."""

    command: tuple[str, ...]
    target: str
    history_depth: int
    max_duration_seconds: int

    @property
    def fetch_depth(self) -> int:
        """The depth ``dispatch_code_scan`` clones to -- one fact, one authority."""
        return self.history_depth

    def as_params(self) -> dict[str, Any]:
        """Normalized parameters for the §7 execution fingerprint.

        ``history_depth`` is here because a deeper scan sees commits a shallower
        one did not, so the second is a different scan of the same target. The
        tip commit, the branch and the pinned config are not ``build_plan``
        inputs and are folded in elsewhere (``execution_context`` and
        ``ruleset_version``). ``max_duration_seconds`` is absent: a budget change
        is not a different scan -- true here because it only bounds how long the
        container may run, and a timeout is a failed run, never a partial one.
        """
        return {"target": self.target, "history_depth": self.history_depth}


def tool_version() -> str:
    """The pinned version, for the §7 fingerprint. Never a host probe."""
    return f"{TOOL}-{GITLEAKS_VERSION}"


def ruleset_version(ruleset_path: str | None = None) -> str:
    """A content hash of the pinned config -- never a hand-maintained number.

    The reasoning is Semgrep's (D11-3: a version somebody must remember to bump
    is a version somebody forgets). What this hashes is only the config file; the
    default rules live in the binary and are covered by ``tool_version()``.
    """
    path = Path(ruleset_path or DEFAULT_RULESET_HOST_PATH)
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def build_plan(
    *, constraints: Mapping[str, Any], budget: Mapping[str, Any], target: str,
) -> GitleaksPlan:
    """Turn a capability into a scan command.

    ``target`` is the ``repo`` scope object's value, ``<location>#<branch>``
    (D43-1). Only ``history_depth`` is read from ``constraints``; there is no
    ``exclude_paths`` here on purpose -- a scan that can be told to skip a path is
    a scan that can be told to skip the path that holds the secret, and nothing
    about D43-2's refusal of containment argues the other way.
    """
    if not target:
        raise AdapterError("no target")
    if "#" not in target:
        raise AdapterError(
            f"invalid repo target {target!r}: expected '<location>#<branch>' (D43-1)"
        )

    max_duration = int(budget.get("max_duration_seconds", 600))
    if max_duration <= 0:
        raise AdapterError("max_duration_seconds must be positive")

    depth = constraints.get("history_depth")
    if depth is None:
        depth = DEFAULT_HISTORY_DEPTH
    if isinstance(depth, bool) or not isinstance(depth, int) or not 1 <= depth <= MAX_HISTORY_DEPTH:
        raise AdapterError(
            f"history_depth must be an integer from 1 to {MAX_HISTORY_DEPTH}, got {depth!r}"
        )

    # Every flag here is a decision, and none is a value a caller may omit:
    #   git <path>              history, not a filesystem walk (``dir``) -- the
    #                           point of the tool is the secret that was removed.
    #   --config                the pinned config; a scanned repo's own
    #                           .gitleaks.toml never applies.
    #   --redact=100            the secret never leaves the container (D43-4, and
    #                           stronger: exact, made by the tool that found it).
    #   --ignore-gitleaks-allow an inline ``gitleaks:allow`` in the repository's
    #                           own content does not suppress its own finding.
    #   --exit-code 0           the exit code says nothing here (module docstring);
    #                           completeness is read from the tool's summary.
    #   --no-banner --no-color  a banner is text the reader did not ask for, and
    #                           colour codes would corrupt the summary parse.
    #   --log-level info        the "N commits scanned" summary is what proves the
    #                           repository was read; pinned so a default change
    #                           cannot silently remove it.
    command = [
        "/usr/bin/gitleaks", "git", CONTAINER_REPO_PATH,
        "--config", CONTAINER_RULESET_PATH,
        "--redact=100",
        "--ignore-gitleaks-allow",
        "--exit-code", "0",
        "--no-banner", "--no-color",
        "--log-level", "info",
        "--report-format", "json",
        "--report-path", "-",
    ]
    return GitleaksPlan(
        command=tuple(command), target=target, history_depth=depth,
        max_duration_seconds=max_duration,
    )


def _parse_report(stdout: str) -> list[dict[str, Any]] | None:
    """The findings, or ``None`` if stdout is not a Gitleaks JSON report."""
    try:
        doc = json.loads(stdout)
    except ValueError:
        return None
    if not isinstance(doc, list) or not all(isinstance(item, dict) for item in doc):
        return None
    return doc


def _commits_scanned(stderr: str) -> int | None:
    found = _COMMITS_SCANNED.search(_ANSI.sub("", stderr))
    return int(found.group(1)) if found else None


def _error_lines(stderr: str) -> int:
    return sum(1 for line in _ANSI.sub("", stderr).splitlines() if re.search(r"\bERR\b", line))


def scan_incomplete_reason(stdout: str, stderr: str) -> str | None:
    """Why this run cannot be taken as "the repository was read", or ``None``.

    Read by ``dispatch_code_scan`` (an adapter may declare it): a run with a
    reason is recorded ``FAILED``, not ``SUCCEEDED``, so an unreadable repository
    is neither a clean bill of health in the evidence nor a dedup hit for the next
    proposal. Fail-closed on absence -- a run whose summary line is missing is
    treated as unreadable, because the alternative reading of a missing line is
    "the tool did not finish".
    """
    if _parse_report(stdout) is None:
        return "unparseable_report"
    if _error_lines(stderr):
        return "tool_reported_errors"
    scanned = _commits_scanned(stderr)
    if scanned is None:
        return "no_scan_summary"
    if scanned == 0:
        return "no_commits_scanned"
    return None


def _safe_rule_id(value: object) -> str:
    return value if isinstance(value, str) and _RULE_ID.match(value) else "invalid-rule-id"


def _safe_commit(value: object) -> str:
    return value if isinstance(value, str) and _COMMIT_SHA.match(value) else "invalid-commit"


def _safe_path(value: object) -> str:
    """A file name is written by whoever committed it, so it is text a model reads.

    Bounded, and passed through the same redactor as any other snippet: a file
    *named* like a credential is a way to put one into evidence.
    """
    if not isinstance(value, str):
        return "invalid-path"
    return redact_snippet(value[:_MAX_PATH_CHARS]).text


def _safe_int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _history_complete(repo_local_path: str) -> bool | None:
    """``False`` when the clone was cut by ``history_depth``; ``None`` if unknown.

    A shallow repository records its cut in a top-level ``shallow`` file; a clone
    deeper than the branch's history has none. Read from the fetched directory
    rather than passed in, so the answer cannot disagree with what was scanned.
    """
    if not os.path.isdir(repo_local_path):
        return None
    return not os.path.exists(os.path.join(repo_local_path, "shallow"))


def derive_view(
    stdout: str, stderr: str, *,
    repo_local_path: str, notable_finding_limit: int = DEFAULT_NOTABLE_FINDING_LIMIT,
) -> dict[str, Any]:
    """The §4.4 derived view -- the only thing a model is shown.

    What it carries, per finding: the rule that fired, where (file, line), and
    which commit -- enough to open the repository and look, and nothing a model
    could act on beyond that. What it deliberately does **not** carry:

    * ``Match`` / ``Secret`` -- redacted by the tool already (``--redact=100``);
      omitted anyway, because the view has no use for a placeholder and a
      future change to the flag must not change what a model sees.
    * ``Message`` / ``Author`` / ``Email`` -- the free text and the identities of
      whoever committed. They are the widest channel through which a third party
      can write into this output (anyone whose commit reached the branch), and
      they say nothing about whether a secret is real. They stay in the raw
      artifact; the view is a strict subset.
    * ``Description`` and ``Tags`` -- rule metadata; ``RuleID`` identifies it.
    * ``stderr`` -- counts only. A tool's error text can quote paths and refs.

    The two D43-4 axes carry over unchanged and stay separate:
    ``untrusted_content`` (a path is attacker-chosen text) and
    ``first_party_source_content`` (this is the customer's own repository's
    secret inventory). What is different from Semgrep is *where* redaction
    happens, not which markers apply.
    """
    findings = _parse_report(stdout)
    reason = scan_incomplete_reason(stdout, stderr)
    findings = findings or []

    by_rule: dict[str, int] = {}
    for f in findings:
        rule = _safe_rule_id(f.get("RuleID"))
        by_rule[rule] = by_rule.get(rule, 0) + 1

    notable = []
    for f in findings[:notable_finding_limit]:
        entropy = f.get("Entropy")
        notable.append({
            "rule_id": _safe_rule_id(f.get("RuleID")),
            "path": _safe_path(f.get("File")),
            "start_line": _safe_int(f.get("StartLine")),
            "commit": _safe_commit(f.get("Commit")),
            "entropy": round(float(entropy), 2)
            if isinstance(entropy, (int, float)) and not isinstance(entropy, bool) else None,
        })

    return {
        "untrusted_content": True,
        "first_party_source_content": True,
        "scan_complete": reason is None,
        "incomplete_reason": reason,
        "commits_scanned": _commits_scanned(stderr),
        "history_complete": _history_complete(repo_local_path),
        "finding_count": len(findings),
        "findings_by_rule": by_rule,
        "notable_findings": notable,
        "omitted_findings": max(len(findings) - len(notable), 0),
    }
