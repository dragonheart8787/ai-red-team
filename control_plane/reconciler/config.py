"""The reconciler's thresholds: every one from configuration, none with a default (D64-3, D64-5).

A time bound is not a number to type into the code (docs/D64_RECONCILER_DESIGN.md §1.2): it is a
budget plus terms read from client timeouts. So this module holds **no value**. ``load()`` reads
``RECONCILER_*`` settings from the environment (``.env.example`` lists the recommended values with
the derivation of each) and refuses -- with one error naming **every** missing or unusable key, not
the first -- when any is absent, not a whole number of seconds, not positive, or below the lower
bound the code itself implies:

* ``B_CAP_S`` is at least the Rego ceiling (``control_plane.policy.ceiling``): a cap *below* what
  the policy lets a capability ask for would judge a legal run overdue;
* ``P_PROXY_S`` is at least the Docker calls a dispatch with an egress proxy makes before its
  container runs, times the Docker client's timeout, plus the proxy's 15 s readiness wait; and
  ``Q_PROXY_S`` at least the calls after it -- counts read from ``tool_gateway/sandbox.py``, so a
  setting cannot undercut the code it describes. (The proxy bounds are the longer ones, and the
  database does not say which kind of run a row is, so they are the only ones used.)
* ``STAGE_GRACE_S`` is at least twice the longest honest decision stage (150 s): a live caller is
  never abandoned (D64 §1.8).

The refusal is the point: a reconciler that guessed a missing threshold would kill or close
something on a number nobody chose. ``Thresholds`` is frozen; the plan receives it as an argument.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields

from docker.constants import DEFAULT_TIMEOUT_SECONDS

from control_plane.policy.ceiling import MAX_DURATION_CEILING_SECONDS

#: docker-py's own client timeout: the unit the bounds below count in.
DOCKER_CALL_TIMEOUT_S = DEFAULT_TIMEOUT_SECONDS

PREFIX = "RECONCILER_"

#: Docker calls a dispatch makes before its container runs / after it (D64 §1.2, read from
#: ``DockerSandbox.run``): an ordinary run, and a run with an egress proxy (which adds the target
#: network, the proxy's own create/connect/start and a readiness wait of 15 s).
DOCKER_CALLS_BEFORE_PROXY = 15
PROXY_READINESS_S = 15
DOCKER_CALLS_AFTER_PROXY = 5

#: The longest an honest decision stage takes (reviewer 120 s + OPA 30 s) -- D64 §1.8.
DECISION_STAGE_FLOOR_S = 150


@dataclass(frozen=True)
class Thresholds:
    """Whole numbers: seconds, except ``max_pages`` and ``max_actions_per_pass``, which are counts.
    Field order is the documentation order."""

    #: ``received`` / ``decided`` for this long -> abandoned / closed (``abandoned_after_decision``)
    stage_grace_s: int
    #: a lapsed lease is closed this long after ``lease_expires_at``
    lease_grace_s: int
    #: an approval is expired this long after ``valid_until``
    approval_grace_s: int
    #: the cap on a budget's ``max_duration_seconds``
    b_cap_s: int
    #: the longest a dispatch spends before its container runs / after it ended, for a run with an
    #: egress proxy -- the longer bound, and the database does not say which kind a run is
    p_proxy_s: int
    q_proxy_s: int
    #: the longest the control plane's own ``kill()`` is allowed
    kill_margin_s: int
    #: an exited or never-started container is kept this long (its output is the only evidence)
    retention_s: int
    #: a network with no container of any state attached is idle after this long
    network_idle_s: int
    #: the sweep of idle networks runs this often (6d); recorded here so that it is configured too
    network_sweep_period_s: int
    #: after a kill, a removal or an unlink, how long the act half waits for the change to be seen
    #: before it calls the action failed (the act half, 6c)
    verify_wait_s: int
    #: the failure summary is written at most this often, and only if something failed (the
    #: service, 6d)
    summary_period_s: int
    #: a kill, a removal or an unlink that failed is not tried again on the same object by this
    #: process for this long (the service, D64 item 4): each attempt writes an intent and makes a
    #: Docker call, and a persistently failing object would otherwise do both every pass
    retry_after_failure_s: int
    #: the most pages of ``reconciler_stuck_proposals`` one pass reads (5,000 rows each); when the
    #: last is still full the pass says its read was truncated and leaves the rest for the next one
    max_pages: int
    #: the most actions one pass carries out; the rest is planned again by the next pass. A backlog
    #: (after an outage, or a development database) is worked off in bounded passes that can be
    #: stopped between, not in one long one
    max_actions_per_pass: int
    #: after a pass that was truncated or limited and still got nothing done, the wait before the
    #: next doubles, up to this; any pass that is neither resets it
    backoff_max_s: int

    # -- derived bounds (D64 §1.2): functions of the configured terms, never configured themselves
    # --
    def budget_s(self, max_duration_s: int) -> int:
        """``B = min(budget, B_cap)``."""
        return min(max_duration_s, self.b_cap_s)

    def unknown_after_s(self, max_duration_s: int) -> int:
        """``B + P + Q`` with the proxy terms -- the longest honest driver; the proxy bound is the
        longer, and the database does not say which a run is (the allowlist is an array)."""
        return self.budget_s(max_duration_s) + self.p_proxy_s + self.q_proxy_s

    def kill_after_s(self, max_duration_s: int) -> int:
        """A container still running this long after Docker's ``StartedAt`` outlived its owner."""
        return self.budget_s(max_duration_s) + self.kill_margin_s

    def proxy_overdue_after_s(self, max_duration_s: int) -> int:
        """The proxy starts before the tool container (up to ``P`` earlier)."""
        return self.kill_after_s(max_duration_s) + self.p_proxy_s

    def file_age_s(self) -> int:
        """``B_cap + P + Q``: the longest legal run plus a dispatch's own margin (D64-12)."""
        return self.b_cap_s + self.p_proxy_s + self.q_proxy_s


KEYS = tuple(f"{PREFIX}{f.name.upper()}" for f in fields(Thresholds))


class ConfigError(Exception):
    """The reconciler's configuration is unusable. ``problems`` names every key at fault."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("reconciler configuration refused:\n  " + "\n  ".join(problems))


def minimums() -> dict[str, int]:
    """The lower bound the code implies for each key (the rest only need to be positive)."""
    return {
        "b_cap_s": MAX_DURATION_CEILING_SECONDS,
        "p_proxy_s": DOCKER_CALLS_BEFORE_PROXY * DOCKER_CALL_TIMEOUT_S + PROXY_READINESS_S,
        "q_proxy_s": DOCKER_CALLS_AFTER_PROXY * DOCKER_CALL_TIMEOUT_S,
        "stage_grace_s": 2 * DECISION_STAGE_FLOOR_S,
    }


def load(env: Mapping[str, str]) -> Thresholds:
    """Thresholds from ``env``; ``ConfigError`` naming every problem if any key is unusable."""
    floors = minimums()
    values: dict[str, int] = {}
    problems: list[str] = []
    for f in fields(Thresholds):
        key = f"{PREFIX}{f.name.upper()}"
        raw = env.get(key)
        if raw is None or not raw.strip():
            problems.append(f"{key}: missing (there is no default)")
            continue
        text = raw.strip()
        if not text.isascii() or not text.isdigit():
            problems.append(f"{key}: not a whole number")
            continue
        number = int(text)
        if number < 1:
            problems.append(f"{key}: must be positive")
            continue
        if number < floors.get(f.name, 1):
            problems.append(
                f"{key}: {number} is below {floors[f.name]}, the least the code implies")
            continue
        values[f.name] = number
    if problems:
        raise ConfigError(problems)
    return Thresholds(**values)
