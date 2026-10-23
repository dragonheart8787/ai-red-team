#!/usr/bin/env python
"""The required checks at enablement of P1 and Q1 (D68 plan section 8.1), executed, with output.

    PYTHONPATH=. python scripts/s8_enablement_check.py --switch p1 --engagement ENG-1 \\
        [--engagement ENG-2 ...]
    PYTHONPATH=. python scripts/s8_enablement_check.py --switch q1 --engagement ENG-1

Two conditions together, or a loud failure; never a quiet "nothing happens":

* **P1** -- ``task_relation_enforce`` is true in the effective policy of each engagement named (a
  switch published to a layer that does not reach an engagement is the silent no-op), *and* the
  stored decisions carry a ``plan_fit`` (the comparison is running).
* **Q1** -- ``goal_fit_enforce`` is true in the effective policy, *and* a validator is configured
  (``CYBERORCH_PLANFIT_BACKEND`` names a real backend, not ``fake``), *and* the stored decisions
  carry a ``goal_fit`` other than ``not_assessed/disabled`` -- zero of those while proposals flow is
  "enabled and doing nothing". Also reported, because DP-14 does not cover it otherwise: a model
  other than the measured ``sonnet`` and the CLI's refusal fallback left on.

Exit status 0 only when every condition holds; 1 on any anomaly, each printed. It reads, and writes
nothing. Before any proposal has been decided only the switch and the configuration are judged, and
the output says that the rest was not.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PLANFIT_BACKEND_ENV = "CYBERORCH_PLANFIT_BACKEND"
PLANFIT_MODEL_ENV = "CYBERORCH_PLANFIT_MODEL"
NO_FALLBACK_ENV = "CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK"
#: What DP-14 was set from (``docs/D68_S7_FIXED_MODEL_REPORT.md``): the alias ``sonnet`` and the
#: CLI's refusal fallback off. The validator's own default model is ``opus`` and the CLI's default
#: is to fall back to a second model when the service's classifier stops a turn; neither was
#: measured.
MEASURED_MODEL = "sonnet"
FAKE = "fake"
#: ``not_assessed`` with this cause is what a proposal records when no validator was passed
DISABLED = "not_assessed/disabled"


def verdict_p1(*, switches: dict[str, bool], decided: int, with_plan_fit: int) -> list[str]:
    """Anomalies of a P1 enablement (empty: none). ``switches`` is the effective switch by
    engagement."""
    problems = [f"P1: task_relation_enforce is not true in the effective policy of {e} "
                "(published somewhere that does not reach it)"
                for e, on in sorted(switches.items()) if not on]
    if not switches:
        problems.append("P1: no engagement was named, so no effective policy was read")
    if decided and not with_plan_fit:
        problems.append(f"P1: {decided} decided proposals and none with a stored plan_fit: the "
                        "comparison is not running")
    return problems


def config_problems(*, backend: str | None, model: str | None,
                    fallback_off: str | None) -> list[str]:
    """The validator's configuration against the one DP-14's numbers belong to. Only for the
    ``claude_code`` backend (the one measured); another backend is itself a difference."""
    name = (backend or "").strip().lower()
    if name in ("", "fake"):
        return []
    out = []
    if name != "claude_code":
        out.append(f"Q1: backend {name!r} was not measured; DP-14 was set on claude_code")
    elif (model or "").strip().lower() != MEASURED_MODEL:
        out.append(f"Q1: the validator model is {model!r} ({PLANFIT_MODEL_ENV}); DP-14 was "
                   f"measured on {MEASURED_MODEL!r}, and the validator's own default is another")
    if name == "claude_code" and (fallback_off or "").strip() != "1":
        out.append(f"Q1: {NO_FALLBACK_ENV} is not 1; DP-14 was measured with the CLI's refusal "
                   "fallback off, and with it on a stopped call is answered by a second model")
    return out


def verdict_q1(*, switches: dict[str, bool], backend: str | None, goal_fit: Counter,
               decided: int, model: str | None = MEASURED_MODEL,
               fallback_off: str | None = "1") -> list[str]:
    """Anomalies of a Q1 enablement. ``goal_fit`` counts ``value/cause`` over stored decisions."""
    problems = [f"Q1: goal_fit_enforce is not true in the effective policy of {e}"
                for e, on in sorted(switches.items()) if not on]
    if not switches:
        problems.append("Q1: no engagement was named, so no effective policy was read")
    name = (backend or "").strip().lower()
    if not name or name == FAKE:
        problems.append(f"Q1: no validator is configured ({PLANFIT_BACKEND_ENV}="
                        f"{backend!r}); the switch would be on and every proposal would record "
                        f"{DISABLED}")
    problems += config_problems(backend=backend, model=model, fallback_off=fallback_off)
    answered = sum(n for key, n in goal_fit.items()
                   if key != DISABLED and not key.startswith("absent"))
    if decided and not answered:
        problems.append(f"Q1: {decided} decided proposals and none with a goal_fit other than "
                        f"{DISABLED}: enabled and doing nothing")
    return problems


def read(engagements: list[str]) -> dict[str, Any]:
    from sqlalchemy import text

    from control_plane.plan_fit import relation as r
    from control_plane.policy.layers import load_effective_policy
    from control_plane.state.db import engagement_scope

    out: dict[str, Any] = {"p1": {}, "q1": {}, "decided": 0, "with_plan_fit": 0,
                           "goal_fit": Counter()}
    for eid in engagements:
        with engagement_scope(eid) as conn:
            policy = load_effective_policy(conn, eid)
            out["p1"][eid] = bool(policy.task_relation_enforce)
            out["q1"][eid] = bool(policy.goal_fit_enforce)
            rows = conn.execute(text(
                "SELECT reviewer_hints->'plan_fit' AS plan_fit FROM action_proposals "
                "WHERE decision IS NOT NULL")).mappings().all()
        for row in rows:
            out["decided"] += 1
            if isinstance(row["plan_fit"], dict):
                out["with_plan_fit"] += 1
                signal = r.policy_signal(row["plan_fit"])
                if "goal_fit" in signal:
                    out["goal_fit"][f"{signal['goal_fit']}/{signal['goal_fit_cause'] or '-'}"] += 1
                else:
                    out["goal_fit"]["absent (decided before Q1)"] += 1
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--switch", choices=("p1", "q1"), required=True)
    parser.add_argument("--engagement", action="append", required=True)
    args = parser.parse_args(argv)
    from control_plane.config import load_dotenv

    load_dotenv()
    seen = read(args.engagement)
    print(f"switch {args.switch}: effective in {seen[args.switch]}")
    print(f"decided proposals read: {seen['decided']}; with a stored plan_fit: "
          f"{seen['with_plan_fit']}; goal_fit values: {dict(seen['goal_fit'])}")
    if args.switch == "p1":
        problems = verdict_p1(switches=seen["p1"], decided=seen["decided"],
                              with_plan_fit=seen["with_plan_fit"])
    else:
        problems = verdict_q1(switches=seen["q1"], backend=os.environ.get(PLANFIT_BACKEND_ENV),
                              goal_fit=seen["goal_fit"], decided=seen["decided"],
                              model=os.environ.get(PLANFIT_MODEL_ENV),
                              fallback_off=os.environ.get(NO_FALLBACK_ENV))
    if not seen["decided"]:
        print("no decided proposal yet: only the switch and the configuration were judged")
    for problem in problems:
        print(f"ANOMALY: {problem}", file=sys.stderr)
    print("OK: every condition holds" if not problems else f"{len(problems)} anomaly(ies)")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
