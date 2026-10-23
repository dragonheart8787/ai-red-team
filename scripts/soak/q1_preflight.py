#!/usr/bin/env python
"""One real call to the configured goal-fit validator, before a Q1 soak starts (D68 S8b).

A Q1 soak whose validator cannot answer (no CLI on the runner, no login, a rate-limited account)
would run four hours to say so. This asks once, for an ordinary matched item, and exits 0 only when
the validator gave one of the three words. It reads the backend from ``CYBERORCH_PLANFIT_BACKEND``
(what the soak will use) and writes nothing.

    PYTHONPATH=. python -m scripts.soak.q1_preflight
"""

from __future__ import annotations

import os
import sys
import time

from scripts.soak import lib


def main() -> int:
    lib.load_env()
    backend = os.environ.get("CYBERORCH_PLANFIT_BACKEND", "").strip().lower()
    if not backend or backend == "fake":
        print("no validator is configured (CYBERORCH_PLANFIT_BACKEND)", file=sys.stderr)
        return 2
    from agents.base_agent import GOAL_FIT_VALUES, PlanFitQuery
    from agents.llm.selection import build_plan_fit_validator

    validator = build_plan_fit_validator()
    query = PlanFitQuery(
        goal="Scan 10.66.252.20 for open ports and the services behind them",
        task_action="network.scan", task_target="ip:10.66.252.20",
        proposal_action="network.scan", proposal_target="ip:10.66.252.20")
    started = time.monotonic()
    try:
        result = validator.assess(query=query)
    except Exception as exc:  # noqa: BLE001 - the point is to say what went wrong
        print(f"the validator raised {type(exc).__name__}: {str(exc)[:300]}", file=sys.stderr)
        return 1
    seconds = round(time.monotonic() - started, 1)
    print(f"backend {backend}: goal_fit={result.goal_fit} cause={result.cause} in {seconds}s")
    if result.goal_fit not in GOAL_FIT_VALUES:
        print("the validator did not answer: a Q1 soak would record nothing but failures",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
