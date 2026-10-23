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
    from agents.base_agent import GOAL_FIT_VALUES
    from agents.llm.selection import build_plan_fit_validator
    from scripts.plan_fit_baseline import run_corpus
    from tests.plan_fit_corpus import MATCHED, build_corpus

    # the baseline script is the one sanctioned caller of a validator outside the control plane
    # (tests/test_plan_fit_baseline.py), so the call goes through its runner, which also records a
    # raised error as a failed call and never lets it escape
    item = next(i for i in build_corpus() if i.group == MATCHED
                and i.query.proposal_action == "network.scan")
    validator = build_plan_fit_validator()
    started = time.monotonic()
    record = run_corpus(validator, (item,))[0]
    seconds = round(time.monotonic() - started, 1)
    print(f"backend {backend}: goal_fit={record['goal_fit']} cause={record['cause']} "
          f"in {seconds}s")
    if record["goal_fit"] not in GOAL_FIT_VALUES:
        print("the validator did not answer: a Q1 soak would record nothing but failures",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
