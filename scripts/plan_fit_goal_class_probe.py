#!/usr/bin/env python
"""Does the validator's failure rate follow the proposal's action, or the wording of the goal? (D68)

The fixed-model baseline put 32 of 49 ``code.secrets`` items in the failed column (65%) while 0 of
its 7 ordinary secrets-scan items failed. Every non-matched ``code.secrets`` item there was built
from an Active-Directory goal, so the action and the goal wording moved together. This probe
separates them with the same validator, model and fallback setting as the baseline:

* ``secrets-goal/secrets-action``: an ordinary secrets-scan goal for a secrets-scan task (matched).
* ``secrets-goal/other-action``: the same goal wording against a task for another action.
* ``ad-goal/secrets-action``: an Active-Directory goal against a secrets-scan task.
* ``ad-goal/ad-action``: an ordinary AD goal for an AD task (matched).

    PYTHONPATH=. python scripts/plan_fit_goal_class_probe.py --n 20 --out probe.json

Real calls (``claude_code``, ``--no-refusal-fallback`` always), ``4 x n`` of them.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.llm.selection import build_plan_fit_validator  # noqa: E402
from scripts.plan_fit_baseline import NO_FALLBACK_ENV, EnvelopeRecorder, run_corpus  # noqa: E402
from tests.plan_fit_corpus import (  # noqa: E402
    _ROLES_PLAIN,
    _ROLES_SENSITIVE,
    EXPECT_NOT_PLAUSIBLE,
    EXPECT_PLAUSIBLE,
    MATCHED,
    MISMATCHED,
    SCENARIOS,
    Item,
    PlanFitQuery,
    _fqdn,
)

SEED = 8201
_BY_NAME = {s[0]: s for s in SCENARIOS}
_OTHER_ACTION = ("web-get", "code-scan", "scan-host")


def build(n: int, seed: int = SEED) -> tuple[Item, ...]:
    rng = random.Random(seed)
    items: list[Item] = []

    def make(label: str, goal_scenario: str, task_scenario: str, group: str, expect: str):
        for i in range(n):
            _, _, _, templates = _BY_NAME[goal_scenario]
            host = _fqdn(rng, _ROLES_PLAIN + _ROLES_SENSITIVE)
            goal = templates[rng.randrange(len(templates))].format(t=host)
            action = _BY_NAME[task_scenario][1]
            items.append(Item(f"{label}-{i:03d}", group,
                              PlanFitQuery(goal, action, f"fqdn:{host}", action, f"fqdn:{host}"),
                              expect, scenario=label))

    make("secrets-goal/secrets-action", "code-secrets", "code-secrets", MATCHED, EXPECT_PLAUSIBLE)
    make("ad-goal/ad-action", "ad-collect", "ad-collect", MATCHED, EXPECT_PLAUSIBLE)
    for label, goal_scenario, tasks in (
            ("secrets-goal/other-action", "code-secrets", _OTHER_ACTION),
            ("ad-goal/secrets-action", "ad-collect", ("code-secrets",))):
        for i in range(n):
            task_scenario = tasks[i % len(tasks)]
            _, _, _, templates = _BY_NAME[goal_scenario]
            host = _fqdn(rng, _ROLES_PLAIN + _ROLES_SENSITIVE)
            goal = templates[rng.randrange(len(templates))].format(t=host)
            action = _BY_NAME[task_scenario][1]
            items.append(Item(f"{label}-{i:03d}", MISMATCHED,
                              PlanFitQuery(goal, action, f"fqdn:{host}", action, f"fqdn:{host}"),
                              EXPECT_NOT_PLAUSIBLE, scenario=label))
    return tuple(items)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--n", type=int, default=20, help="items per cell (4 cells)")
    parser.add_argument("--model", default="sonnet")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    items = list(build(args.n))
    # interleaved: the cells that the classifier stops are most of a run when they come in a row,
    # and a run of failures is what the baseline runner's own guard reads as a dead backend
    random.Random(SEED).shuffle(items)
    recorder = EnvelopeRecorder(env={NO_FALLBACK_ENV: "1"})
    validator = build_plan_fit_validator("claude_code", model=args.model, runner=recorder)
    records = run_corpus(validator, tuple(items), envelopes=recorder.envelopes,
                         stop_after_failures=None,
                         checkpoint=args.out.with_suffix(".jsonl"))
    by = {i.item_id: i for i in items}
    table: dict[str, Counter] = {}
    for r in records:
        cell = by[r["item_id"]].scenario
        table.setdefault(cell, Counter())["failed" if r["call_failed"] else r["goal_fit"]] += 1
    for cell, c in table.items():
        n = sum(c.values())
        print(f"{cell}: failed {c['failed']}/{n}  answers {dict(c)}")
    args.out.write_text(json.dumps({"table": {k: dict(v) for k, v in table.items()},
                                    "records": records}, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
