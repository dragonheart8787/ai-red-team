#!/usr/bin/env python
"""The corpus's matched group, asked sequentially here, beside S7's numbers (D68 S8b).

The first Q1 smokes failed on about half of the soak's ordinary ``network.scan`` proposals in CI
-- every one a safety-classifier stop -- while the same validator on the development machine failed
on ``network.scan`` 0 of 16 matched items, as in S7. Whether the CI environment itself does this
(the runner's egress, the OAuth-token path), or only the soak's and the stream's own inputs and
concurrency do, is separated by asking the *same 60 items* here, one after another, before the
soak starts.

``--run`` makes the pass through the baseline runner (the one sanctioned caller of a validator
outside the control plane; this module is what the soak workflow names, as it names the
pre-flight, so that a Q1 soak the owner asked for is the only place a workflow reaches a model --
``tests/test_plan_fit_baseline.py`` keeps the baseline script out of every workflow by name).

    PYTHONPATH=. python -m scripts.soak.q1_ci_matched --record ci_matched.json --run [--out t.md]
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from control_plane.plan_fit.shadow import fmt, rate
from tests.plan_fit_corpus import MATCHED, build_corpus, by_id

S7_RECORD = (Path(__file__).resolve().parents[2]
             / "docs/D68_S7_BASELINE/fixed_model/pass1_fixed.json")


def per_action(records: list[dict]) -> dict[str, list[int]]:
    """``{action: [failed, n]}`` over the matched items among ``records``."""
    items = by_id(build_corpus())
    out: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for record in records:
        item = items[record["item_id"]]
        if item.group != MATCHED:
            continue
        action = item.query.proposal_action
        out[action][0] += bool(record.get("call_failed"))
        out[action][1] += 1
    return dict(out)


def render(here: dict[str, list[int]], s7: dict[str, list[int]]) -> str:
    lines = ["## The corpus's matched group, here and in S7", "",
             "| action | S7 (dev machine, 2026-10-22) | this environment |", "|---|---|---|"]
    for action in sorted(set(here) | set(s7)):
        a, b = s7.get(action, [0, 0]), here.get(action, [0, 0])
        lines.append(f"| {action} | {fmt(rate(*a))} | {fmt(rate(*b))} |")
    ta = [sum(v[0] for v in s7.values()), sum(v[1] for v in s7.values())]
    tb = [sum(v[0] for v in here.values()), sum(v[1] for v in here.values())]
    lines += [f"| **all matched** | {fmt(rate(*ta))} | {fmt(rate(*tb))} |", "",
              "S7's `network.scan` was 0 of 16. Here, `network.scan` "
              f"{here.get('network.scan', [0, 0])[0]} of {here.get('network.scan', [0, 0])[1]}."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--run", action="store_true",
                        help="make the pass first (60 real calls, sequential, the measured "
                             "configuration), writing --record")
    args = parser.parse_args(argv)
    if args.run:
        from scripts import plan_fit_baseline

        plan_fit_baseline.main([
            "--backend", "claude_code", "--model", "sonnet", "--no-refusal-fallback",
            "--group", "matched", "--max-calls", "100", "--stop-after-failures", "0",
            "--json", str(args.record)])
    here = per_action(json.loads(args.record.read_text())["records"])
    s7 = per_action(json.loads(S7_RECORD.read_text())["records"])
    text = render(here, s7)
    print(text)
    if args.out:
        args.out.write_text(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
