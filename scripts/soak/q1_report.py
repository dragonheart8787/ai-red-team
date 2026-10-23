#!/usr/bin/env python
"""The Q1 stream's result: failure rate by action class and by goal wording (D68 S8b).

    PYTHONPATH=. python -m scripts.soak.q1_report --stream q1_stream.jsonl --out q1_report.md \\
        [--soak-run soak-run]

Reads the stream's journal (which cell and wording each proposal had) and the database (what the
validator answered, stored with each decision: ``reviewer_hints.plan_fit.goal_fit``), and prints
what happened, by action class, with the wording of the goal as a second axis.

**The judgement being tested, written down before the data (D68 S7, ACCEPTANCE 5.118):** the
failures of the goal-fit validator follow the *wording of the goal* -- Active-Directory collection
language is a general trigger of the service's safety-classifier stop -- and not the action class,
`code.secrets` in particular. It is read as *holding* if (1) the Wilson upper bound of the failure
rate over secrets-scan-wording goals (natural ``code.secrets`` plus the crossed ``ad.collect``
cell) is below the Wilson lower bound of the rate over AD-wording goals (natural ``ad.collect``
plus the crossed ``code.secrets`` cell), (2) the same holds for natural ``code.secrets`` alone, and
(3) what S7 predicted for secrets-scan wording is not contradicted: its failure rate (1 of 40 in
the S7 probe, 95% upper bound 12.9%) -- the Wilson *lower* bound of natural ``code.secrets`` must
not exceed 12.9%. (3) is there because (1) and (2) compare against AD wording and would pass a
`code.secrets` rate of 60% beside an AD rate of 85%. Otherwise the judgement is reported as not
established or not holding, with the numbers; nothing is relaxed to make it hold.
"""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from control_plane.plan_fit.shadow import fmt, rate

SECRETS, AD = "code-secrets", "ad-collect"
#: the S7 probe's upper 95% bound for secrets-scan wording (1 failure in 40 calls)
S7_SECRETS_UPPER = 0.129


def wilson(k: int, n: int) -> tuple[float, float]:
    """The 95% Wilson interval for ``k`` of ``n`` (``(0, 1)`` for no data)."""
    if n <= 0:
        return 0.0, 1.0
    z, p = 1.96, k / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    scale = 1 + z * z / n
    return max(0.0, (centre - margin) / scale), min(1.0, (centre + margin) / scale)


def outcome(goal_fit: str | None, cause: str | None) -> str:
    """One word per stored answer: an answer, or why there is none."""
    if not goal_fit:
        return "absent"
    if goal_fit == "not_assessed":
        return f"not_assessed/{cause or '?'}"
    return goal_fit


def failed(label: str) -> bool:
    return label == "not_assessed/failed"


def tabulate(items: list[dict[str, Any]]) -> dict[str, Any]:
    """``items``: dicts with ``action``, ``cell``, ``goal_wording`` and ``outcome``. Groups by
    (cell, action) and by wording; every proposal is in exactly one of each."""
    by_cell: dict[tuple[str, str], Counter] = defaultdict(Counter)
    by_wording: dict[str, Counter] = defaultdict(Counter)
    for item in items:
        by_cell[(item["cell"], item["action"])][item["outcome"]] += 1
        by_wording[item["goal_wording"]][item["outcome"]] += 1
    return {"by_cell": by_cell, "by_wording": by_wording}


def _counts(counter: Counter) -> tuple[int, int]:
    return sum(n for label, n in counter.items() if failed(label)), sum(counter.values())


def judge(items: list[dict[str, Any]]) -> dict[str, Any]:
    """The pre-registered reading (module docstring), from the items."""
    def group(pred) -> tuple[int, int]:
        sel = [i for i in items if pred(i)]
        return sum(1 for i in sel if failed(i["outcome"])), len(sel)

    secrets_wording = group(lambda i: i["goal_wording"] == SECRETS)
    ad_wording = group(lambda i: i["goal_wording"] == AD)
    natural_secrets = group(lambda i: i["cell"] == "natural" and i["action"] == "code.secrets")
    ad_lo = wilson(*ad_wording)[0]
    first = wilson(*secrets_wording)[1] < ad_lo if ad_wording[1] and secrets_wording[1] else None
    second = wilson(*natural_secrets)[1] < ad_lo if ad_wording[1] and natural_secrets[1] else None
    third = wilson(*natural_secrets)[0] <= S7_SECRETS_UPPER if natural_secrets[1] else None
    parts = (first, second, third)
    holds = None if any(p is None for p in parts) else all(parts)
    return {"secrets_wording": secrets_wording, "ad_wording": ad_wording,
            "natural_code_secrets": natural_secrets, "ad_lower95": round(ad_lo, 4),
            "rule_1": first, "rule_2": second, "rule_3": third, "holds": holds}


def render(items: list[dict[str, Any]]) -> str:
    table = tabulate(items)
    lines = ["## Q1 stream: what the validator answered, by action class and wording", "",
             "| cell | action | n | plausible | implausible | insufficient | failed | other "
             "| failed (rate, 95% upper) |", "|---|---|---|---|---|---|---|---|---|"]
    for (cell, action), counter in sorted(table["by_cell"].items()):
        k, n = _counts(counter)
        other = {label: c for label, c in counter.items()
                 if label not in ("plausible", "implausible", "insufficient_context",
                                  "not_assessed/failed")}
        lines.append(f"| {cell} | {action} | {n} | {counter['plausible']} "
                     f"| {counter['implausible']} | {counter['insufficient_context']} | {k} "
                     f"| {other or '-'} | {fmt(rate(k, n))} |")
    lines += ["", "### By the wording of the goal (the second axis)", "",
              "| wording | n | failed | rate, 95% interval |", "|---|---|---|---|"]
    for wording, counter in sorted(table["by_wording"].items()):
        k, n = _counts(counter)
        lo, hi = wilson(k, n)
        lines.append(f"| {wording} | {n} | {k} | {100 * k / n:.1f}% "
                     f"({100 * lo:.1f}-{100 * hi:.1f}) |")
    verdict = judge(items)
    k_s, n_s = verdict["secrets_wording"]
    k_a, n_a = verdict["ad_wording"]
    k_c, n_c = verdict["natural_code_secrets"]
    state = {True: "HOLDS", False: "does NOT hold", None: "not established (too little data)"}[
        verdict["holds"]]
    lines += ["", "### The judgement tested (written before the data; see the docstring)", "",
              "*Failures follow the goal's wording (Active-Directory language), not the action "
              "class.*",
              "", f"* secrets-scan wording (any action): {k_s}/{n_s} failed",
              f"* Active-Directory wording (any action): {k_a}/{n_a} failed "
              f"(Wilson lower bound {100 * verdict['ad_lower95']:.1f}%)",
              f"* natural `code.secrets` (secrets wording on its own action): {k_c}/{n_c} failed",
              f"* rule 1 (secrets-wording upper < AD-wording lower): {verdict['rule_1']}; "
              f"rule 2 (natural `code.secrets` upper < AD-wording lower): {verdict['rule_2']}; "
              f"rule 3 (natural `code.secrets` lower <= {100 * S7_SECRETS_UPPER:.1f}%, S7's "
              f"prediction not contradicted): {verdict['rule_3']}",
              f"* **the judgement {state}**"]
    return "\n".join(lines) + "\n"


def load(stream: Path) -> tuple[str, list[dict[str, Any]]]:
    eid = ""
    proposals = []
    for line in stream.read_text().splitlines():
        record = json.loads(line)
        if record["kind"] == "start":
            eid = record["engagement"]
        elif record["kind"] == "proposal":
            proposals.append(record)
    return eid, proposals


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--stream", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    from scripts.soak import lib

    lib.load_env()
    eid, proposals = load(args.stream)
    meta = {p["proposal_id"]: p for p in proposals if p.get("proposal_id")}
    rows = lib.psql(
        "SELECT proposal_id, reviewer_hints->'plan_fit'->>'goal_fit', "
        f"reviewer_hints->'plan_fit'->>'goal_fit_cause' FROM action_proposals "
        f"WHERE engagement_id = '{eid}'")
    items = []
    for proposal_id, value, cause in rows:
        if proposal_id in meta:
            m = meta[proposal_id]
            items.append({"action": m["action"], "cell": m["cell"],
                          "goal_wording": SECRETS if m["goal_wording"] == "code-secrets" else (
                              AD if m["goal_wording"] == "ad-collect" else m["goal_wording"]),
                          "outcome": outcome(value or None, cause or None)})
    text = render(items)
    print(text)
    if args.out:
        args.out.write_text(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
