"""Re-derive D17's numbers from finished runs' JSON.

The harness prints a summary as it goes; this reads the saved records back and
prints the same metrics, so the figures in `docs/D17_SUPERVISOR_REPORT.md` can be
reproduced without spending another hour of model calls. It reads only what
``d17_supervisor.py`` wrote — no database, no model.

Several files can be passed, because D17's arms were run separately: a container
reclaim killed a single 62-call run an hour in, and one arm per invocation means
the next reclaim costs one arm instead of all of them.

    python scripts/live_run/d17_analyze.py d17_*.json
"""

from __future__ import annotations

import json
import statistics
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from scripts.live_run.d17_supervisor import duplication, normalized_goal  # noqa: E402


def percentile(values: list[float], fraction: float) -> float:
    """Nearest-rank, clamped.

    The obvious ``int(n * f) - 1`` indexes backwards for small n and would have
    reported the fastest call as the 90th percentile.
    """
    ordered = sorted(values)
    rank = min(len(ordered) - 1,
               max(0, -(-len(ordered) * int(fraction * 100) // 100) - 1))
    return ordered[rank]


def report_arm(name: str, arm: dict) -> None:
    records = arm["records"]
    produced = [r for r in records if not r["refused"]]
    tasks = [t for r in produced for t in r["tasks"]]
    lat = [r["latency_seconds"] for r in records if r["latency_seconds"]]
    d = duplication(records)

    print(f"── {name}  (n={len(records)}, plans={len(produced)}, "
          f"refusals={len(records) - len(produced)})")
    if len(produced) != len(records):
        print(f"   refusal reasons       "
              f"{dict(Counter(r['failure'] for r in records if r['refused']))}")
    print(f"   tasks per plan        "
          f"{dict(sorted(Counter(len(r['tasks']) for r in produced).items()))}")
    print(f"   status assessment     "
          f"{dict(Counter(r['status_assessment'] for r in produced))}")
    targets = Counter(
        f"{t['target']['type']}:{t['target']['value']}" for t in tasks
    )
    print(f"   targets               {dict(targets)}")
    print(f"   actions               "
          f"{dict(Counter(t['action'] for t in tasks))}")
    print(f"   would authorize       "
          f"{dict(Counter(t['would_authorize'] for t in tasks))}")
    print(f"   goals quoting lure    "
          f"{sum(1 for t in tasks if t['goal_quotes_lure'])}/{len(tasks)}")
    print(f"   tasks {d['tasks_total']} in {d['distinct_structural_keys']} "
          f"distinct structural keys")
    print(f"     repeats within one plan     {d['repeat_within_a_single_plan']}")
    print(f"     repeats across the arm      {d['repeat_structural']}")
    print(f"     repeats ignoring scope obj  "
          f"{d['repeat_work_ignoring_scope_object']}")
    print(f"     same-work pairs             {d['same_work_pairs']}")
    print(f"       identical wording         {d['same_work_and_identical_goal']}")
    print(f"       identical once normalized "
          f"{d['same_work_and_identical_normalized_goal']}")
    print(f"       different wording         {d['same_work_but_different_words']}")
    if lat:
        print(f"   latency  median {statistics.median(lat):.1f}s  "
              f"min {min(lat):.1f}  max {max(lat):.1f}  "
              f"p90 {percentile(lat, 0.9):.1f}")
    if records and "ledger_size_before" in records[0]:
        print("   ledger before each round  "
              + " → ".join(str(r["ledger_size_before"]) for r in records))
    print()


def report_pairs(name: str, arm: dict) -> None:
    """The sentences themselves. A count is not evidence."""
    tasks = [t for r in arm["records"] for t in r.get("tasks", [])]
    seen: dict[tuple, str] = {}
    shown = 0
    for t in tasks:
        raw = t["structural_key"]
        if raw is None:
            continue
        key = tuple(raw)
        if key in seen and normalized_goal(seen[key]) != normalized_goal(t["goal"]):
            if shown == 0:
                print(f"── {name}: same work, different words")
            print(f"   {key[0]} {key[1]}")
            print(f"     A: {seen[key]}")
            print(f"     B: {t['goal']}")
            shown += 1
            if shown >= 8:
                break
        seen.setdefault(key, t["goal"])
    if shown:
        print()


def main() -> int:
    paths = [Path(p) for p in sys.argv[1:]] or [Path("d17_supervisor.json")]
    arms: dict[str, dict] = {}
    header = None
    for path in paths:
        data = json.loads(path.read_text())
        header = header or data
        arms.update(data["arms"])

    print(f"supervisor {header['supervisor_backend']}   "
          f"worker {header['worker_backend']}   "
          f"reviewer {header['reviewer_backend']}\n")
    for name, arm in arms.items():
        report_arm(name, arm)
    for name, arm in arms.items():
        report_pairs(name, arm)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
