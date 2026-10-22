#!/usr/bin/env python
"""Summarise the larger P1 shadow runs by stratum (D68).

    PYTHONPATH=. python scripts/live_run/summarise_p1_scale.py \\
        --stratum original=docs/D68_S7_BASELINE/p1_shadow \\
        --stratum scale_opus=docs/D68_S7_BASELINE/p1_scale/opus \\
        --stratum scale_sonnet=docs/D68_S7_BASELINE/p1_scale/sonnet --out summary.json

Each stratum is a directory of d40 run records (``run*.json``); the engagement of each is read from
the record and reported with ``plan_fit_report.collect`` (the stored ``plan_fit`` of every proposal,
joined to its task). Strata are reported side by side and **also pooled**; they are different
populations (different planners, different scopes) and the pooled figure says so. Nothing here
decides anything: it counts.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from control_plane.config import load_dotenv  # noqa: E402
from control_plane.plan_fit.shadow import fmt  # noqa: E402
from scripts.plan_fit_report import collect, combine  # noqa: E402


def engagements(directory: Path) -> list[str]:
    ids = []
    for path in sorted(directory.glob("run*.json")):
        record = json.loads(path.read_text())
        main = record.get("main_run") or {}
        if main.get("engagement_id"):
            ids.append(main["engagement_id"])
    return ids


def classify(task_canonical: str, proposal_canonical: str, relation: str,
             sub_cause: str | None = None) -> str:
    """Why a proposal does not match its task, in words about what happened (not the policy's
    sub-cause names): the DP-13 case first, then the others this run found. A match by the DP-13
    containment rule is its own line, so a run made after the rule can be told from one before."""
    import ipaddress

    if relation == "matches_task":
        return ("matched by the containment rule (a host or network inside the task's network)"
                if sub_cause == "subset_of_task_range" else "matches")
    t_kind, _, t_value = task_canonical.partition(":")
    p_kind, _, p_value = proposal_canonical.partition(":")
    try:
        if t_kind == "cidr" and p_kind == "ip":
            inside = ipaddress.ip_address(p_value) in ipaddress.ip_network(t_value, strict=False)
            return ("network task narrowed to one host inside it" if inside
                    else "network task proposed as a host outside it")
        if t_kind == "cidr" and p_kind == "cidr":
            task_net, prop_net = (ipaddress.ip_network(t_value, strict=False),
                                  ipaddress.ip_network(p_value, strict=False))
            if task_net.prefixlen == 32 and task_net.network_address in prop_net:
                return "task target lost its prefix (/32); proposal is the network it meant"
            if prop_net.subnet_of(task_net):
                return "network task narrowed to a smaller network inside it"
            return "network task proposed as a different network"
    except ValueError:
        pass
    if t_kind == "ip" and p_kind == "url" and t_value in p_value:
        return "same host, task as ip and proposal as url"
    return "other"


def classified(engagement_ids: list[str]) -> Counter:
    from sqlalchemy import text

    from control_plane.api.function_api import _task_identity
    from control_plane.state.db import engagement_scope

    out: Counter = Counter()
    for eid in engagement_ids:
        with engagement_scope(eid) as conn:
            rows = conn.execute(text(
                "SELECT t.action AS task_action, t.canonical_target AS task_target, "
                "p.action AS action, p.target AS target, "
                "p.reviewer_hints->'plan_fit'->>'task_relation' AS relation, "
                "p.reviewer_hints->'plan_fit'->>'sub_cause' AS sub_cause "
                "FROM tasks t JOIN action_proposals p ON p.task_id = t.task_id")).mappings().all()
        for row in rows:
            canonical, _ = _task_identity(row["action"], row["target"])
            kind = row["task_target"].partition(":")[0]
            why = classify(row["task_target"], canonical, row["relation"], row["sub_cause"])
            out[(kind, why)] += 1
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--stratum", action="append", required=True, metavar="NAME=DIR")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    load_dotenv()

    result: dict = {"strata": {}}
    pooled: dict[str, dict] = {}
    for spec in args.stratum:
        name, _, directory = spec.partition("=")
        ids = engagements(REPO / directory)
        per = {eid: collect(eid) for eid in ids}
        total = combine(per)
        net = total["dp13_proposals_on_network_tasks"]
        result["strata"][name] = {
            "why_proposals_differ": {f"{k[0]} task: {k[1]}": v for k, v in classified(ids).items()},
            "runs": len(ids), "proposals": total["proposals"], "decisions": total["decisions"],
            "task_relation": total["task_relation"],
            "task_relation_sub_cause": total["task_relation_sub_cause"],
            "dp13_proposals_on_network_tasks": net,
            "would_add_p1_only": total["would_add"]["p1_only"],
        }
        pooled.update(per)
    total = combine(pooled)
    net = total["dp13_proposals_on_network_tasks"]
    result["pooled"] = {
        "why_proposals_differ": {f"{k[0]} task: {k[1]}": v
                                 for k, v in classified(list(pooled)).items()},
        "runs": len(pooled), "proposals": total["proposals"], "decisions": total["decisions"],
        "task_relation": total["task_relation"],
        "task_relation_sub_cause": total["task_relation_sub_cause"],
        "dp13_proposals_on_network_tasks": net,
        "would_add_p1_only": total["would_add"]["p1_only"],
    }
    for name, s in {**result["strata"], "POOLED": result["pooled"]}.items():
        print(f"{name} why:", json.dumps(s["why_proposals_differ"], indent=1))
        n = s["dp13_proposals_on_network_tasks"]
        print(f"{name}: {s['runs']} runs, {s['proposals']} proposals, {s['task_relation']}; "
              f"on network tasks: {fmt(n['single_host_inside'])} {n['by_relation']}; P1 would add "
              f"{fmt(s['would_add_p1_only']['would_become_human_approval'])}")
    if args.out:
        args.out.write_text(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
