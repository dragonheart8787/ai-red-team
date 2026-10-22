#!/usr/bin/env python
"""What would enabling the plan-fit switches cost? A read-only report (D68 S6).

Over named engagements.

Until S8 both switches (``task_relation_enforce``, ``goal_fit_enforce``) are off and the relation to
the task and the validator's answer are only *recorded*, beside each decision
(``action_proposals.reviewer_hints["plan_fit"]``) and in one ``plan_fit.assessed`` audit event. This
reads that record and answers the question S7 needs: of the proposals decided ``ALLOW``, how many
would have been sent to a human had a switch been on, and under which reason.

    python scripts/plan_fit_report.py --engagement ENG-1 --engagement ENG-2
    python scripts/plan_fit_report.py --engagement ENG-1 --json
    python scripts/plan_fit_report.py --engagement ENG-1 --since 2026-10-01

**It reports and changes nothing**, over the ordinary ``cyberorch_app`` connection, and **the
engagements have to be named**: row-level security means no role can sweep the database
(``audit_scope_values.py`` explains it). An operator supplies the list.

How to read it, so that a number is not mistaken for more than it is:

* The counts are of proposals that went through ``propose_action`` since S2. A decision from before
  has no ``plan_fit``; it is counted apart and asks for nothing.
* "Would add" is computed by ``control_plane/plan_fit/shadow.py`` -- a restatement of the policy's
  rules, tested against the real policy -- on the *stored* value, which is what the approval
  re-derivation reads too. It does not re-ask a validator.
* A proposal already sent to a human gets no new approval from a switch; the report shows the
  reasons it would *gain*, which change what the approver is told and not how many approvals exist.
* DP-13: a task on a network and a proposal for one host (or a smaller network) inside it is, since
  2026-10-22, ``matches_task`` with the sub-cause ``subset_of_task_range``; before, it was
  ``differs_from_task`` with ``same_action_target_inside_task_target``. Both are reported (a
  database can hold both), and the rule's own use -- how many matches it decided, and what share
  of all matches -- is a line of its own, so that its use can be watched.
* No real engagement traffic is implied by a run on a test or soak engagement.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import text  # noqa: E402

from control_plane.config import load_dotenv  # noqa: E402
from control_plane.plan_fit import relation as r  # noqa: E402
from control_plane.plan_fit.shadow import ALL_REASONS, fmt, rate, would_ask  # noqa: E402
from control_plane.state.db import engagement_scope  # noqa: E402

#: (name, task switch, goal switch): the three ways S8 might enable
SCENARIOS = (("p1_only", True, False), ("q1_only", False, True), ("both", True, True))


def summarize(rows: list[dict[str, Any]], events: list[dict[str, Any]]) -> dict[str, Any]:
    """The report's numbers from one engagement's proposals and ``plan_fit.assessed`` payloads.

    A pure function of its two lists, so it is tested without a database. ``rows`` have
    ``decision``, ``pipeline_stage`` and ``plan_fit`` (the stored dict, or ``None``).
    """
    decided = [x for x in rows if x["decision"] is not None]
    with_plan = [x for x in decided if isinstance(x.get("plan_fit"), dict)]
    out: dict[str, Any] = {
        "proposals": len(rows), "decided": len(decided),
        "decisions": dict(Counter(x["decision"] for x in decided)),
        "with_plan_fit": len(with_plan),
        "without_plan_fit": len(decided) - len(with_plan)}

    relations = Counter()
    sub_causes = Counter()
    goal = Counter()
    for x in with_plan:
        signal = r.policy_signal(x["plan_fit"])
        relations[signal["task_relation"]] += 1
        if signal["sub_cause"]:
            sub_causes[f"{signal['task_relation']}/{signal['sub_cause']}"] += 1
        if "goal_fit" in signal:
            goal[f"{signal['goal_fit']}/{signal['goal_fit_cause'] or '-'}"] += 1
        else:
            goal["absent (decided before Q1)"] += 1
    out["task_relation"] = dict(relations)
    out["task_relation_sub_cause"] = dict(sub_causes)
    out["goal_fit"] = dict(goal)
    differs = relations.get(r.DIFFERS_FROM_TASK, 0)
    out["dp13_inside_task_target"] = rate(
        sub_causes.get(f"{r.DIFFERS_FROM_TASK}/{r.INSIDE_TASK_TARGET}", 0), differs)
    out["dp13_rule_use"] = _rule_use(sub_causes, relations, len(with_plan))
    # DP-13 as the question was asked: of the proposals made for a task whose target is a network,
    # how many were for one host inside it (and so would be `differs_from_task`)?
    on_cidr = [x for x in with_plan if x.get("task_target_kind") == "cidr"]
    inside = 0
    kinds: Counter = Counter()
    for x in on_cidr:
        signal = r.policy_signal(x["plan_fit"])
        if (signal["task_relation"], signal["sub_cause"]) in (
                (r.DIFFERS_FROM_TASK, r.INSIDE_TASK_TARGET),     # decided before the rule
                (r.MATCHES_TASK, r.SUBSET_OF_TASK_RANGE)):       # decided by it
            inside += 1
        kinds[signal["task_relation"]] += 1
    out["dp13_proposals_on_network_tasks"] = {
        "single_host_inside": rate(inside, len(on_cidr)), "by_relation": dict(kinds)}

    allowed = [x for x in with_plan if x["decision"] == "ALLOW"]
    asked = [x for x in with_plan if x["decision"] == "HUMAN_APPROVAL"]
    would: dict[str, Any] = {}
    for name, task, goal_switch in SCENARIOS:
        extra = [(x, would_ask(x["plan_fit"], task_enforce=task, goal_enforce=goal_switch))
                 for x in allowed]
        turned = [(x, rs) for x, rs in extra if rs]
        by_reason = Counter(reason for _, rs in turned for reason in rs)
        gained = Counter(
            reason for x in asked
            for reason in would_ask(x["plan_fit"], task_enforce=task, goal_enforce=goal_switch))
        would[name] = {
            "allow_decisions": len(allowed),
            "would_become_human_approval": rate(len(turned), len(allowed)),
            "by_reason": {k: by_reason.get(k, 0) for k in ALL_REASONS if by_reason.get(k)},
            "reasons_gained_by_already_asked": dict(gained)}
    out["would_add"] = would

    calls = [e["call"] for e in events if "call" in e]
    latency = sorted(float(c["latency_seconds"]) for c in calls)
    p95 = latency[min(len(latency) - 1, math.ceil(0.95 * len(latency)) - 1)] if latency else None
    out["validator"] = {
        "events": len(events),
        "ids": dict(Counter(e.get("validator_id", "?") for e in events)),
        "prompts": dict(Counter(
            (e.get("validator") or {}).get("prompt_sha256", "?")[:12] for e in events)),
        "errors": dict(Counter(e["error_type"] for e in events if e.get("error_type"))),
        "calls": len(calls),
        "latency_median": round(statistics.median(latency), 2) if latency else None,
        "latency_p95": round(p95, 2) if p95 is not None else None,
        "tokens": {"input": sum(int(c.get("input_tokens", 0)) for c in calls),
                   "output": sum(int(c.get("output_tokens", 0)) for c in calls)}}
    return out


def collect(engagement_id: str, *, since: str | None = None) -> dict[str, Any]:
    """Read one engagement's proposals and audit events (its own scope; RLS decides the rest)."""
    when = " AND created_at >= CAST(:since AS timestamptz)" if since else ""
    audit_when = " AND ts >= CAST(:since AS timestamptz)" if since else ""
    params = {"since": since} if since else {}
    with engagement_scope(engagement_id) as conn:
        rows = [
            {"proposal_id": p["proposal_id"], "decision": p["decision"],
             "pipeline_stage": p["pipeline_stage"],
             "plan_fit": (p["reviewer_hints"] or {}).get("plan_fit")
             if isinstance(p["reviewer_hints"], dict) else None,
             "task_target_kind": (p["task_target"] or "").partition(":")[0] or None}
            for p in conn.execute(text(
                "SELECT p.proposal_id, p.decision, p.pipeline_stage, p.reviewer_hints, "
                "t.canonical_target AS task_target "
                "FROM action_proposals p LEFT JOIN tasks t ON t.task_id = p.task_id "
                "WHERE true" + when.replace("created_at", "p.created_at")
                + " ORDER BY p.created_at"), params).mappings()]
        events = [e["payload"] for e in conn.execute(text(
            "SELECT payload FROM audit_log WHERE event_type = 'plan_fit.assessed'" + audit_when
            + " ORDER BY audit_id"), params).mappings()]
    return summarize(rows, events)


def combine(per_engagement: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Totals across the named engagements (counters add; rates are recomputed, never averaged)."""
    total: dict[str, Any] = {"engagements": len(per_engagement)}
    for key in ("proposals", "decided", "with_plan_fit", "without_plan_fit"):
        total[key] = sum(v[key] for v in per_engagement.values())
    for key in ("decisions", "task_relation", "task_relation_sub_cause", "goal_fit"):
        merged: Counter = Counter()
        for v in per_engagement.values():
            merged.update(v[key])
        total[key] = dict(merged)
    inside = total["task_relation_sub_cause"].get(
        f"{r.DIFFERS_FROM_TASK}/{r.INSIDE_TASK_TARGET}", 0)
    total["dp13_inside_task_target"] = rate(inside, total["task_relation"].get(
        r.DIFFERS_FROM_TASK, 0))
    total["dp13_rule_use"] = _rule_use(
        total["task_relation_sub_cause"], total["task_relation"], total["with_plan_fit"])
    network = [v["dp13_proposals_on_network_tasks"] for v in per_engagement.values()]
    by_relation: Counter = Counter()
    for entry in network:
        by_relation.update(entry["by_relation"])
    total["dp13_proposals_on_network_tasks"] = {
        "single_host_inside": rate(sum(e["single_host_inside"]["k"] for e in network),
                                   sum(e["single_host_inside"]["n"] for e in network)),
        "by_relation": dict(by_relation)}
    would: dict[str, Any] = {}
    for name, _, _ in SCENARIOS:
        rows = [v["would_add"][name] for v in per_engagement.values()]
        allow = sum(x["allow_decisions"] for x in rows)
        turned = sum(x["would_become_human_approval"]["k"] for x in rows)
        reasons: Counter = Counter()
        gained: Counter = Counter()
        for x in rows:
            reasons.update(x["by_reason"])
            gained.update(x["reasons_gained_by_already_asked"])
        would[name] = {
            "allow_decisions": allow, "would_become_human_approval": rate(turned, allow),
            "by_reason": dict(reasons), "reasons_gained_by_already_asked": dict(gained)}
    total["would_add"] = would
    return total


def _rule_use(sub_causes: Any, relations: Any, with_plan: int) -> dict[str, Any]:
    """How much the DP-13 containment rule decided: matches it made, of all proposals with a stored
    value and of all matches. The sub-cause exists so that this can be asked."""
    used = sub_causes.get(f"{r.MATCHES_TASK}/{r.SUBSET_OF_TASK_RANGE}", 0)
    return {"of_proposals": rate(used, with_plan),
            "of_matches": rate(used, relations.get(r.MATCHES_TASK, 0))}


def render(report: dict[str, Any]) -> str:
    lines: list[str] = []
    for name, data in (*report["engagements"].items(), ("ALL", report["total"])):
        lines += [f"## {name}", "",
                  f"* proposals {data['proposals']}, decided {data['decided']}: "
                  f"{data['decisions']}",
                  f"* with a stored plan_fit {data['with_plan_fit']}, without "
                  f"{data['without_plan_fit']} (decided before S2: asks for nothing)",
                  f"* task_relation: {data['task_relation']}",
                  f"* sub-causes: {data['task_relation_sub_cause']}",
                  f"* goal_fit: {data['goal_fit']}",
                  f"* DP-13, a host inside the task's network, of all `differs_from_task`: "
                  f"{fmt(data['dp13_inside_task_target'])}",
                  f"* DP-13 containment rule (`matches_task/subset_of_task_range`): "
                  f"{fmt(data['dp13_rule_use']['of_proposals'])} of proposals, "
                  f"{fmt(data['dp13_rule_use']['of_matches'])} of matches",
                  f"* DP-13 as asked: proposals for a task on a network that were for one host "
                  f"inside it: {fmt(data['dp13_proposals_on_network_tasks']['single_host_inside'])}"
                  f" ({data['dp13_proposals_on_network_tasks']['by_relation']})", "",
                  "| if enabled | ALLOW decisions | would go to a human | by reason | reasons "
                  "added to those already asked |", "|---|---|---|---|---|"]
        for scenario, w in data["would_add"].items():
            lines.append(
                f"| {scenario} | {w['allow_decisions']} | {fmt(w['would_become_human_approval'])} "
                f"| {w['by_reason']} | {w['reasons_gained_by_already_asked']} |")
        if "validator" in data:
            v = data["validator"]
            lines += ["", f"* validator events {v['events']}, ids {v['ids']}, prompts "
                      f"{v['prompts']}, exceptions {v['errors']}, latency median "
                      f"{v['latency_median']}s p95 {v['latency_p95']}s, tokens {v['tokens']}"]
        lines.append("")
    lines += ["Nothing here is a decision. Enabling a switch is S8; the gate is S7's.", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--engagement", action="append", dest="engagements", required=True,
                        metavar="ENG-...", help="repeat for more; RLS means they must be named")
    parser.add_argument("--since", default=None, help="only rows created at or after this time")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    load_dotenv()
    per = {eid: collect(eid, since=args.since) for eid in args.engagements}
    report = {"engagements": per, "total": combine(per)}
    if args.as_json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
