#!/usr/bin/env python
"""Measure how a real plan-fit validator (Q1) judges a corpus with known answers (D68 S6).

Run by hand.

Like ``reviewer_baseline.py``, this is a script and not a test, on purpose: it reaches a real model,
model output is not deterministic, and a gate that fails for reasons unrelated to the change is one
people re-run without reading. It is **never run in CI** (a test fails if a workflow names it), and
``docs/ADR_REVIEWER_BILLING.md`` applies: confirm the billing status of the backend before a run --
``claude_code`` is the subscription, ``api`` is metered.

    python scripts/plan_fit_baseline.py --backend claude_code --model sonnet --dry-run
    python scripts/plan_fit_baseline.py --backend claude_code --model sonnet --repeat 1 \\
        --json out.json --report out.md
    python scripts/plan_fit_baseline.py --backend local --group matched --limit 20

What it measures is the *model's* judgement of the corpus (``tests/plan_fit_corpus.py``: matched,
mismatched and lure triples whose right answer is true by construction). The kernel's behaviour
around the answer is settled and tested elsewhere: whatever the validator says, ``plausible`` adds
no caution and an answer never lowers a decision. The open question is what the *validator* says.

The record names the **backend, model, the CLI's version and the prompt's hash together**, because
a rate that moved is only attributable if all four are written beside it (design section 5).
Counts are printed ``k/N`` with an upper bound at 95% -- ``0/N`` bounds the true rate to about
``3/N``, so N decides what a clean result is worth.

The analysis (``analyse``) is a pure function of the records and is tested offline; this file's
network-touching part is the one call to ``validator.assess``.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agents.base_agent import GOAL_FIT_VALUES, NOT_ASSESSED  # noqa: E402
from control_plane.plan_fit.shadow import fmt, rate  # noqa: E402
from tests.plan_fit_corpus import (  # noqa: E402
    GROUPS,
    LURE,
    LURE_CLASSES,
    MATCHED,
    MISMATCHED,
    PER_CLASS,
    SEED,
    Item,
    build_corpus,
    corpus_digest,
)

#: calls above this need ``--max-calls`` raised on purpose
DEFAULT_MAX_CALLS = 600

FAILED = "failed"
PLAUSIBLE, IMPLAUSIBLE, INSUFFICIENT = GOAL_FIT_VALUES


# ---------------------------------------------------------------------------------------------
# running
# ---------------------------------------------------------------------------------------------

class RunAborted(RuntimeError):  # noqa: N818 - a run stopped on purpose, with what it had
    def __init__(self, message: str, records: list[dict[str, Any]]) -> None:
        super().__init__(message)
        self.records = records


class EnvelopeRecorder:
    """Wraps ``subprocess.run`` for the ``claude_code`` backend and keeps what the CLI says about
    each call: the models that served it, its list-price cost, whether it reported an error. The
    validator never sees this (it gets the completed process back unchanged); the runner reads it
    after each call, so the record names the model that *answered*, not the alias that was asked."""

    def __init__(self, inner: Any = None) -> None:
        self._inner = inner or subprocess.run
        self.envelopes: list[dict[str, Any]] = []

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        done = self._inner(*args, **kwargs)
        entry: dict[str, Any] = {"returncode": done.returncode}
        try:
            env = json.loads(done.stdout or "")
            usage = env.get("modelUsage") or {}
            entry.update(
                cost_usd=env.get("total_cost_usd"), models=sorted(usage),
                is_error=bool(env.get("is_error")), api_error_status=env.get("api_error_status"),
                terminal_reason=env.get("terminal_reason"),
                cache_read_tokens=int((env.get("usage") or {}).get("cache_read_input_tokens", 0)),
                cache_creation_tokens=int(
                    (env.get("usage") or {}).get("cache_creation_input_tokens", 0)))
        except (ValueError, TypeError, AttributeError):
            entry["unparsed"] = True
        self.envelopes.append(entry)
        return done


def run_corpus(validator: Any, items: tuple[Item, ...], *, repeat: int = 1, progress: Any = None,
               envelopes: list[dict[str, Any]] | None = None,
               stop_after_failures: int | None = None,
               checkpoint: Path | None = None) -> list[dict[str, Any]]:
    """Ask ``validator`` about every item, ``repeat`` times, in order; one record per call.

    A validator that raises is recorded as ``failed`` -- the same reading the control plane gives
    it (S5) -- so that one bad call cannot end a run that has spent an hour and some tokens.
    ``stop_after_failures`` is the opposite protection: that many failures *in a row* (a rate
    limit, an expired login, a dead server) mean every further call will fail too, and the run
    stops with what it has (:class:`RunAborted`) instead of spending the rest of the corpus on it.
    ``checkpoint`` appends each record to a JSONL file as it is made.
    """
    records: list[dict[str, Any]] = []
    streak = 0
    for run in range(repeat):
        for n, item in enumerate(items):
            calls = getattr(validator, "calls", None)
            before = len(calls) if isinstance(calls, list) else 0
            seen = len(envelopes) if envelopes is not None else 0
            record: dict[str, Any] = {"item_id": item.item_id, "run": run}
            try:
                got = validator.assess(query=item.query)
                value, cause = got.goal_fit, got.cause
            except Exception as exc:  # noqa: BLE001 - recorded, not hidden
                value, cause = NOT_ASSESSED, "failed"
                record["error_type"] = type(exc).__name__
            record["goal_fit"] = FAILED if value == NOT_ASSESSED else value
            record["cause"] = cause
            if isinstance(calls, list) and len(calls) > before:
                call = calls[-1]
                record.update(
                    latency_seconds=round(float(call.latency_seconds), 3),
                    input_tokens=int(call.input_tokens), output_tokens=int(call.output_tokens),
                    call_failed=bool(call.failed))
                if call.failed and call.failure:
                    record["failure"] = str(call.failure)[:200]
            if envelopes is not None and len(envelopes) > seen:
                env = envelopes[-1]
                record.update(cost_usd=env.get("cost_usd"), models=env.get("models"),
                              cache_read_tokens=env.get("cache_read_tokens"))
            records.append(record)
            if checkpoint is not None:
                with checkpoint.open("a") as handle:
                    handle.write(json.dumps(record) + "\n")
            if progress is not None:
                progress(run, n, len(items), record)
            streak = streak + 1 if record["goal_fit"] == FAILED else 0
            if stop_after_failures and streak >= stop_after_failures:
                raise RunAborted(
                    f"{streak} calls failed in a row after {len(records)} calls; last: "
                    f"{record.get('failure') or record.get('error_type') or 'no detail'}", records)
    return records


# ---------------------------------------------------------------------------------------------
# analysis (pure)
# ---------------------------------------------------------------------------------------------

def _tally(records: list[dict[str, Any]]) -> Counter:
    return Counter(r["goal_fit"] for r in records)


def analyse(records: list[dict[str, Any]], items: tuple[Item, ...]) -> dict[str, Any]:
    """Every measure the S7 gate looks at, from the records alone. No threshold is applied here:
    the numbers are the owner's decision (DP-14); this reports them."""
    by_item = {i.item_id: i for i in items}
    known = [r for r in records if r["item_id"] in by_item]
    unknown = len(records) - len(known)
    group_of = {r_id: i.group for r_id, i in by_item.items()}
    out: dict[str, Any] = {"calls": len(known), "unknown_items": unknown}

    # answers by group, failures kept apart (a failure is not an answer, and is never plausible)
    groups: dict[str, dict[str, Any]] = {}
    for group in GROUPS:
        subset = [r for r in known if group_of[r["item_id"]] == group]
        tally = _tally(subset)
        n = len(subset)
        groups[group] = {
            "n": n, **{v: rate(tally.get(v, 0), n) for v in (*GOAL_FIT_VALUES, FAILED)}}
    out["groups"] = groups

    m = groups[MATCHED]
    out["false_positive_on_matched"] = m[IMPLAUSIBLE]          # implausible on matched
    out["insufficient_on_matched"] = m[INSUFFICIENT]
    mm = groups[MISMATCHED]
    n_mm = mm["n"]
    caught = mm[IMPLAUSIBLE]["k"] + mm[INSUFFICIENT]["k"]
    out["detection_on_mismatched"] = rate(caught, n_mm)
    out["plausible_on_mismatched"] = mm[PLAUSIBLE]            # the control rate of every lure

    # lures against their controls, paired per (base item, run)
    answers = {(r["item_id"], r["run"]): r["goal_fit"] for r in known}
    lures: dict[str, Any] = {}
    runs = sorted({r["run"] for r in known})
    for cls in LURE_CLASSES:
        rows = []
        for item in items:
            if item.lure != cls:
                continue
            for run in runs:
                lured, ctl = answers.get((item.item_id, run)), answers.get((item.base_id, run))
                if lured is not None and ctl is not None:
                    rows.append((lured, ctl))
        n = len(rows)
        lured_ok = sum(1 for lured, _ in rows if lured == PLAUSIBLE)
        control_ok = sum(1 for _, ctl in rows if ctl == PLAUSIBLE)
        bought = sum(1 for lured, ctl in rows if lured == PLAUSIBLE and ctl != PLAUSIBLE)
        lost = sum(1 for lured, ctl in rows if ctl == PLAUSIBLE and lured != PLAUSIBLE)
        lures[cls] = {
            "n": n, "lured_plausible": rate(lured_ok, n), "control_plausible": rate(control_ok, n),
            "delta_points": round(100.0 * (lured_ok - control_ok) / n, 1) if n else None,
            "bought_by_the_lure": bought, "lost_by_the_lure": lost,
            "lured_failed": rate(sum(1 for lured, _ in rows if lured == FAILED), n)}
    out["lures"] = lures

    # stability (L7): per item, did the answer differ between runs?
    per_item: dict[str, list[str]] = defaultdict(list)
    for r in known:
        per_item[r["item_id"]].append(r["goal_fit"])
    repeated = {k: v for k, v in per_item.items() if len(v) >= 2}
    flipped = sum(1 for v in repeated.values() if len(set(v)) > 1)
    out["flip_rate"] = rate(flipped, len(repeated))

    lat = sorted(r["latency_seconds"] for r in known if "latency_seconds" in r)
    out["latency_seconds"] = ({
        "calls": len(lat), "median": round(statistics.median(lat), 2),
        "p95": round(lat[min(len(lat) - 1, math.ceil(0.95 * len(lat)) - 1)], 2),
        "max": lat[-1]} if lat else None)
    out["tokens"] = {
        "input": sum(r.get("input_tokens", 0) for r in known),
        "output": sum(r.get("output_tokens", 0) for r in known)}
    out["failed_calls"] = rate(sum(1 for r in known if r["goal_fit"] == FAILED), len(known))
    out["error_types"] = dict(Counter(r["error_type"] for r in known if "error_type" in r))
    costs = [r["cost_usd"] for r in known if isinstance(r.get("cost_usd"), (int, float))]
    out["cost_usd_list_price"] = round(sum(costs), 4) if costs else None
    out["models_that_answered"] = dict(Counter(
        m for r in known for m in (r.get("models") or [])))
    return out


def render(report: dict[str, Any]) -> str:
    a, meta = report["analysis"], report["meta"]
    lines = ["# Plan-fit baseline", ""]
    lines += [f"* backend `{meta['backend']}`, model `{meta['model'] or 'default'}`, "
              f"CLI `{meta['cli_version']}`, prompt `{meta['prompt_sha256'][:12]}`",
              f"* corpus seed {meta['seed']}, per class {meta['per_class']}, digest "
              f"`{meta['corpus_digest'][:12]}`, repeat {meta['repeat']}, {a['calls']} calls",
              f"* run started {meta['started']}, commit `{meta['commit']}`", "",
              "Counts are `k/N` with an upper bound at 95%; `0/N` bounds a rate to about "
              "`3/N`.", "",
              "## Answers by group", "",
              "| group | n | plausible | implausible | insufficient_context | failed |",
              "|---|---|---|---|---|---|"]
    for group, g in a["groups"].items():
        lines.append(f"| {group} | {g['n']} | " + " | ".join(
            fmt(g[v]) for v in (PLAUSIBLE, IMPLAUSIBLE, INSUFFICIENT, FAILED)) + " |")
    lines += ["", "## Measures", "",
              f"* false positive (`implausible` on matched): {fmt(a['false_positive_on_matched'])}",
              f"* `insufficient_context` on matched: {fmt(a['insufficient_on_matched'])}",
              f"* detection (`implausible` or `insufficient_context` on mismatched): "
              f"{fmt(a['detection_on_mismatched'])}",
              f"* `plausible` on mismatched (the controls): {fmt(a['plausible_on_mismatched'])}",
              f"* flip rate (same item, different answer across runs): {fmt(a['flip_rate'])}",
              f"* failed calls: {fmt(a['failed_calls'])}", "",
              "## Lures against their controls (paired per base item and run)", "",
              "| lure | n | judged plausible | its control plausible | delta (points) | bought | "
              "lost |", "|---|---|---|---|---|---|---|"]
    for cls, row in a["lures"].items():
        lines.append(
            f"| {cls} | {row['n']} | {fmt(row['lured_plausible'])} | "
            f"{fmt(row['control_plausible'])} | {row['delta_points']} | "
            f"{row['bought_by_the_lure']} | {row['lost_by_the_lure']} |")
    lat = a["latency_seconds"]
    lines += ["", "## Latency and tokens", "",
              (f"* latency median {lat['median']}s, p95 {lat['p95']}s, max {lat['max']}s "
               f"over {lat['calls']} calls" if lat else "* latency: no call records"),
              f"* tokens in {a['tokens']['input']}, out {a['tokens']['output']}"]
    if a["error_types"]:
        lines.append(f"* exceptions raised by the validator: {a['error_types']}")
    if a["cost_usd_list_price"] is not None:
        lines.append(f"* list-price cost reported by the CLI: ${a['cost_usd_list_price']} "
                     "(a notional figure on a subscription backend)")
    if a["models_that_answered"]:
        lines.append(f"* models that served the calls: {a['models_that_answered']}")
    lines += ["", "No threshold is applied here. The numbers are read against the gate the owner "
              "sets (DP-14) in S7.", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------------
# the command line
# ---------------------------------------------------------------------------------------------

def cli_version() -> str:
    """The ``claude`` CLI's version, best effort: the billing ADR asks a baseline to name it."""
    try:
        done = subprocess.run(["claude", "--version"], capture_output=True, text=True, timeout=10)
        return (done.stdout or done.stderr).strip().splitlines()[0] or "unknown"
    except Exception:  # noqa: BLE001 - a record field, not an input
        return "unavailable"


def git_commit() -> str:
    try:
        done = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                              text=True, timeout=10, cwd=ROOT)
        return done.stdout.strip() or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def select(items: tuple[Item, ...], *, group: list[str] | None, lure: list[str] | None,
           limit: int | None) -> tuple[Item, ...]:
    chosen = items
    if group:
        chosen = tuple(i for i in chosen if i.group in group)
    if lure:
        chosen = tuple(i for i in chosen if i.group != LURE or i.lure in lure)
    if limit:
        # keep every group represented: take from each group in turn
        buckets: dict[str, list[Item]] = defaultdict(list)
        for i in chosen:
            buckets[i.group if i.group != LURE else f"{LURE}-{i.lure}"].append(i)
        picked: list[Item] = []
        while len(picked) < limit and any(buckets.values()):
            for key in list(buckets):
                if buckets[key] and len(picked) < limit:
                    picked.append(buckets[key].pop(0))
        keep = {i.item_id for i in picked}
        chosen = tuple(i for i in chosen if i.item_id in keep)
    # a lure is only measurable against its control: the bases of the chosen lures come along
    bases = {i.base_id for i in chosen if i.base_id}
    return tuple(i for i in items if i in chosen or i.item_id in bases)


def make_report(*, backend: str, model: str | None, validator: Any, items: tuple[Item, ...],
                records: list[dict[str, Any]], repeat: int, seed: int, per_class: int,
                started: str) -> dict[str, Any]:
    try:
        prompt_sha = validator.provenance().get("prompt_sha256", "unknown")
    except Exception:  # noqa: BLE001
        prompt_sha = "unknown"
    return {
        "meta": {
            "backend": backend, "model": model, "cli_version": cli_version(),
            "prompt_sha256": prompt_sha, "seed": seed, "per_class": per_class,
            "corpus_digest": corpus_digest(items), "repeat": repeat, "started": started,
            "commit": git_commit(), "items": len(items)},
        "analysis": analyse(records, items), "records": records}


def main(argv: list[str] | None = None) -> int:
    from agents.llm.selection import BACKENDS, build_plan_fit_validator

    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", choices=[b for b in BACKENDS if b != "fake"], required=True,
                        help="a real backend; the fake validators measure nothing")
    parser.add_argument("--model", default=None)
    parser.add_argument("--repeat", type=int, default=1, help="passes over the corpus (L7)")
    parser.add_argument("--group", action="append", choices=GROUPS)
    parser.add_argument("--lure", action="append", choices=LURE_CLASSES)
    parser.add_argument("--limit", type=int, default=None, help="at most this many items")
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--per-class", type=int, default=PER_CLASS)
    parser.add_argument("--max-calls", type=int, default=DEFAULT_MAX_CALLS,
                        help="refuse a run with more calls than this (default %(default)s)")
    parser.add_argument("--stop-after-failures", type=int, default=8,
                        help="stop after this many failed calls in a row (0: never)")
    parser.add_argument("--checkpoint", type=Path, default=None,
                        help="append each record to this JSONL file as it is made")
    parser.add_argument("--dry-run", action="store_true",
                        help="print what would be asked and make no call")
    parser.add_argument("--json", type=Path, default=None, help="write the full record here")
    parser.add_argument("--report", type=Path, default=None, help="write the rendered report here")
    args = parser.parse_args(argv)

    items = select(build_corpus(args.seed, args.per_class), group=args.group, lure=args.lure,
                   limit=args.limit)
    calls = len(items) * args.repeat
    counts = Counter(i.group if i.group != LURE else f"lure {i.lure}" for i in items)
    print(f"backend={args.backend} model={args.model or 'default'} repeat={args.repeat}")
    print(f"corpus: {len(items)} items " + ", ".join(f"{k} {v}" for k, v in counts.items()))
    print(f"calls: {calls} (limit {args.max_calls})")
    if args.dry_run:
        print("dry run: no call made")
        return 0
    if calls > args.max_calls:
        print(f"refusing: {calls} calls is above --max-calls {args.max_calls}; raise it on "
              "purpose, after reading docs/ADR_REVIEWER_BILLING.md", file=sys.stderr)
        return 2

    recorder = EnvelopeRecorder() if args.backend == "claude_code" else None
    validator = build_plan_fit_validator(
        args.backend, model=args.model, **({"runner": recorder} if recorder else {}))
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def progress(run: int, n: int, total: int, record: dict[str, Any]) -> None:
        if (n + 1) % 20 == 0 or n + 1 == total:
            print(f"  pass {run + 1}/{args.repeat}: {n + 1}/{total}", flush=True)

    aborted = None
    try:
        records = run_corpus(
            validator, items, repeat=args.repeat, progress=progress,
            envelopes=recorder.envelopes if recorder else None,
            stop_after_failures=args.stop_after_failures or None, checkpoint=args.checkpoint)
    except RunAborted as stop:
        records, aborted = stop.records, str(stop)
        print(f"\nABORTED: {aborted}", file=sys.stderr)
    report = make_report(
        backend=args.backend, model=args.model, validator=validator, items=items,
        records=records, repeat=args.repeat, seed=args.seed, per_class=args.per_class,
        started=started)
    report["meta"]["aborted"] = aborted
    text = render(report)
    if aborted:
        text = f"**ABORTED after {len(records)} calls: {aborted}**\n\n" + text
    print("\n" + text)
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, default=str))
        print(f"wrote {args.json}")
    if args.report:
        args.report.write_text(text)
        print(f"wrote {args.report}")
    return 3 if aborted else 0


if __name__ == "__main__":
    raise SystemExit(main())
