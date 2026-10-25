#!/usr/bin/env python
"""D68 DP-15 enable-decision, stage 1: the one analysis, C1.

    PYTHONPATH=. python scripts/dp15_stage1_analysis.py \\
        --record docs/D68_DP15_RECORD_MODE/stage1/record.jsonl

Read ``docs/D68_DP15_RECORD_MODE/ENABLE_DECISION_PLAN.md`` (sections 2, 4, 5, 9) first. This script
reads the item-level record the stage-1 runner wrote (``dp15_stage1_run.py``) and prints, once, the
verdict of **C1** -- *met*, *not met* or *not evaluable* -- with the numbers that carry it. It calls
no model and does not touch a database; the record is the only input.

What is counted (plan section 2). A call is *marked* when the validator's answer is not
``plausible`` (``implausible``, ``insufficient_context`` or failed -- refusal or unclassified). A
transport loss is not an observation: reported, in no denominator. A wording is asked three times;
it is **marked** when at least half of its non-transport calls are marked (more than half, and a
tie counts as marked) and **undecided** when it has no non-transport call.

C1 (the only threshold of stage 1): over the decided wordings, the Wilson 95% upper bound **and**
the exact (Clopper-Pearson) 95% upper bound of the share of marked wordings are both at most 15%
(at 60 decided wordings: at most 3 marked). **Not evaluable** when fewer than 90% of the planned
wordings are decided (54 of 60). The two sources of the wordings, ``real`` (28) and ``hand`` (32),
are reported as two rows beside the pooled row; neither row is a threshold.

**One look.** The first run of this script on a record is the look; it is written to
``<record>.looks.jsonl`` with the record's hash. A later run needs ``--reason "..."``, and both
looks stay in that file (plan section 9). No exit status depends on the verdict: 0 the analysis
ran, 2 usage / the record cannot be read.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import sys
import time
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

# -- the registered numbers (ENABLE_DECISION_PLAN.md 5.1) -----------------------------------------
C1_THRESHOLD = 0.15             # a policy value the owner delegated; not a statistical constant
Z95 = 1.959964                  # two-sided 95%
EVALUABLE_SHARE = 0.9           # fewer decided wordings than this share of the plan: not evaluable
BOOTSTRAP_RESAMPLES = 2000
BOOTSTRAP_SEED = 20261025
LARGE_DIFFERENCE = "the two Wilson 95% intervals do not overlap"

PLAUSIBLE, IMPLAUSIBLE, INSUFFICIENT = "plausible", "implausible", "insufficient_context"
FAILED, TRANSPORT = "failed", "transport"
MET, NOT_MET, NOT_EVALUABLE = "met", "not met", "not evaluable"
EXIT_OK, EXIT_USAGE = 0, 2


# -- intervals -------------------------------------------------------------------------------------

def wilson(k: int, n: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score interval of k of n."""
    if n <= 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def _cdf(k: int, n: int, p: float) -> float:
    return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k + 1))


def _bisect(f, lo: float = 0.0, hi: float = 1.0) -> float:
    for _ in range(80):
        mid = (lo + hi) / 2
        if f(mid):
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def exact(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    """Clopper-Pearson interval of k of n (two-sided, ``1 - alpha``)."""
    if n <= 0:
        return (0.0, 1.0)
    upper = 1.0 if k >= n else _bisect(lambda p: _cdf(k, n, p) > alpha / 2)
    lower = 0.0 if k <= 0 else _bisect(lambda p: 1 - _cdf(k - 1, n, p) < alpha / 2)
    return (lower, upper)


def allowed_marked(n: int, threshold: float = C1_THRESHOLD) -> int:
    """The most marked wordings of ``n`` for which both upper bounds are at most ``threshold``
    (-1 when not even none does)."""
    best = -1
    for k in range(n + 1):
        if wilson(k, n)[1] <= threshold and exact(k, n)[1] <= threshold:
            best = k
        else:
            break
    return best


# -- the record ------------------------------------------------------------------------------------

def read_record(path: Path) -> tuple[dict, list[dict], dict | None, str]:
    """``(header, call lines, footer or None, sha256 of the file)``."""
    raw = path.read_bytes()
    header, calls, footer = None, [], None
    for line in raw.decode().splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        kind = entry.get("type")
        if kind == "header":
            header = entry
        elif kind == "call":
            calls.append(entry)
        elif kind == "footer":
            footer = entry
    if header is None:
        raise ValueError("the record has no header line")
    return header, calls, footer, hashlib.sha256(raw).hexdigest()


def label(call: dict) -> str:
    """One word per call: an answer, ``failed:<kind>`` or ``transport``."""
    value = call.get("goal_fit")
    if value in (PLAUSIBLE, IMPLAUSIBLE, INSUFFICIENT):
        return value
    kind = call.get("failure_kind") or "unclassified"
    return TRANSPORT if kind == TRANSPORT else f"{FAILED}:{kind}"


def is_marked(lab: str) -> bool:
    return lab != PLAUSIBLE and lab != TRANSPORT


# -- the analysis (pure) ---------------------------------------------------------------------------

def wording_table(header: dict, calls: list[dict]) -> dict[int, dict]:
    """Per planned wording: its source, its non-transport calls, how many were marked, transport
    losses, and its mark (``True`` / ``False`` / ``None`` for undecided). Leg A only."""
    table = {w["i"]: {"source": w["source"], "calls": 0, "marked": 0, "transport": 0}
             for w in header["wordings"]}
    for c in calls:
        if c.get("leg") != "A" or c.get("wording") not in table:
            continue
        row, lab = table[c["wording"]], label(c)
        if lab == TRANSPORT:
            row["transport"] += 1
        else:
            row["calls"] += 1
            row["marked"] += is_marked(lab)
    for row in table.values():
        # more than half marked, and a tie counts as marked; no call that counts: undecided
        row["mark"] = (row["marked"] * 2 >= row["calls"]) if row["calls"] else None
    return table


def row_stats(table: dict[int, dict], source: str | None) -> dict:
    mine = [r for r in table.values() if source is None or r["source"] == source]
    decided = [r for r in mine if r["mark"] is not None]
    k, n = sum(bool(r["mark"]) for r in decided), len(decided)
    return {"planned": len(mine), "decided": n, "undecided": len(mine) - n, "marked": k,
            "point": (k / n) if n else None, "wilson": wilson(k, n), "exact": exact(k, n),
            "marked_calls": sum(r["marked"] for r in mine),
            "counted_calls": sum(r["calls"] for r in mine),
            "transport": sum(r["transport"] for r in mine)}


def bootstrap_call_share(table: dict[int, dict], resamples: int = BOOTSTRAP_RESAMPLES,
                         seed: int = BOOTSTRAP_SEED) -> tuple[float, float] | None:
    """A 95% percentile interval of the share of marked calls (of the non-transport ones),
    resampling wordings with their calls (the unit is the wording)."""
    rows = [(r["marked"], r["calls"]) for r in table.values() if r["calls"]]
    if not rows:
        return None
    rng = random.Random(seed)
    shares = []
    for _ in range(resamples):
        draw = [rows[rng.randrange(len(rows))] for _ in rows]
        total = sum(c for _, c in draw)
        shares.append(sum(m for m, _ in draw) / total if total else 0.0)
    shares.sort()
    return (shares[int(0.025 * (resamples - 1))], shares[int(0.975 * (resamples - 1))])


def difference_label(real: dict, hand: dict) -> str:
    """Whether the two sources differ "largely" (their Wilson intervals do not overlap) and which
    way. A label on the report; it is used for nothing else."""
    if not real["decided"] or not hand["decided"]:
        return "not assessable (a row has no decided wordings)"
    (rl, rh), (hl, hh) = real["wilson"], hand["wilson"]
    if hl > rh:
        return "LARGE: the hand-written row is above the real row (intervals do not overlap)"
    if rl > hh:
        return "LARGE: the real row is above the hand-written row (intervals do not overlap)"
    return "not large (the intervals overlap)"


def verdict(pooled: dict, planned: int) -> tuple[str, str]:
    """``(C1 verdict, the reason in a line)``."""
    need = math.ceil(EVALUABLE_SHARE * planned)
    if pooled["decided"] < need:
        return NOT_EVALUABLE, (f"{pooled['decided']} of {planned} wordings are decided, fewer than "
                               f"the {need} (90%) the plan needs")
    wil, ex = pooled["wilson"][1], pooled["exact"][1]
    k, n = pooled["marked"], pooled["decided"]
    ok = wil <= C1_THRESHOLD and ex <= C1_THRESHOLD
    return (MET if ok else NOT_MET,
            f"{k} of {n} decided wordings marked; Wilson upper {wil:.1%}, exact upper {ex:.1%}, "
            f"threshold {C1_THRESHOLD:.0%} for both (at {n} decided wordings at most "
            f"{allowed_marked(n)} may be marked)")


def agreement(calls: list[dict]) -> dict:
    """Leg B against Leg A: for each Leg B call, Leg A's first repeat of the same wording. Counted
    where neither is a transport loss; reported, no threshold."""
    first = {c["wording"]: label(c) for c in calls if c.get("leg") == "A" and c.get("repeat") == 0}
    pairs = disagree = lost = 0
    for c in calls:
        if c.get("leg") != "B":
            continue
        a, b = first.get(c["wording"]), label(c)
        if a is None or a == TRANSPORT or b == TRANSPORT:
            lost += 1
            continue
        pairs += 1
        # a failure is a failure whatever its kind: the stored answer carries no kind
        same = a == b or (a.startswith(FAILED) and b.startswith(FAILED))
        disagree += not same
    return {"pairs": pairs, "agree": pairs - disagree, "not_compared": lost,
            "leg_b_calls": sum(c.get("leg") == "B" for c in calls)}


def analyse(header: dict, calls: list[dict], footer: dict | None) -> dict:
    table = wording_table(header, calls)
    pooled, real, hand = row_stats(table, None), row_stats(table, "real"), row_stats(table, "hand")
    leg_a = [c for c in calls if c.get("leg") == "A"]
    split = Counter(label(c) for c in leg_a)
    decided_rows = [r for r in table.values() if r["calls"]]
    c1, reason = verdict(pooled, len(table))
    return {
        "c1": c1, "reason": reason, "pooled": pooled, "real": real, "hand": hand,
        "difference": difference_label(real, hand),
        "split_calls": dict(sorted(split.items())),
        "bootstrap": bootstrap_call_share(table),
        "split_wordings": sum(0 < r["marked"] < r["calls"] for r in decided_rows),
        "undecided": sorted(i for i, r in table.items() if r["mark"] is None),
        "agreement": agreement(calls), "leg_a_calls": len(leg_a),
        "complete": footer is not None and footer.get("stopped") is None,
        "stopped": footer.get("stopped") if footer else "no footer: the run did not end cleanly",
        "usage": footer.get("usage") if footer else None,
        "models": footer.get("models") if footer else None,
    }


# -- the report ------------------------------------------------------------------------------------

def _pct(x: float | None) -> str:
    return "-" if x is None else f"{x:.1%}"


def _interval(pair: tuple[float, float]) -> str:
    return f"{pair[0]:.1%} - {pair[1]:.1%}"


def render(result: dict, header: dict, record_sha: str) -> list[str]:
    lines = ["DP-15 stage 1: the one analysis (C1)",
             f"record sha256 {record_sha}",
             f"wording file sha256 {header.get('wordings_sha256')}; prompt digest "
             f"{header.get('prompt_digest')}; backend {header.get('backend')}; model alias "
             f"{header.get('model_alias')}; CLI {header.get('cli_version')}; refusal fallback "
             f"{header.get('fallback')}; database {header.get('database')} "
             f"(migration {header.get('migration')}); started {header.get('started_at')}",
             f"plan commit {header.get('plan_commit')}; seed {header.get('seed')}",
             ""]
    lines.append(f"C1: {result['c1'].upper()} -- {result['reason']}")
    lines.append("")
    lines.append(f"{'row':<26}{'wordings':>9}{'decided':>9}{'marked':>8}{'point':>8}  "
                 f"{'Wilson 95%':<18}{'exact 95%':<18}")
    for name, key in (("real (model Supervisor)", "real"), ("hand-written", "hand"),
                      ("network.scan pooled (C1)", "pooled")):
        r = result[key]
        lines.append(f"{name:<26}{r['planned']:>9}{r['decided']:>9}{r['marked']:>8}"
                     f"{_pct(r['point']):>8}  {_interval(r['wilson']):<18}"
                     f"{_interval(r['exact']):<18}")
    lines.append(f"difference between the two rows: {result['difference']}")
    lines.append("  How to read it (plan 5.3): a label on the report and nothing else. It is "
                 "not used to resample, drop or reweight a row, to replace the pooled row, to "
                 "change a threshold or a wording, or to run the stage again. C1 stands on the "
                 "pooled row.")
    lines.append("")
    lines.append("reported, not thresholds:")
    for name, key in (("real", "real"), ("hand-written", "hand"), ("pooled", "pooled")):
        r = result[key]
        lines.append(f"  {name}: marked calls {r['marked_calls']} of {r['counted_calls']} "
                     f"non-transport calls; transport losses {r['transport']}")
    boot = result["bootstrap"]
    lines.append("  call-level marked share, pooled, with a 95% bootstrap interval over "
                 "wordings: " + ("-" if boot is None else f"{_interval(boot)}"))
    lines.append("  calls by outcome: " + ", ".join(
        f"{k} {v}" for k, v in result["split_calls"].items()))
    lines.append(f"  split wordings (their calls disagree): {result['split_wordings']}; undecided "
                 f"wordings: {len(result['undecided'])} {result['undecided'] or ''}".rstrip())
    ag = result["agreement"]
    lines.append(f"  Leg B (through propose_action) agrees with Leg A's first repeat: "
                 f"{ag['agree']} of {ag['pairs']} compared pairs ({ag['leg_b_calls']} Leg B calls, "
                 f"{ag['not_compared']} not compared); no threshold")
    lines.append("")
    lines.append(("the run completed" if result["complete"] else
                  f"THE RUN STOPPED EARLY: {result['stopped']}") +
                 f"; Leg A calls recorded {result['leg_a_calls']}")
    usage = result["usage"]
    if usage:
        lines.append(f"usage: {usage.get('cli_runs')} CLI runs; list-price-equivalent cost "
                     f"US${float(usage.get('cost_usd') or 0):.2f} (not an invoice); tokens in "
                     f"{usage.get('input_tokens')}, out {usage.get('output_tokens')}, cache read "
                     f"{usage.get('cache_read_tokens')}, cache creation "
                     f"{usage.get('cache_creation_tokens')}; models named in the envelopes: "
                     f"{', '.join(result['models'] or []) or '(none)'}")
    lines.append("This verdict says only whether C1 as registered was met. It does not say whether "
                 "goal_fit_enforce may be turned on.")
    return lines


# -- the one look ----------------------------------------------------------------------------------

def ledger_path(record: Path) -> Path:
    return record.with_name(record.name + ".looks.jsonl")


def read_ledger(record: Path) -> list[dict]:
    path = ledger_path(record)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def look(record: Path, *, reason: str | None = None, out=print) -> int:
    """The analysis of one record. The first look needs no reason; every later one does, and all
    are kept in the ledger beside the record."""
    try:
        header, calls, footer, sha = read_record(record)
    except (OSError, ValueError) as exc:
        print(f"refused: the record cannot be read ({type(exc).__name__}: {exc})", file=sys.stderr)
        return EXIT_USAGE
    earlier = read_ledger(record)
    if earlier and not (reason or "").strip():
        print(f"refused: this record was already looked at {len(earlier)} time(s) "
              f"(first on {earlier[0]['at']}, verdict {earlier[0]['verdict']!r}); another look "
              "needs --reason \"...\", written down, and both looks are kept", file=sys.stderr)
        return EXIT_USAGE
    result = analyse(header, calls, footer)
    number = len(earlier) + 1
    lines = [f"look {number} of this record" + (f" (reason: {reason.strip()})" if earlier else "")]
    if earlier and any(e["record_sha256"] != sha for e in earlier):
        lines.append("NOTE: the record has changed since an earlier look")
    lines += render(result, header, sha)
    for line in lines:
        out(line)
    with ledger_path(record).open("a") as handle:
        handle.write(json.dumps({
            "look": number, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "record_sha256": sha, "verdict": result["c1"], "reason": (reason or "").strip() or None,
        }) + "\n")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--record", required=True, type=Path, help="the stage-1 record (JSONL)")
    parser.add_argument("--reason", default=None,
                        help="why another look (required after the first)")
    args = parser.parse_args(argv)
    return look(args.record, reason=args.reason)


if __name__ == "__main__":
    raise SystemExit(main())
