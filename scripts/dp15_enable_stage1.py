#!/usr/bin/env python
"""D68 DP-15 enable-decision, stage 1 (registration 1, C1): the plan of the run, as a dry run.

    PYTHONPATH=. python scripts/dp15_enable_stage1.py --wordings-dir DIR
    PYTHONPATH=. python scripts/dp15_enable_stage1.py --wordings-dir DIR --classes network.scan

**Read ``docs/D68_DP15_RECORD_MODE/ENABLE_DECISION_PLAN.md`` first; it is a DRAFT** (the owner has
not said 定稿) and so is this. Only the dry run exists. ``--execute`` is refused: the run itself is
not built, and nothing here calls a model, publishes a policy or writes to a database.

What the dry run does: it reads the wording files (one JSON per class, ``DIR/<class>.json``), checks
them against the plan's rules, allocates the targets (three different ones per wording), picks the
Leg B subset, and prints the calls, the cost and time estimates and the hard caps. Before that, and
whatever else is true, it prints the database it is connected to, the migration revision, and the
effective ``goal_fit_enforce`` / ``task_relation_enforce`` (read only, the guards of
``dp15_record_mode.py``), and it refuses when ``goal_fit_enforce`` is not off.

The rules a wording file must meet (ENABLE_DECISION_PLAN.md 3.2): exactly 60 wordings per class;
each holds the target token ``{t}`` exactly once; none is within token-Jaccard 0.6 of another in any
class, nor of a wording the validator has already been measured on (the S7 corpus templates and the
DP-15 run-1 sentences). The hash of each file is printed so that the final lists can be registered
before the first call.

Exit status: 0 the plan is sound, 1 a check or a guard refused (nothing was sent), 2 usage / not
built.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
import sys
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

# -- the registered numbers (ENABLE_DECISION_PLAN.md, stage 1; DRAFT) ------------------------------
CLASSES = ("network.scan", "code.scan", "code.secrets")
WORDINGS_PER_CLASS = 60
REPEATS = 3                     # each wording asked three times, each time with a different target
LEG_B_PER_CLASS = 10            # wordings (first repeat) also sent through propose_action
JACCARD_LIMIT = 0.6             # two wordings at or above this are one wording
TARGET_TOKEN = "{t}"
KINDS = ("ip", "cidr", "fqdn")
SEED = 20261025                 # written down before any draw
COST_PER_CALL_USD = 0.0088      # list price per call, S7: US$4.23 for 480
SECONDS_RUN1 = 246.0 / 150      # DP-15 run 1: 150 calls in 4.1 minutes, two in flight
SECONDS_S7_SEQUENTIAL = 3.6     # S7: 480 calls in 29 minutes, one at a time
DEFAULT_DIR = REPO_ROOT / "docs" / "D68_DP15_RECORD_MODE" / "stage1_wordings"

EXIT_OK, EXIT_REFUSED, EXIT_USAGE = 0, 1, 2


@dataclass(frozen=True)
class Wording:
    text: str
    kinds: tuple[str, ...]
    source: str                 # "real" (written by a model Supervisor) or "hand"


@dataclass(frozen=True)
class Call:
    leg: str                    # "A" the validator directly; "B" through propose_action
    cls: str
    wording: int
    repeat: int
    target: str


# -- wording files ---------------------------------------------------------------------------------

def tokens(text: str) -> frozenset[str]:
    return frozenset(re.findall(r"[a-z{}]+", text.lower()))


def jaccard(a: str, b: str) -> float:
    ta, tb = tokens(a), tokens(b)
    return len(ta & tb) / len(ta | tb) if (ta | tb) else 1.0


def normal(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def read_wordings(path: Path) -> tuple[list[Wording], str]:
    """The wordings of one file and the sha256 of its bytes."""
    raw = path.read_bytes()
    document = json.loads(raw)
    out = [Wording(str(w["text"]), tuple(w.get("kinds", ())), str(w.get("source", "")))
           for w in document["wordings"]]
    return out, hashlib.sha256(raw).hexdigest()


def seen_wordings() -> list[str]:
    """Wordings the validator has already been measured on: the S7 corpus templates and the
    sentences of DP-15 run 1. A new wording close to one of these is not an independent test."""
    from scripts import dp15_record_mode as rm
    from tests.plan_fit_corpus import SCENARIOS

    seen = [template for _, _, _, templates in SCENARIOS for template in templates]
    seen += [sentence.replace("{host}", TARGET_TOKEN) for sentence in rm.GOALS.values()]
    return seen


def check_wordings(per_class: dict[str, list[Wording]], *, expected: int = WORDINGS_PER_CLASS,
                   seen: Sequence[str] | None = None) -> list[str]:
    """What is wrong with the wording lists (empty: nothing)."""
    problems: list[str] = []
    prior = list(seen_wordings() if seen is None else seen)
    flat: list[tuple[str, int, str]] = []
    for cls, wordings in per_class.items():
        if len(wordings) != expected:
            problems.append(f"{cls}: {len(wordings)} wordings, the plan needs exactly {expected}")
        for i, w in enumerate(wordings):
            if w.text.count(TARGET_TOKEN) != 1:
                problems.append(f"{cls}#{i}: the target token {TARGET_TOKEN} must occur exactly "
                                f"once (it occurs {w.text.count(TARGET_TOKEN)} times)")
            if not w.kinds or any(k not in KINDS for k in w.kinds):
                problems.append(f"{cls}#{i}: target kinds {list(w.kinds)} are not a non-empty "
                                f"subset of {list(KINDS)}")
            for p in prior:
                if jaccard(w.text, p) >= JACCARD_LIMIT:
                    problems.append(f"{cls}#{i}: too close to a wording the validator was "
                                    f"already measured on ({p!r})")
                    break
            flat.append((cls, i, w.text))
    for x in range(len(flat)):
        for y in range(x + 1, len(flat)):
            (ca, ia, ta), (cb, ib, tb) = flat[x], flat[y]
            if normal(ta) == normal(tb):
                problems.append(f"{ca}#{ia} and {cb}#{ib} are the same wording")
            elif jaccard(ta, tb) >= JACCARD_LIMIT:
                problems.append(f"{ca}#{ia} and {cb}#{ib} are near-duplicates (token-Jaccard "
                                f">= {JACCARD_LIMIT})")
    return problems


# -- targets and the plan --------------------------------------------------------------------------

def _hostname_pools() -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    from tests.plan_fit_corpus import _ROLES_PLAIN, _ROLES_SENSITIVE, _ZONES

    return _ROLES_PLAIN, _ROLES_SENSITIVE, _ZONES


def make_target(kind: str, rng: random.Random) -> str:
    if kind == "ip":
        return f"10.{rng.randint(1, 250)}.{rng.randint(0, 250)}.{rng.randint(2, 250)}"
    if kind == "cidr":
        return f"10.{rng.randint(1, 250)}.{rng.randint(0, 250)}.0/24"
    plain, sensitive, zones = _hostname_pools()
    role = rng.choice(plain + sensitive)
    return f"{role}{rng.randint(1, 19):02d}.{rng.choice(zones)}.example"


def allocate_targets(per_class: dict[str, list[Wording]], seed: int = SEED,
                     repeats: int = REPEATS) -> dict[tuple[str, int, int], str]:
    """``(class, wording, repeat) -> target``: three different targets per wording, none used
    twice in the whole plan, drawn from a seed. A wording that fits an address and a network meets
    both kinds."""
    out: dict[tuple[str, int, int], str] = {}
    used: set[str] = set()
    for cls, wordings in per_class.items():
        for i, w in enumerate(wordings):
            kinds = sorted(set(w.kinds))
            for r in range(repeats):
                rng = random.Random(f"{seed}|{cls}|{i}|{r}")
                kind = kinds[(i + r) % len(kinds)]
                target = make_target(kind, rng)
                while target in used:
                    target = make_target(kind, rng)
                used.add(target)
                out[(cls, i, r)] = target
    return out


def build_plan(per_class: dict[str, list[Wording]], seed: int = SEED,
               leg_b_per_class: int = LEG_B_PER_CLASS, repeats: int = REPEATS) -> list[Call]:
    """Leg A: every wording x every repeat, repeat by repeat and class by class, so that a stop
    leaves balanced coverage. Leg B: the first repeat of ``leg_b_per_class`` wordings per class,
    chosen from the seed, after Leg A."""
    targets = allocate_targets(per_class, seed, repeats)
    calls: list[Call] = []
    longest = max((len(w) for w in per_class.values()), default=0)
    for r in range(repeats):
        for i in range(longest):
            for cls, wordings in per_class.items():
                if i < len(wordings):
                    calls.append(Call("A", cls, i, r, targets[(cls, i, r)]))
    for cls, wordings in per_class.items():
        pick = random.Random(f"{seed}|legB|{cls}").sample(range(len(wordings)),
                                                          min(leg_b_per_class, len(wordings)))
        calls += [Call("B", cls, i, 0, targets[(cls, i, 0)]) for i in sorted(pick)]
    return calls


def caps(planned_calls: int) -> dict[str, float]:
    """Hard caps from the planned number of calls: 10% more runs (rounded up to ten), 1.5 times the
    list-price cost (to the nearest 0.5), and the sequential S7 rate plus 30% (to five minutes)."""
    cost = planned_calls * COST_PER_CALL_USD
    return {
        "runs": math.ceil(planned_calls * 1.1 / 10) * 10,
        "usd": math.floor(cost * 1.5 / 0.5 + 0.5) * 0.5,
        "minutes": math.ceil(planned_calls * SECONDS_S7_SEQUENTIAL * 1.3 / 300) * 5,
    }


def estimate(planned_calls: int) -> dict[str, float]:
    return {"usd": round(planned_calls * COST_PER_CALL_USD, 2),
            "minutes_low": round(planned_calls * SECONDS_RUN1 / 60, 1),
            "minutes_high": round(planned_calls * SECONDS_S7_SEQUENTIAL / 2 / 60, 1)}


# -- the dry run -----------------------------------------------------------------------------------

def render_plan(per_class: dict[str, list[Wording]], hashes: dict[str, str],
                calls: list[Call], problems: list[str]) -> list[str]:
    lines = [f"classes: {', '.join(per_class)}; {WORDINGS_PER_CLASS} wordings per class x "
             f"{REPEATS} repeats (a different target each time); "
             f"Leg B: {LEG_B_PER_CLASS} per class"]
    for cls, wordings in per_class.items():
        kinds = Counter(k for w in wordings for k in w.kinds)
        sources = Counter(w.source for w in wordings)
        lines.append(f"  {cls:<13}{len(wordings):>3} wordings  sha256 {hashes.get(cls, '?')}  "
                     f"sources {dict(sorted(sources.items()))}  allowed kinds "
                     f"{dict(sorted(kinds.items()))}")
    leg_a = sum(c.leg == "A" for c in calls)
    leg_b = sum(c.leg == "B" for c in calls)
    lines.append(f"calls: Leg A {leg_a} (the validator directly; writes nothing), Leg B {leg_b} "
                 f"(through propose_action; needs a clean database), total {len(calls)}")
    by_kind = Counter("cidr" if "/" in c.target else ("fqdn" if re.search(r"[a-z]", c.target)
                                                      else "ip") for c in calls if c.leg == "A")
    lines.append(f"targets: {len({c.target for c in calls if c.leg == 'A'})} distinct for the "
                 f"{leg_a} calls of Leg A (Leg B reuses the first target of its wordings, so that "
                 f"the two paths are compared on the same query); Leg A by kind "
                 f"{dict(sorted(by_kind.items()))}")
    for cls, wordings in per_class.items():
        for i in range(min(2, len(wordings))):
            mine = [c.target for c in calls if c.leg == "A" and c.cls == cls and c.wording == i]
            lines.append(f"  e.g. {cls} wording #{i}: {wordings[i].text!r} -> {mine}")
    cap = caps(len(calls))
    est = estimate(len(calls))
    lines.append(f"estimate: US${est['usd']} list price, {est['minutes_low']} to "
                 f"{est['minutes_high']} minutes at two in flight")
    lines.append(f"hard caps: {int(cap['runs'])} CLI runs, US${cap['usd']:.2f}, "
                 f"{int(cap['minutes'])} minutes (a cap may be lowered, never raised)")
    lines.append("order: repeat by repeat, class by class (first six: " + ", ".join(
        f"{c.cls}#{c.wording}.{c.repeat}" for c in calls[:6]) + ")")
    lines.append("a stop is final: no retry, no resume; nothing is printed while a stage runs but "
                 "a progress count")
    lines.append("plan checks: " + ("ok" if not problems else f"{len(problems)} problem(s)"))
    return lines


def dry_run(args: argparse.Namespace) -> int:
    from scripts import dp15_record_mode as rm

    print("DRY RUN (stage 1, registration 1: DRAFT, not pre-registered) -- no model is called, "
          "nothing is written; the database is only read.")
    refusals: list[str] = []
    try:
        from control_plane.config import load_dotenv

        load_dotenv()
        banner, guards = rm.check_startup(allow_nonempty=True, rehearsal=False)
        print("\n".join(banner))
        refusals += guards
        print("startup guards: " + ("ok -- goal_fit_enforce is off" if not guards else "REFUSED"))
    except Exception as exc:
        print(f"database: NOT READ ({type(exc).__name__}) -- the guards could not be checked")
        refusals.append("the database could not be read: goal_fit_enforce was not checked")
    classes = tuple(c.strip() for c in args.classes.split(",") if c.strip())
    unknown = [c for c in classes if c not in CLASSES]
    if unknown:
        print(f"refused: unknown class(es) {unknown}; the plan has {list(CLASSES)}",
              file=sys.stderr)
        return EXIT_USAGE
    per_class: dict[str, list[Wording]] = {}
    hashes: dict[str, str] = {}
    problems: list[str] = []
    for cls in classes:
        path = Path(args.wordings_dir) / f"{cls}.json"
        if not path.exists():
            problems.append(f"{cls}: no wording file at {path}")
            continue
        per_class[cls], hashes[cls] = read_wordings(path)
    problems += check_wordings(per_class)
    calls = build_plan(per_class, args.seed) if per_class and not problems else []
    for line in render_plan(per_class, hashes, calls, problems):
        print(line)
    for problem in problems:
        print(f"PLAN PROBLEM: {problem}", file=sys.stderr)
    for refusal in refusals:
        print(f"REFUSED: {refusal}", file=sys.stderr)
    print("execution: not built. The run itself is written only after the owner says 定稿.")
    return EXIT_REFUSED if problems or refusals else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--wordings-dir", default=str(DEFAULT_DIR),
                        help="directory with <class>.json wording files")
    parser.add_argument("--classes", default=",".join(CLASSES),
                        help="comma list; 'network.scan' alone is the case without code.*")
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--execute", action="store_true", help="refused: the run is not built")
    args = parser.parse_args(argv)
    if args.execute:
        print("refused: the stage-1 run is not built; this tool plans and checks only, and the "
              "plan is a DRAFT until the owner says 定稿", file=sys.stderr)
        return EXIT_USAGE
    return dry_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
