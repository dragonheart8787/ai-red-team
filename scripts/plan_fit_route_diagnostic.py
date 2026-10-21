#!/usr/bin/env python
"""Which model answered, and why? A diagnostic for the ``claude_code`` plan-fit backend (D68 S7).

The first real baseline found that about one call in six is answered by a model other than the one
asked for. This reads the CLI's full event stream (``--output-format stream-json --verbose``) for
chosen corpus items and writes down, per call: the exact prompt sent, every model turn in order, why
a turn ended (``stop_reason`` and its ``stop_details``), the CLI's own notice of a fallback, the
answer, the cost, and the account's rate-limit windows as the CLI reports them.

    python scripts/plan_fit_route_diagnostic.py --pass1 docs/D68_S7_BASELINE/pass1.json \\
        --l4-plausible --repeat 1 --out out.json
    python scripts/plan_fit_route_diagnostic.py --items lure-L4-003 \\
        --model claude-sonnet-5-5 --repeat 3

``--model`` pins a model id instead of the alias; ``--schema reason`` adds a free-text ``reason``
field to the answer schema **for diagnosis only**: it changes the input, so what it shows is what a
model says when it is allowed to explain, not a replay of the production decision. The production
validator never asks for a reason (a sentence from a model on the way to a person is a persuasion
channel, design 2.4). Manual, real model, never in CI.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agents.llm import headless  # noqa: E402
from agents.llm.plan_fit_base import (  # noqa: E402
    PLAN_FIT_SCHEMA,
    SYSTEM_PROMPT,
    BasePlanFitValidator,
)
from tests.plan_fit_corpus import build_corpus  # noqa: E402

REASON_SCHEMA = {
    "type": "object",
    "properties": {
        "goal_fit": PLAN_FIT_SCHEMA["properties"]["goal_fit"],
        "reason": {"type": "string", "description": "Two sentences at most: why this value."},
    },
    "required": ["goal_fit", "reason"],
    "additionalProperties": False,
}


def build_command(prompt: str, *, model: str, schema_kind: str) -> list[str]:
    schema = REASON_SCHEMA if schema_kind == "reason" else PLAN_FIT_SCHEMA
    cmd = headless.build_command(
        prompt=prompt, system_prompt=SYSTEM_PROMPT, schema=schema, model=model)
    cmd = ["stream-json" if part == "json" else part for part in cmd]
    return [*cmd, "--verbose"]


def summarise_stream(lines: list[str]) -> dict[str, Any]:
    """The route of one call from its event stream. A pure function of the lines.

    ``turns`` are the model messages in order, each with the model that produced it, how it ended
    and what it said; ``fallback_notice`` is the CLI's own record of switching; thinking text is
    withheld by the service (only its size is kept).
    """
    turns: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    answer: Any = None
    out: dict[str, Any] = {"fallback_notice": False, "synthetic_user_messages": []}
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        kind = event.get("type")
        if kind == "rate_limit_event":
            info = event.get("rate_limit_info") or {}
            windows = info.get("unifiedWindows") or {}
            out["rate_limit"] = {
                "status": info.get("status"), "type": info.get("rateLimitType"),
                "overage": info.get("overageStatus"),
                "utilization": {k: (v or {}).get("utilization") for k, v in windows.items()}}
        elif kind == "system" and event.get("subtype") == "model_refusal_fallback":
            out["fallback_notice"] = True
            out["fallback_event"] = {k: event.get(k) for k in event if k not in (
                "uuid", "session_id", "type", "subtype")}
        elif kind == "user" and event.get("isSynthetic"):
            content = (event.get("message") or {}).get("content") or []
            out["synthetic_user_messages"].append(
                " ".join(c.get("text", "") for c in content if isinstance(c, dict))[:400])
        elif kind == "stream_event":
            inner = event.get("event") or {}
            if inner.get("type") == "message_start":
                message = inner.get("message") or {}
                turn = {"message_id": message.get("id"), "model": message.get("model"),
                        "stop_reason": None, "stop_details": None, "output_tokens": 0,
                        "thinking_tokens": 0, "text": "", "tool_calls": []}
                turns.append(turn)
                by_id[message.get("id")] = turn
            elif inner.get("type") == "message_delta" and turns:
                delta = inner.get("delta") or {}
                turn = by_id.get(event.get("api_message_id")) or turns[-1]
                turn["stop_reason"] = delta.get("stop_reason") or turn["stop_reason"]
                turn["stop_details"] = delta.get("stop_details") or turn["stop_details"]
                usage = inner.get("usage") or {}
                turn["output_tokens"] = usage.get("output_tokens", turn["output_tokens"])
                turn["thinking_tokens"] = (usage.get("output_tokens_details") or {}).get(
                    "thinking_tokens", turn["thinking_tokens"])
        elif kind == "assistant":
            message = event.get("message") or {}
            turn = by_id.get(message.get("id"))
            for block in message.get("content") or []:
                if block.get("type") == "text" and turn is not None:
                    turn["text"] += block.get("text", "")
                elif block.get("type") == "tool_use":
                    call = {"name": block.get("name"), "input": block.get("input")}
                    if turn is not None:
                        turn["tool_calls"].append(call)
                    if block.get("name") == "StructuredOutput":
                        answer = block.get("input")
        elif kind == "result":
            usage = event.get("modelUsage") or {}
            out["result"] = {
                "subtype": event.get("subtype"), "is_error": event.get("is_error"),
                "stop_reason": event.get("stop_reason"), "num_turns": event.get("num_turns"),
                "safety_stops": event.get("safety_stops"),
                "total_cost_usd": event.get("total_cost_usd"), "models": sorted(usage),
                "duration_ms": event.get("duration_ms"),
                "structured_output": event.get("structured_output")}
            if answer is None:
                answer = event.get("structured_output")
    out["turns"] = turns
    out["answer"] = answer
    out["refused_turns"] = [t["model"] for t in turns if t["stop_reason"] == "refusal"]
    out["answering_model"] = next(
        (t["model"] for t in reversed(turns) if t["tool_calls"]), None)
    out["took_fallback"] = bool(out["refused_turns"]) and out["answering_model"] not in (
        None, *out["refused_turns"])
    return out


#: Found in the CLI binary, not documented: stops the CLI from re-asking another model after the
#: service's safety classifier ended a turn. With it set a stopped call has no answer -- which is
#: the point of using it here: it shows what the asked-for model says when it is allowed to say it,
#: and how often it is not.
NO_FALLBACK_ENV = "CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK"


def run_one(item, *, model: str, schema_kind: str, no_fallback: bool = False,
            timeout: float = 120.0) -> dict[str, Any]:
    validator = BasePlanFitValidator()
    prompt = validator.build_prompt(query=item.query)
    command = build_command(prompt, model=model, schema_kind=schema_kind)
    started = time.monotonic()
    env = {**os.environ, **({NO_FALLBACK_ENV: "1"} if no_fallback else {})}
    done = subprocess.run(command, cwd=tempfile.mkdtemp(prefix="cyberorch-diag-"), text=True,
                          capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout, env=env)
    record = summarise_stream(done.stdout.splitlines())
    record.update(
        item_id=item.item_id, model_requested=model, schema=schema_kind, no_fallback=no_fallback,
        returncode=done.returncode, seconds=round(time.monotonic() - started, 2),
        stderr=(done.stderr or "")[:200],
        query={"goal": item.query.goal, "task_action": item.query.task_action,
               "task_target": item.query.task_target,
               "proposal_action": item.query.proposal_action,
               "proposal_target": item.query.proposal_target},
        prompt_sent=prompt)
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--items", nargs="*", default=[], help="corpus item ids")
    parser.add_argument("--pass1", type=Path, default=None,
                        help="a baseline record, for --l4-plausible / --l4-all")
    parser.add_argument("--l4-plausible", action="store_true",
                        help="the L4 items the baseline answered plausible")
    parser.add_argument("--l4-all", action="store_true", help="every L4 item in the baseline")
    parser.add_argument("--model", default="sonnet", help="an alias or a pinned model id")
    parser.add_argument("--schema", choices=["production", "reason"], default="production")
    parser.add_argument("--no-refusal-fallback", action="store_true",
                        help=f"set {NO_FALLBACK_ENV}=1: a call the classifier stops has no answer")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--max-calls", type=int, default=120)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    ids = list(args.items)
    if args.l4_plausible or args.l4_all:
        if not args.pass1:
            parser.error("--l4-plausible / --l4-all need --pass1")
        records = json.loads(args.pass1.read_text())["records"]
        ids += [r["item_id"] for r in records if r["item_id"].startswith("lure-L4")
                and (args.l4_all or r["goal_fit"] == "plausible")]
    corpus = {i.item_id: i for i in build_corpus()}
    unknown = [i for i in ids if i not in corpus]
    if unknown:
        parser.error(f"unknown item(s): {unknown}")
    calls = len(ids) * args.repeat
    print(f"model={args.model} schema={args.schema} no_fallback={args.no_refusal_fallback} "
          f"items={len(ids)} repeat={args.repeat} calls={calls}")
    if calls > args.max_calls:
        print(f"refusing: above --max-calls {args.max_calls}", file=sys.stderr)
        return 2
    results = []
    for run in range(args.repeat):
        for iid in ids:
            record = run_one(corpus[iid], model=args.model, schema_kind=args.schema,
                             no_fallback=args.no_refusal_fallback)
            record["run"] = run
            results.append(record)
            print(f"  {iid} run {run}: answer={record['answer']} "
                  f"refused={record['refused_turns']} by={record['answering_model']} "
                  f"fallback={record['took_fallback']} rc={record['returncode']}", flush=True)
    if args.out:
        args.out.write_text(json.dumps(results, indent=2))
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
