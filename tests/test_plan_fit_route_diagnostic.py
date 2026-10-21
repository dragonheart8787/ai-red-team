"""The route diagnostic's parser (D68 S7), offline: it reads an event stream, it calls nothing."""

from __future__ import annotations

import json

from scripts import plan_fit_route_diagnostic as diag


def ev(**kw):
    return json.dumps(kw)


REFUSED_THEN_ANSWERED = [
    ev(type="rate_limit_event", rate_limit_info={
        "status": "allowed", "rateLimitType": "five_hour", "overageStatus": "rejected",
        "unifiedWindows": {"five_hour": {"utilization": 0.13}, "seven_day": {"utilization": 0.4}}}),
    ev(type="stream_event", api_message_id="m1", event={
        "type": "message_start", "message": {"id": "m1", "model": "claude-sonnet-5-5"}}),
    ev(type="stream_event", api_message_id="m1", event={
        "type": "message_delta",
        "delta": {"stop_reason": "refusal",
                  "stop_details": {"type": "refusal", "category": "cyber"}},
        "usage": {"output_tokens": 0}}),
    ev(type="user", isSynthetic=True, message={"content": [
        {"type": "text", "text": "Your response above was stopped by a safety classifier"}]}),
    ev(type="system", subtype="model_refusal_fallback", from_model="claude-sonnet-5-5"),
    ev(type="stream_event", api_message_id="m2", event={
        "type": "message_start", "message": {"id": "m2", "model": "claude-sonnet-5"}}),
    ev(type="assistant", message={"id": "m2", "model": "claude-sonnet-5", "content": [
        {"type": "tool_use", "name": "StructuredOutput", "input": {"goal_fit": "plausible"}}]}),
    ev(type="stream_event", api_message_id="m2", event={
        "type": "message_delta", "delta": {"stop_reason": "tool_use"},
        "usage": {"output_tokens": 275, "output_tokens_details": {"thinking_tokens": 216}}}),
    ev(type="result", subtype="success", is_error=False, num_turns=3, safety_stops=2,
       total_cost_usd=0.0369, modelUsage={"claude-sonnet-5-5": {}, "claude-sonnet-5": {}},
       structured_output={"goal_fit": "plausible"}),
]


def test_a_refusal_followed_by_another_model_is_read_as_a_fallback():
    got = diag.summarise_stream(REFUSED_THEN_ANSWERED)
    assert got["took_fallback"] is True
    assert got["refused_turns"] == ["claude-sonnet-5-5"]
    assert got["answering_model"] == "claude-sonnet-5"
    assert got["answer"] == {"goal_fit": "plausible"}
    assert got["fallback_notice"] is True and len(got["synthetic_user_messages"]) == 1
    assert [t["model"] for t in got["turns"]] == ["claude-sonnet-5-5", "claude-sonnet-5"]
    assert got["turns"][0]["stop_details"]["category"] == "cyber"
    assert got["turns"][1]["thinking_tokens"] == 216
    assert got["rate_limit"]["utilization"] == {"five_hour": 0.13, "seven_day": 0.4}
    assert got["result"]["safety_stops"] == 2


def test_a_call_with_no_refusal_is_not_a_fallback():
    lines = [line for line in REFUSED_THEN_ANSWERED
             if '"m1"' not in line and "model_refusal_fallback" not in line
             and "isSynthetic" not in line]
    got = diag.summarise_stream(lines)
    assert got["took_fallback"] is False and got["refused_turns"] == []
    assert got["answering_model"] == "claude-sonnet-5"


def test_garbage_lines_are_skipped_not_fatal():
    got = diag.summarise_stream(["", "not json", "[]", *REFUSED_THEN_ANSWERED[:2]])
    assert got["turns"][0]["model"] == "claude-sonnet-5-5"


def test_the_command_pins_the_model_and_asks_for_the_stream_and_the_reason_only_on_request():
    prod = diag.build_command("p", model="claude-sonnet-5-5", schema_kind="production")
    assert prod[prod.index("--model") + 1] == "claude-sonnet-5-5"
    assert prod[prod.index("--output-format") + 1] == "stream-json" and "--verbose" in prod
    assert "reason" not in prod[prod.index("--json-schema") + 1]
    reason = diag.build_command("p", model="sonnet", schema_kind="reason")
    assert "reason" in reason[reason.index("--json-schema") + 1]
    # the isolation set is the production one
    for flag in ("--safe-mode", "--strict-mcp-config", "--no-session-persistence"):
        assert flag in prod
